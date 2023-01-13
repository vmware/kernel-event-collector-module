// Copyright (c) 2020 VMWare, Inc. All rights reserved.
// SPDX-License-Identifier: GPL-2.0

#include "BpfApi.h"
#include "bcc_sensor.h"

#include "sensor.skel.h"

// bcc headers
#include <bcc/BPF.h>
#include <bcc/perf_reader.h>
#include <bcc/common.h>
#include <bcc/libbpf.h> // helper library, not real libbpf

// real libbpf from conan package
#include <bpf/libbpf.h>

#include <climits>
#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>
#include <chrono>
#include <exception>
#include <boost/filesystem.hpp>

#include <sys/epoll.h>
#include <sys/resource.h>   // Only for setrlimit()

using namespace cb_endpoint::bpf_probe;
using namespace std::chrono;
namespace fs = boost::filesystem; 

#define DEBUG_ORDER(BLOCK)
//#define DEBUG_ORDER(BLOCK) BLOCK while(0)

#define DEBUG_HARVEST(BLOCK)
//#define DEBUG_HARVEST(BLOCK) BLOCK while(0)

BpfApi::BpfApi()
    : m_BPF(nullptr)
    , m_try_libbpf(true)
    , m_kptr_restrict_path("/proc/sys/kernel/kptr_restrict")
    , m_bracket_kptr_restrict(false)
    , m_first_syscall_lookup(true)
    , m_kptr_restrict_orig(0)
    , m_event_list()
    , m_timestamp_last(0)
    , m_event_count(0)
    , m_did_leave_events(false)
    , m_has_lru_hash(false)
    , m_skel(nullptr)
    , m_epoll_fd(-1)
    , m_log_fn(nullptr)
{
    m_ProgInstanceType = BpfApi::ProgInstanceType::Uninitialized;
}

BpfApi::~BpfApi()
{
    if (m_skel)
    {
        sensor_bpf__destroy(m_skel);
        m_skel = nullptr;

        if (m_epoll_fd >= 0)
        {
            close(m_epoll_fd);
            m_epoll_fd = -1;
        }

        if (m_perf_reader.size())
        {
            for (auto perf_reader : m_perf_reader)
            {
                perf_reader_free(perf_reader);
            }
            m_perf_reader.clear();
        }
    }

    // Ensure C global holds our reference
    if (m_log_fn)
    {
        libbpf_set_print(nullptr);
    }
}

void BpfApi::CleanBuildDir()
{
    // delete the contents of the directory /var/tmp/bcc
    // resolves DSEN-13711
    IGNORE_UNUSED_RETURN_VALUE(fs::remove_all("/var/tmp/bcc"));
}

bool BpfApi::Init_libbpf()
{
    struct rlimit rlim_new = {
        .rlim_cur   = RLIM_INFINITY,
        .rlim_max   = RLIM_INFINITY,
    };

    // TODO: Remove when using libbpf 1.0.0+ aka BCC v0.25.0+
    (void)setrlimit(RLIMIT_MEMLOCK, &rlim_new);

    m_skel = sensor_bpf__open();
    if (!m_skel)
    {
        return false;
    }

    m_ncpu = ebpf::get_online_cpus();

    // if (libbpf_probe_bpf_map_type(BPF_MAP_TYPE_RINGBUF, NULL))
    // {
        // max_entries ideally should be perf buffer's size * m_cpu
        // PAGE_SIZE may be larger on aarch64

        // unsigned int max_entries = (1024 * 4096) * m_ncpu.size();

        // bpf_map__set_max_entries(m_skel->maps.dummy_events, max_entries);
        // bpf_map__set_type(m_skel->maps.dummy_events, BPF_MAP_TYPE_RINGBUF);
        // bpf_map__set_key_size(m_skel->maps.dummy_events, 0);
        // bpf_map__set_value_size(m_skel->maps.dummy_events, 0);
        // m_skel->rodata->USE_RINGBUF = 1;
    // }

    if (sensor_bpf__load(m_skel))
    {
        Reset();

        return false;
    }

    // TODO: Log if using ringbuf or perf buffer here

    m_ProgInstanceType = BpfApi::ProgInstanceType::LibbpfAutoAttached;

    return true;
}

bool BpfApi::Init_bcc(const std::string & bpf_program)
{
    m_BPF = std::unique_ptr<ebpf::BPF>(new ebpf::BPF());
    if (!m_BPF)
    {
        return false;
    }

    bool kptr_result = GetKptrRestrict(m_kptr_restrict_orig);
    if (kptr_result && m_kptr_restrict_orig >= 2)
    {
        m_bracket_kptr_restrict = true;
    }

    CleanBuildDir();

    auto result = m_BPF->init(bpf_program, {}, {});
    if (!result.ok())
    {
        m_ErrorMessage = result.msg();
    }

    if (result.ok())
    {
        m_ProgInstanceType = BpfApi::ProgInstanceType::Bcc;

        // A compile time BPF program will create map "has_lru".
        // Should throw invalid_argument if not found or wrong map type.
        try
        {
            m_BPF->get_array_table<uint32_t>("has_lru");

            m_has_lru_hash = true;
        }
        catch (std::invalid_argument &ia)
        {
            m_has_lru_hash = false;
        }
    }

    return result.ok();
}

bool BpfApi::Init(const std::string & bpf_program, bool try_bcc_first)
{
    bool result = false;
    // For now libbpf support must have BTF.
    if (m_try_libbpf)
    {
        int fd = open("/sys/kernel/btf/vmlinux", O_RDONLY);

        if (fd < 0)
        {
            m_try_libbpf = false;
        }
        else
        {
            m_try_libbpf = true;
            close(fd);
        }
    }

    if (try_bcc_first)
    {
        result = Init_bcc(bpf_program);
    }

    if (!result && m_try_libbpf)
    {
        result = Init_libbpf();

        //
        // Explicitly tell this instance to never re-retry libbpf
        //
        m_try_libbpf = result;
    }

    if (!result && !try_bcc_first)
    {
        result = Init_bcc(bpf_program);
    }

    return result;
}

void BpfApi::Reset()
{
    m_ProgInstanceType = BpfApi::ProgInstanceType::Uninitialized;

    if (m_skel)
    {
        sensor_bpf__destroy(m_skel);
        m_skel = nullptr;

        if (m_epoll_fd >= 0)
        {
            close(m_epoll_fd);
            m_epoll_fd = -1;
        }

        if (m_perf_reader.size())
        {
            for (auto perf_reader : m_perf_reader)
            {
                perf_reader_free(perf_reader);
            }
            m_perf_reader.clear();
        }
    }

    // Calling ebpf::BPF::detach_all multiple times on the same object results in double free and segfault.
    // ebpf::BPF::~BPF calls detach_all so the best thing is to delete the object.
    if (m_BPF)
    {
        m_BPF.reset();
    }
}

// Used for telling us how we mapped keys and value pairs
// for hashtables used like caches.
bool BpfApi::IsLRUCapable() const
{
    if (!m_BPF)
    {
        return false;
    }

    return m_has_lru_hash;
}

// When we need to lower kptr_restrict we only have to do it once.
// Alternatively we could manually guess what the name of the syscall prefix
// without changing kptr_restrict but would need  more work to do cleanly.
//
// BPF::get_syscall_fnname() doesn't have the code for handling ARM symbols,
// due to which it's not returning the correct kernel function for the
// syscall for ARM architecture. So, handling the same for ARM here.
void BpfApi::LookupSyscallName(const char * name, std::string & syscall_name)
{
    if (m_ProgInstanceType == BpfApi::ProgInstanceType::LibbpfAutoAttached)
    {
        return;
    }

    if (!name)
    {
        return;
    }

#if defined(__aarch64__)
    syscall_name = std::string("__arm64_sys_") + name;
#else
    if (m_BPF)
    {
        if (m_first_syscall_lookup)
        {
            LowerKptrRestrict();
        }
        syscall_name = m_BPF->get_syscall_fnname(name);
        if (m_first_syscall_lookup)
        {
            RaiseKptrRestrict();
            m_first_syscall_lookup = false;
        }
    }
    else
    {
        syscall_name = std::string(name);
    }
#endif
}

bool BpfApi::AttachProbe(const char * name,
                         const char * callback,
                         ProbeType    type)
{
    // Just return true even though if we don't care
    if (m_ProgInstanceType == BpfApi::ProgInstanceType::LibbpfAutoAttached)
    {
        return true;
    }

    if (!m_BPF)
    {
        return false;
    }

    std::string           alternate;
    bpf_probe_attach_type attach_type;
    switch (type)
    {
    case ProbeType::LookupEntry:
        LookupSyscallName(name, alternate);
        name = alternate.c_str();
        // https://gcc.gnu.org/onlinedocs/gcc/Warning-Options.html#index-Wimplicit-fallthrough
        [[fallthrough]];
    case ProbeType::Entry:
        attach_type = BPF_PROBE_ENTRY;
        break;
    case ProbeType::LookupReturn:
        LookupSyscallName(name, alternate);
        name = alternate.c_str();
        // https://gcc.gnu.org/onlinedocs/gcc/Warning-Options.html#index-Wimplicit-fallthrough
        [[fallthrough]];
    case ProbeType::Return:
        attach_type = BPF_PROBE_RETURN;
        break;
    case ProbeType::Tracepoint:
    {
        auto result = m_BPF->attach_tracepoint(name, callback);
        if (!result.ok())
        {
            m_ErrorMessage = result.msg();
        }

        return result.ok();
    }
    default:
        return false;
    }

    auto result = m_BPF->attach_kprobe(
            name,
            callback,
            0,
            attach_type);

    if (!result.ok())
    {
        m_ErrorMessage = result.msg();
    }

    return result.ok();
}

bool BpfApi::AutoAttach()
{
    if (m_ProgInstanceType == BpfApi::ProgInstanceType::LibbpfAutoAttached)
    {
        if (!m_skel)
        {
            m_ErrorMessage = std::string("Cannot Auto Attach null bpf skeleton");
            return false;
        }

        if (sensor_bpf__attach(m_skel))
        {
            m_ErrorMessage = std::string("sensor_bpf__attach failed");
            return false;
        }
        return true;
    }

    m_ErrorMessage = std::string("Cannot Auto Attach With InstanceType");
    return false;
}

bool BpfApi::RegisterEventCallback(EventCallbackFn callback)
{
    // Convert per CPU buffer bytes to approprite number of pages.
    // This is to correctly handle aarch64. https://docs.kernel.org/arm64/memory.html
    int perCPUPageCount = MAX_PERCPU_BUFFER_SIZE / getpagesize();

    if (m_skel)
    {
        // Get events map
        int map_fd = bpf_map__fd(m_skel->maps.events);
        if (map_fd < 0)
        {
            m_ErrorMessage = std::string("bpf perf map 'events' fd not initialized");
            return false;
        }

        // Create epollfd instance as well!!!
        m_epoll_fd = epoll_create1(EPOLL_CLOEXEC);
        if (m_epoll_fd < 0)
        {
            m_ErrorMessage = std::string("create epoll fd failed");
            return false;
        }

        for (auto cpu : m_ncpu)
        {
            // perf_reader is opaque
            struct perf_reader *perf_reader = static_cast<struct perf_reader *>(bpf_open_perf_buffer(
                on_perf_submit,
                on_perf_peek,
                nullptr,
                static_cast<void*>(this),
                -1,
                cpu,
                perCPUPageCount
            ));

            if (perf_reader)
            {
                m_perf_reader.push_back(perf_reader);

                int key = cpu;
                int perf_buf_fd = perf_reader_fd(perf_reader);

                struct epoll_event event = {};
                
                event.events = EPOLLIN;
                event.data.ptr = static_cast<void *>(perf_reader);
                if (epoll_ctl(m_epoll_fd, EPOLL_CTL_ADD, perf_buf_fd, &event) != 0)
                {
                    perf_reader_free(perf_reader);
                    
                    m_ErrorMessage = std::string("epoll_ctl failed to add perf buf fd");
                    return false;
                }

                // thin wrapper to bpf_map_update_elem
                int err = bpf_update_elem(map_fd, &key, &perf_buf_fd, 0);
                if (err)
                {
                    m_ErrorMessage = std::string("bpf_map_update_elem for perf buf map");
                    return false;
                }
            }
            else
            {
                m_ErrorMessage = std::string("bpf_open_perf_buffer failed");
                return false;
            }
        }

        m_epoll_data.reset(new epoll_event[m_perf_reader.size()]);
        m_eventCallbackFn = std::move(callback);

        return true;
    }

    if (!m_BPF)
    {
        return false;
    }

    m_eventCallbackFn = std::move(callback);

    auto result = m_BPF->open_perf_buffer("events",
                                          on_perf_submit,
                                          on_perf_peek,
                                          nullptr,
                                          static_cast<void*>(this),
                                          perCPUPageCount);

    if (!result.ok())
    {
        m_ErrorMessage = result.msg();
    }

    return result.ok();
}

int BpfApi::PollEvents()
{
    // This poll cycle will read events from all CPU perf buffers and call the event callback for each event in the buffer.
    //  Each buffer is read until empty OR until the target timestamp is reached.  The probe will continue adding events to
    //  the queues during this process.  Since new events could be added to CPU queues that have already been read, and
    //  to queues yet to be read.  We could collect events in this pass that are "newer" than events in the CPU queue.
    //
    // To account for this we collect the events in a local list, sort them, check to queues again for any missed events
    //  which are older than the last one we have, sort them again, and finally send them to the client.
    //
    // We use the peek callback to stop adding events to the local list if we reach the target timestamp.  Otherwise on a
    //  really busy system we could collect so many events from one CPU that we have dificulty knowing exactly where to
    //  stop sending events.
    //
    // Note: This logic requires patches to BCC to provide the peek callback and a force perfbuffer read.
    //
    // This article has a good writeup of the problems.
    //   https://kinvolk.io/blog/2018/02/timing-issues-when-using-bpf-with-virtual-cpus/
    // Here is a reference implementation of the fix.  (I used this as a reference, but developed my own solution.)
    //  https://github.com/iovisor/gobpf/blob/65e4048660d6c4339ebae113ac55b1af6f01305d/elf/perf.go#L147
    if (!m_BPF && (!m_skel || m_perf_reader.size() == 0))
    {
        return -1;
    }

    // Do we have events waiting to be sent from a previous read cycle
    auto events_waiting = !m_event_list.empty();

    if (m_did_leave_events)
    {
        // We left events on a CPU queue so we need to bypass the poll
        m_did_leave_events = false;

        if (m_perf_reader.size() > 0)
        {
            // For each CPU online read
            for (auto perf_reader : m_perf_reader)
            {
                perf_reader_event_read(perf_reader);
            }
        }
        else if (m_BPF)
        {
            m_BPF->read_perf_buffer("events");
        }
    }
    else
    {
        auto timeout_ms = POLL_TIMEOUT_MS;
        if (events_waiting)
        {
            // We had events waiting, so force a very short sleep to give the probe the probe a chance to finish submitting
            //  events.  Also provide a very short timeout to the poll so that we don't hold onto events for very long.
            usleep(500);
            timeout_ms = 1;
        }
        m_did_leave_events = false;


        int result = -1;

        // epoll all perf buffers and then consume
        if (m_BPF)
        {
            result = m_BPF->poll_perf_buffer("events", timeout_ms);
        }
        else
        {
            result = epoll_wait(m_epoll_fd, m_epoll_data.get(),
                                     m_perf_reader.size(), timeout_ms);
            for (int i = 0; i < result; i++)
            {
                perf_reader_event_read(static_cast<perf_reader *>(m_epoll_data[i].data.ptr));
            }
        }

        if (result < 0)
        {
            return result;
        }
    }

    // Were events collected during this pass?
    //  This can be false even if events are available in the queuue since the peek function will cause us to stop reading
    //  events once we reach the target delta.
    auto collected_events = (m_event_count > 0);

    if (!m_event_list.empty())
    {
        if (collected_events)
        {
            // If we collected events during this cycle, than sort the list
            m_event_list.sort();
            m_timestamp_last  = m_event_list.back().GetEventTime();

            DEBUG_HARVEST({
                fprintf(stderr, "sorted ");
            });
        }

        DEBUG_HARVEST({
            #define TF(A) ((A) ? "true" : "false")
            fprintf(stderr, "%ld w:%s c:%s l:%s\n",
                m_event_list.size(),
                TF(events_waiting),
                TF(collected_events),
                TF(m_did_leave_events));
        });

        if (!collected_events)
        {
            // We have decided to harvest events.  We need to loop over all events in the list and send them to the target
            for (auto & data: m_event_list)
            {
                // Leave this here for future debugging
                DEBUG_ORDER({
                     uint64_t event_time = data.GetEventTime();
                     static uint64_t m_last_event_time = 0;
                     if (event_time < m_last_event_time)
                     {
                         auto ns = nanoseconds(m_last_event_time - event_time);
                         auto ms = duration_cast<milliseconds>(ns);
                         ns = ns - duration_cast<nanoseconds>(ms);
                         fprintf(stderr, "Event out of order (%ldms %ldns)\n",
                                     ms.count(), ns.count());
                     }
                     m_last_event_time = event_time;
                });

                m_eventCallbackFn(std::move(data));

            }

            // Erase the events that we sent
            m_event_list.clear();
            m_timestamp_last  = 0;
        }
    }
    m_event_count = 0;

    return 0;
}

bool BpfApi::GetKptrRestrict(long &kptr_restrict_value)
{
    auto fileHandle = open(m_kptr_restrict_path.c_str(), O_RDONLY);
    if (fileHandle < 0)
    {
        return false;
    }

    size_t size = 32;
    unsigned char buffer[size] = {};
    auto bytesRead = read(fileHandle, buffer, size);
    close(fileHandle);

    if (!bytesRead || !buffer[0])
    {
        return false;
    }

    long value = strtol(reinterpret_cast<const char *>(buffer), nullptr, 10);
    if ((value == LONG_MIN || value == LONG_MAX) && errno == ERANGE)
    {
        return false;
    }

    kptr_restrict_value = value;

    return true;
}

void BpfApi::SetKptrRestrict(long value)
{
    size_t size = 32;
    char buffer[size] = {};
    int ret = snprintf(buffer, sizeof(buffer) -1, "%ld\n", value);
    if (ret <= 0 || !buffer[0])
    {
        return;
    }
    size = strlen(buffer);

    auto fileHandle = open(m_kptr_restrict_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC,
                           S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (fileHandle < 0)
    {
        return;
    }

    IGNORE_UNUSED_RETURN_VALUE(write(fileHandle, buffer, size));
    close(fileHandle);
}

void BpfApi::LowerKptrRestrict()
{
    if (m_bracket_kptr_restrict)
    {
        SetKptrRestrict(1);
    }
}

void BpfApi::RaiseKptrRestrict()
{
    if (m_bracket_kptr_restrict)
    {
        SetKptrRestrict(m_kptr_restrict_orig);
    }
}

bool BpfApi::OnPeek(const bpf_probe::Data data)
{
    // This callback allows us to inspect the next event and signal BPF to stop reading from the current CPU queue
    //  * Always continue reading if this is the first cycle after we have cleared the list because m_timestamp_last is
    //    not valid.
    //  * Otherwise stop reading from this CPU if the event time is greater than the last timestamp.
    auto keep_collecting =  (!m_timestamp_last || (data.GetEventTime() <= m_timestamp_last));

    m_did_leave_events |= !keep_collecting;

    return keep_collecting;
}

void BpfApi::OnEvent(bpf_probe::Data data)
{
    // Keep a count of the events we capture during this poll cycle
    ++m_event_count;

    // Add the event to our internal event list
    m_event_list.emplace_back(std::move(data));
}

bool BpfApi::on_perf_peek(int cpu, void *cb_cookie, void *data, int data_size)
{
    auto bpfApi = static_cast<BpfApi*>(cb_cookie);
    if (bpfApi)
    {
        return bpfApi->OnPeek(static_cast<bpf_probe::data *>(data));
    }
    return false;
}

void BpfApi::on_perf_submit(void *cb_cookie, void *orig_data, int data_size)
{
    auto bpfApi = static_cast<BpfApi*>(cb_cookie);
    if (bpfApi)
    {
        bpf_probe::data *data = reinterpret_cast<bpf_probe::data *>(new (std::nothrow) char[data_size]);
        if (!data) {
            return;
        } 
        memcpy(data, orig_data, data_size);
        bpfApi->OnEvent(static_cast<bpf_probe::data *>(data));
    }
}

// "Global" default callback libbpf log function
int BpfApi::default_libbpf_log(enum libbpf_print_level level,
                               const char *format,
                               va_list args)
{
    if (level == LIBBPF_DEBUG)
    {
        return 0;
    }

    return vfprintf(stderr, format, args);
}

// Allow instance to provide their own custom logger.
// BCC specific message should have their own callback fn.
libbpf_print_fn_t BpfApi::SetLibBpfLogCallback(libbpf_print_fn_t log_fn)
{
    m_log_fn = log_fn;

    return libbpf_set_print(log_fn);
}
