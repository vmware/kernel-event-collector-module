// Copyright (c) 2020 VMWare, Inc. All rights reserved.
// SPDX-License-Identifier: GPL-2.0

#include "BpfApi.h"

#include <climits>
#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>
#include <chrono>
#include <exception>
#include <boost/filesystem.hpp>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "sensor.skel.h"

using namespace cb_endpoint::bpf_probe;
using namespace std::chrono;
namespace fs = boost::filesystem;

#define DEBUG_ORDER(BLOCK)
//#define DEBUG_ORDER(BLOCK) BLOCK while(0)

#define DEBUG_HARVEST(BLOCK)
//#define DEBUG_HARVEST(BLOCK) BLOCK while(0)

BpfApi::BpfApi()
    : m_sensor(nullptr)
    , m_events_pb(nullptr)
    , m_kptr_restrict_path("/proc/sys/kernel/kptr_restrict")
    , m_bracket_kptr_restrict(false)
    , m_first_syscall_lookup(true)
    , m_kptr_restrict_orig(0)
    , m_event_list()
    , m_timestamp_last(0)
    , m_event_count(0)
    , m_did_leave_events(false)
    , m_has_lru_hash(false)
{
}

BpfApi::~BpfApi()
{
}

// BCC specific
// void BpfApi::CleanBuildDir()
// {
//     // delete the contents of the directory /var/tmp/bcc
//     // resolves DSEN-13711
//     IGNORE_UNUSED_RETURN_VALUE(fs::remove_all("/var/tmp/bcc"));
// }

bool BpfApi::Init(const std::string & bpf_program)
{
    m_sensor = sensor_bpf__open()
    if (!m_sensor)
    {
        return false;
    }

    bool kptr_result = GetKptrRestrict(m_kptr_restrict_orig);
    if (kptr_result && m_kptr_restrict_orig >= 2)
    {
        m_bracket_kptr_restrict = true;
    }

    //CleanBuildDir();

    if (sensor_bpf__load(m_sensor)) {
    {
        m_ErrorMessage = result.msg();
        return false
    }

// TODO: Legacy kernel support
    // A compile time BPF program will create map "has_lru".
    // Should throw invalid_argument if not found or wrong map type.
//    try
//    {
//        m_BPF->get_array_table<uint32_t>("has_lru");

//        m_has_lru_hash = true;
//    }
//    catch (std::invalid_argument &ia)
//    {
//        m_has_lru_hash = false;
//    }


    return true;
}

void BpfApi::Reset()
{
    // Calling ebpf::BPF::detach_all multiple times on the same object results in double free and segfault.
    // ebpf::BPF::~BPF calls detach_all so the best thing is to delete the object.
    if (m_BPF)
    {
        m_BPF.reset();
    }
}

// TODO: Legacy kernel support
// Used for telling us how we mapped keys and value pairs
// for hashtables used like caches.
//bool BpfApi::IsLRUCapable() const
//{
//    if (!m_BPF)
//    {
//        return false;
//    }
//
//    return m_has_lru_hash;
//}

// When we need to lower kptr_restrict we only have to do it once.
// Alternatively we could manually guess what the name of the syscall prefix
// without changing kptr_restrict but would need  more work to do cleanly.
void BpfApi::LookupSyscallName(const char * name, std::string & syscall_name)
{
    if (!name)
    {
        return;
    }

    // if (m_sensor)
    // {
    //     if (m_first_syscall_lookup)
    //     {
    //         LowerKptrRestrict();
    //     }
    //     syscall_name = m_BPF->get_syscall_fnname(name);
    //     if (m_first_syscall_lookup)
    //     {
    //         RaiseKptrRestrict();
    //         m_first_syscall_lookup = false;
    //     }
    // }
    // else
    // {
    //     syscall_name = std::string(name);
    // }
}

bool BpfApi::AttachProbe(const char * name,
                         const char * callback,
                         ProbeType    type)
{
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
    // case ProbeType::Tracepoint:
    // {
    //     auto result = m_BPF->attach_tracepoint(name, callback);
    //     if (!result.ok())
    //     {
    //         m_ErrorMessage = result.msg();
    //     }

    //     return result.ok();
    // }
    default:
        return false;
    }

    auto result = bpf_program__attach_kprobe(name, attach_type == BPF_PROBE_RETURN, callback);
    if (!result.ok())
    {
        m_ErrorMessage = result.msg();
    }

    return result.ok();
}

bool BpfApi::RegisterEventCallback(EventCallbackFn callback)
{
    if (!m_sensor)
    {
        return false;
    }

    m_eventCallbackFn = std::move(callback);

    m_events_pb = perf_buffer__new(m_fd, 1024, on_perf_submit, nullptr, static_cast<void*>(this), nullptr);
    if (!m_events_pb)
    {
        m_ErrorMessage = "Failed creating events perf buffer";
    }

    return m_events_pb != nullptr;
}

int BpfApi::PollEvents()
{
    return perf_buffer__poll(m_sensor, POLL_TIMEOUT_MSc);
}

bool BpfApi::GetKptrRestrict(long &kptr_restrict_value)
{
    auto fileHandle = open(m_kptr_restrict_path.c_str(), O_RDONLY);
    if (fileHandle <= 0)
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
    if (fileHandle <= 0)
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

void BpfApi::OnEvent(bpf_probe::Data data)
{
    // Keep a count of the events we capture during this poll cycle
    ++m_event_count;

    // Add the event to our internal event list
    m_event_list.emplace_back(std::move(data));
}

void BpfApi::on_perf_submit(void *ctx, int cpu, void *data, __u32 size)
{
    auto bpfApi = static_cast<BpfApi*>(ctx);
    if (bpfApi)
    { 
        bpfApi->m_eventCallbackFn(static_cast<struct data *>(data));
    }
}

// bool BpfApi::ClearUDPCache4()
// {
//     bool okay = false;

//     if (!m_sensor)
//     {
//         return false;
//     }

//     if (IsLRUCapable())
//     {
//         try
//         {
//             auto udp_cache = m_BPF->get_hash_table<bpf_probe::ip_key,
//                                                   bpf_probe::ip_entry>("ip_cache");
//             auto result = udp_cache.clear_table_non_atomic();
//             okay = result.ok();
//         }
//         catch (std::invalid_argument &ia)
//         {
//         }
//     }
//     // TODO: Legacy kernel support
//     // else
//     // {
//     //     try
//     //     {
//     //         auto udp_cache = m_BPF->get_hash_table<uint32_t,
//     //                                                bpf_probe::ip_key>("ip_cache");
//     //         auto result = udp_cache.clear_table_non_atomic();
//     //         okay = result.ok();
//     //     }
//     //     catch (std::invalid_argument &ia)
//     //     {
//     //     }
//     // }

//     return okay;
// }


// Looks like it's unsued. 
// bool BpfApi::ClearUDPCache6()
// {
//     bool okay = false;

//     if (!m_BPF)
//     {
//         return false;
//     }

//     if (IsLRUCapable())
//     {
//         try
//         {
//             auto udp_cache = m_BPF->get_hash_table<bpf_probe::ip6_key,
//                                                    bpf_probe::ip_entry>("ip6_cache");
//             auto result = udp_cache.clear_table_non_atomic();
//             okay = result.ok();
//         }
//         catch (std::invalid_argument &ia)
//         {
//         }
//     }
//     else
//     {
//         try
//         {
//             auto udp_cache = m_BPF->get_hash_table<uint32_t,
//                                                    bpf_probe::ip6_key>("ip6_cache");
//             auto result = udp_cache.clear_table_non_atomic();
//             okay = result.ok();
//         }
//         catch (std::invalid_argument &ia)
//         {
//         }
//     }

//     return okay;
// }

// bool BpfApi::InsertUDPCache4(const bpf_probe::ip_key &key,
//                              const bpf_probe::ip_entry &value)
// {
//     bool okay = false;

//     if (IsLRUCapable())
//     {
//         try
//         {
//             auto udp_cache = m_BPF->get_hash_table<bpf_probe::ip_key,
//                                                    bpf_probe::ip_entry>("ip_cache");
//             auto result = udp_cache.update_value(key, value);
//             okay = result.ok();
//         }
//         catch (std::invalid_argument &ia)
//         {
//         }
//     }
//     else
//     {
//         try
//         {
//             auto udp_cache = m_BPF->get_hash_table<uint32_t,
//                                                    bpf_probe::ip_key>("ip_cache");
//             auto result = udp_cache.update_value(key.pid, key);
//             okay = result.ok();
//         }
//         catch (std::invalid_argument &ia)
//         {
//         }
//     }

//     return okay;
// }

// bool BpfApi::RemoveEntryUDPCache4(const bpf_probe::ip_key &key)
// {
//     bool okay = false;

//     if (IsLRUCapable())
//     {
//         try
//         {
//             auto udp_cache = m_BPF->get_hash_table<bpf_probe::ip_key,
//                                                    bpf_probe::ip_entry>("ip_cache");
//             auto result = udp_cache.remove_value(key);
//             okay = result.ok();
//         }
//         catch (std::invalid_argument &ia)
//         {
//         }
//     }
//     else
//     {
//         try
//         {
//             auto udp_cache = m_BPF->get_hash_table<uint32_t,
//                                                    bpf_probe::ip_key>("ip_cache");
//             auto result = udp_cache.remove_value(key.pid);
//             okay = result.ok();
//         }
//         catch (std::invalid_argument &ia)
//         {
//         }
//     }

//     return okay;
// }

// bool BpfApi::GetEntryUDPLRUCache4(const bpf_probe::ip_key &key,
//                                   bpf_probe::ip_entry &value)
// {
//     bool okay = false;

//     if (IsLRUCapable())
//     {
//         try
//         {
//             auto udp_cache = m_BPF->get_hash_table<bpf_probe::ip_key,
//                                                    bpf_probe::ip_entry>("ip_cache");
//             auto result = udp_cache.get_value(key, value);
//             okay = result.ok();
//         }
//         catch (std::invalid_argument &ia)
//         {
//         }
//     }

//     return okay;
// }

// bool BpfApi::GetEntryUDPCache4(const uint32_t &pid,
//                                bpf_probe::ip_key &value)
// {
//     bool okay = false;

//     if (!IsLRUCapable())
//     {
//         try
//         {
//             auto udp_cache = m_BPF->get_hash_table<uint32_t,
//                                                    bpf_probe::ip_key>("ip_cache");
//             auto result = udp_cache.get_value(pid, value);
//             okay = result.ok();
//         }
//         catch (std::invalid_argument &ia)
//         {
//         }
//     }

//     return okay;
// }
