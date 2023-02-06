/* Copyright (c) 2020 VMWare, Inc. All rights reserved. */
/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

#pragma once

#include "bcc_sensor.h"

#include <functional>
#include <memory>
#include <list>
#include <vector>
#include <chrono>

#include <sys/epoll.h>

#include <bpf/libbpf.h>

// A number of calls are annotated with 'warn_unused_result' in their definition, so a
// normal (void) cast is not enough to satisfy the compiler. The added negation (!) tricks
// the compiler into properly allowing the call to be ignored.
#define IGNORE_UNUSED_RETURN_VALUE(statement) do { \
    static_cast<void>(!statement); \
} while (0)

namespace ebpf {
    class BPF;
}

struct sensor_bpf;
struct perf_reader;

namespace cb_endpoint {
namespace bpf_probe {
    class Data
    {
    public:
        // Allow implicit conversion
        Data(bpf_probe::data * _data)
            : data(_data)
        {
            if (!data)
            {
                throw std::runtime_error("Bad pointer");
            }
        }

        bpf_probe::data * data;

        friend bool operator<(Data const& left, Data const& right)
        {
            return left.data->header.event_time < right.data->header.event_time;
        }

        uint64_t GetEventTime() const
        {
            return data->header.event_time;
        }
    };
    using EventList = std::list<Data>;

    class IBpfApi
    {
    public:
        using UPtr = std::unique_ptr<IBpfApi>;
        using EventCallbackFn = std::function<void(bpf_probe::Data data)>;
        using DroppedCallbackFn = std::function<void(uint64_t drop_count)>;

        static const uint64_t POLL_TIMEOUT_MS = 300;
        static constexpr int  MAX_PERCPU_BUFFER_SIZE = (1024 * 4096);

        enum class ProbeType
        {
            Entry,
            Return,
            LookupEntry,
            LookupReturn,
            Tracepoint
        };

        enum class ProgInstanceType
        {
            Uninitialized,
            LibbpfAutoAttached,
            Bcc,
        };

        virtual ~IBpfApi() = default;

        virtual bool Init(const std::string & bpf_program,
                          bool try_bcc_first = false) = 0;

        virtual void Reset() = 0;

        virtual bool IsLRUCapable() const = 0;

        virtual bool AttachProbe(
            const char * name,
            const char * callback,
            ProbeType     type) = 0;

        virtual bool AutoAttach() = 0;

        virtual bool RegisterEventCallback(EventCallbackFn callback,
                                           DroppedCallbackFn dropCallback) = 0;

        virtual int PollEvents() = 0;

        virtual libbpf_print_fn_t SetLibBpfLogCallback(libbpf_print_fn_t log_fn) = 0;

        const std::string &GetErrorMessage() const
        {
            return m_ErrorMessage;
        }

        ProgInstanceType GetProgInstanceType() const
        {
            return m_ProgInstanceType;
        }

        static const char *InstanceTypeToString(const ProgInstanceType &progInstanceType)
        {
            const char *str = "Unknown";
            switch (progInstanceType)
            {// LCOV_EXCL_START
            case ProgInstanceType::Uninitialized: str = "Uninitialized"; break;
            case ProgInstanceType::LibbpfAutoAttached: str = "LibbpfAutoAttached"; break;
            case ProgInstanceType::Bcc: str = "Bcc"; break;
            default: break;
            }// LCOV_EXCL_END
            return str;
        }

        static const char *TypeToString(uint8_t type)
        {
            const char *str = "unknown";
            switch (type)
            {// LCOV_EXCL_START
            case EVENT_PROCESS_EXEC_ARG: str = "PROCESS_EXEC_ARG"; break;
            case EVENT_PROCESS_EXEC_PATH: str = "PROCESS_EXEC_PATH"; break;
            case EVENT_PROCESS_EXEC_RESULT: str = "PROCESS_EXEC_RESULT"; break;
            case EVENT_PROCESS_EXIT: str = "PROCESS_EXIT"; break;
            case EVENT_PROCESS_CLONE: str = "PROCESS_CLONE"; break;
            case EVENT_FILE_READ: str = "FILE_READ"; break;
            case EVENT_FILE_WRITE: str = "FILE_WRITE"; break;
            case EVENT_FILE_CREATE: str = "FILE_CREATE"; break;
            case EVENT_FILE_PATH: str = "FILE_PATH"; break;
            case EVENT_FILE_MMAP: str = "FILE_MMAP"; break;
            case EVENT_FILE_TEST: str = "FILE_TEST"; break;
            case EVENT_NET_CONNECT_PRE: str = "NET_CONNECT_PRE"; break;
            case EVENT_NET_CONNECT_ACCEPT: str = "NET_CONNECT_ACCEPT"; break;
            case EVENT_NET_CONNECT_DNS_RESPONSE: str = "NET_CONNECT_DNS_RESPONSE"; break;
            case EVENT_NET_CONNECT_WEB_PROXY: str = "NET_CONNECT_WEB_PROXY"; break;
            case EVENT_FILE_DELETE: str = "FILE_DELETE"; break;
            case EVENT_FILE_CLOSE: str = "FILE_CLOSE"; break;
            case EVENT_FILE_RENAME: str = "FILE_RENAME"; break;
            case EVENT_CONTAINER_CREATE: str = "CONTAINER_CREATE"; break;
            default: break;
            }// LCOV_EXCL_END
            return str;
        }

        static const char *StateToString(uint8_t state)
        {
            const char *str = "unknown";
            switch (state)
            {// LCOV_EXCL_START
            case PP_NO_EXTRA_DATA: str = "NO_EXTRA_DATA"; break;
            case PP_ENTRY_POINT: str = "ENTRY_POINT"; break;
            case PP_PATH_COMPONENT: str = "PATH_COMPONENT"; break;
            case PP_FINALIZED: str = "FINALIZED"; break;
            case PP_APPEND: str = "APPEND"; break;
            case PP_DEBUG: str = "DEBUG"; break;
            default: break;
            }// LCOV_EXCL_END
            return str;
        }

    protected:
        std::string                 m_ErrorMessage;
        EventCallbackFn             m_eventCallbackFn;
        DroppedCallbackFn           m_DroppedCallbackFn;
        ProgInstanceType            m_ProgInstanceType;
    };

    class BpfApi
        : public IBpfApi
    {
    public:
        using CpuList = std::vector<int>;
        using PerfReaderList = std::vector<struct perf_reader *>;
        using EpollEventData = std::unique_ptr<epoll_event[]>;

        BpfApi();
        virtual ~BpfApi();

        bool Init(const std::string & bpf_program,
                  bool try_bcc_first = false) override;
        void Reset() override;
        bool IsLRUCapable() const override;

        bool AttachProbe(
            const char * name,
            const char * callback,
            ProbeType     type) override;

        bool AutoAttach() override;

        bool RegisterEventCallback(EventCallbackFn callback,
                                   DroppedCallbackFn dropCallback) override;

        int PollEvents() override;

        const std::string &GetErrorMessage() const
        {
            return m_ErrorMessage;
        }

        ProgInstanceType GetProgInstanceType() const
        {
            return m_ProgInstanceType;
        }

        libbpf_print_fn_t SetLibBpfLogCallback(libbpf_print_fn_t log_fn) override;

        static int default_libbpf_log(enum libbpf_print_level level,
                                      const char *format,
                                      va_list args);

    private:

        bool Init_bcc(const std::string & bpf_program);
        bool Init_libbpf();

        void LookupSyscallName(const char * name, std::string & syscall_name);

        // Returns True when kptr_restrict value was obtained
        bool GetKptrRestrict(long &kptr_restrict_value);

        void SetKptrRestrict(long value);

        void LowerKptrRestrict();

        void RaiseKptrRestrict();

        void CleanBuildDir();

        bool OnPeek(const bpf_probe::Data data);
        void OnEvent(bpf_probe::Data data);
        void OnDropped(uint64_t drop_count);

        static bool on_perf_peek(int cpu, void *cb_cookie, void *data, int data_size);
        static void on_perf_submit(void *cb_cookie, void *data, int data_size);
        static void on_perf_dropped(void *cb_cookie, uint64_t drop_count);

        std::unique_ptr<ebpf::BPF>  m_BPF;
        bool                        m_try_libbpf;
        const std::string           m_kptr_restrict_path;
        bool                        m_bracket_kptr_restrict;
        bool                        m_first_syscall_lookup;
        long                        m_kptr_restrict_orig;

        EventList                   m_event_list;
        uint64_t                    m_timestamp_last;
        uint64_t                    m_event_count;
        bool                        m_did_leave_events;
        bool                        m_has_lru_hash;

        // libbpf related resources
        struct sensor_bpf *         m_skel;
        int                         m_epoll_fd;
        CpuList                     m_ncpu;
        PerfReaderList              m_perf_reader;
        EpollEventData              m_epoll_data;

        // C style function pointer.
        libbpf_print_fn_t           m_log_fn;
    };
}
}
