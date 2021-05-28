// Copyright (c) 2020 VMWare, Inc. All rights reserved.

#pragma once

#include <functional>
#include <cb-memory>

namespace ebpf {
    class BPF;
}


namespace cb_endpoint {
namespace cb_ebpf {
    class BpfApi
    {
    public:
        using EventCallbackFn = std::function<void(void *data, int data_size)>;
        enum class ProbeType
        {
            Entry,
            Return,
            LookupEntry,
            LookupReturn
        };
        BpfApi();
        ~BpfApi();

        static const std::string BPF_PROGRAM;

        void CleanBuildDir();

        bool Init(const std::string & bpf_program);

        void Reset();

        bool AttachProbe(const char * name,
                         const char * callback,
                         ProbeType     type);

        bool RegisterEventCallback(EventCallbackFn callback);

        int PollEvents(int timeout_ms = -1);

        const std::string &GetErrorMessage() const
        {
            return m_ErrorMessage;
        }

        void LookupSyscallName(const char * name, std::string & syscall_name);

    private:
        // Returns True when kptr_restrict value was obtained
        bool GetKptrRestrict(long &kptr_restrict_value);

        void SetKptrRestrict(long value);

        void LowerKptrRestrict();

        void RaiseKptrRestrict();

        void EmitMessage(void *data, int data_size);
        static void on_perf_submit(void *cb_cookie, void *data, int data_size);

        std::unique_ptr<ebpf::BPF>  m_BPF;
        std::string                 m_ErrorMessage;
        const std::string           m_kptr_restrict_path;
        bool                        m_bracket_kptr_restrict;
        bool                        m_first_syscall_lookup;
        long                        m_kptr_restrict_orig;
        EventCallbackFn             m_eventCallbackFn;
    };
}
}
