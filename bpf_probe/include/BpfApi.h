/* Copyright (c) 2020 VMWare, Inc. All rights reserved. */
/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

#pragma once

#include "bcc_sensor.h"

#include <functional>
#include <cb-memory>

namespace ebpf {
    class BPF;
}


namespace cb_endpoint {
namespace bpf_probe {
    class IBpfApi
    {
    public:
        using UPtr = std::unique_ptr<IBpfApi>;
        using EventCallbackFn = std::function<void(struct data *data)>;

        enum class ProbeType
        {
            Entry,
            Return,
            LookupEntry,
            LookupReturn,
            Tracepoint
        };

        virtual ~IBpfApi() = default;

        virtual bool Init(const std::string & bpf_program) = 0;

        virtual void Reset() = 0;

        virtual bool AttachProbe(
            const char * name,
            const char * callback,
            ProbeType     type) = 0;

        virtual bool RegisterEventCallback(EventCallbackFn callback) = 0;

        virtual int PollEvents(int timeout_ms = -1) = 0;

        const std::string &GetErrorMessage() const
        {
            return m_ErrorMessage;
        }

    protected:
        std::string                 m_ErrorMessage;
        EventCallbackFn             m_eventCallbackFn;
    };

    class BpfApi
        : public IBpfApi
    {
    public:
        BpfApi();
        virtual ~BpfApi();

        bool Init(const std::string & bpf_program) override;
        void Reset() override;

        bool AttachProbe(
            const char * name,
            const char * callback,
            ProbeType     type) override;

        bool RegisterEventCallback(EventCallbackFn callback) override;

        int PollEvents(int timeout_ms = -1) override;

        const std::string &GetErrorMessage() const
        {
            return m_ErrorMessage;
        }

    private:

        void LookupSyscallName(const char * name, std::string & syscall_name);

        // Returns True when kptr_restrict value was obtained
        bool GetKptrRestrict(long &kptr_restrict_value);

        void SetKptrRestrict(long value);

        void LowerKptrRestrict();

        void RaiseKptrRestrict();

        void CleanBuildDir();

        static void on_perf_submit(void *cb_cookie, void *data, int data_size);

        std::unique_ptr<ebpf::BPF>  m_BPF;
        const std::string           m_kptr_restrict_path;
        bool                        m_bracket_kptr_restrict;
        bool                        m_first_syscall_lookup;
        long                        m_kptr_restrict_orig;
    };
}
}
