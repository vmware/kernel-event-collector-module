/* Copyright 2021 VMware Inc.  All rights reserved. */
/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

#pragma once

#include "BpfApi.h"

#define BPF_REQUIRED false
#define BPF_OPTIONAL true

#define BPF_ENTRY_HOOK(NAME, CALLBACK)                          {(NAME), (CALLBACK), nullptr, cb_endpoint::bpf_probe::BpfApi::ProbeType::Entry,        BPF_REQUIRED}
#define BPF_RETURN_HOOK(NAME, CALLBACK)                         {(NAME), (CALLBACK), nullptr, cb_endpoint::bpf_probe::BpfApi::ProbeType::Return,       BPF_REQUIRED}
#define BPF_LOOKUP_ENTRY_HOOK(NAME, CALLBACK)                   {(NAME), (CALLBACK), nullptr, cb_endpoint::bpf_probe::BpfApi::ProbeType::LookupEntry,  BPF_REQUIRED}
#define BPF_LOOKUP_RETURN_HOOK(NAME, CALLBACK)                  {(NAME), (CALLBACK), nullptr, cb_endpoint::bpf_probe::BpfApi::ProbeType::LookupReturn, BPF_REQUIRED}
#define BPF_OPTIONAL_ENTRY_HOOK(NAME, CALLBACK)                 {(NAME), (CALLBACK), nullptr, cb_endpoint::bpf_probe::BpfApi::ProbeType::Entry,        BPF_OPTIONAL}
#define BPF_OPTIONAL_RETURN_HOOK(NAME, CALLBACK)                {(NAME), (CALLBACK), nullptr, cb_endpoint::bpf_probe::BpfApi::ProbeType::Return,       BPF_OPTIONAL}
#define BPF_ALTERNATE_ENTRY_HOOK(NAME, ALT, CALLBACK)           {(NAME), (CALLBACK), (ALT),   cb_endpoint::bpf_probe::BpfApi::ProbeType::Entry,        BPF_REQUIRED}
#define BPF_ALTERNATE_RETURN_HOOK(NAME, ALT, CALLBACK)          {(NAME), (CALLBACK), (ALT),   cb_endpoint::bpf_probe::BpfApi::ProbeType::Return,       BPF_REQUIRED}
#define BPF_TRACEPOINT(NAME, CALLBACK)                          {(NAME), (CALLBACK), nullptr, cb_endpoint::bpf_probe::BpfApi::ProbeType::Tracepoint,   BPF_REQUIRED}
#define BPF_OPTIONAL_TRACEPOINT(NAME, CALLBACK)                 {(NAME), (CALLBACK), nullptr, cb_endpoint::bpf_probe::BpfApi::ProbeType::Tracepoint,   BPF_OPTIONAL}
#define BPF_LOOKUP_ALTERNATE_RETURN_HOOK(NAME, ALT, CALLBACK)   {(NAME), (CALLBACK), (ALT),   cb_endpoint::bpf_probe::BpfApi::ProbeType::LookupReturn, BPF_REQUIRED}

namespace cb_endpoint {
namespace bpf_probe {
    class BpfProgram
    {
    public:
        // TODO: Unionize this for BCC and Libbpf probe types
        // to allow more special probes to be hooked in the future.
        struct ProbePoint
        {
            char const * name;
            char const * callback;
            char const * alternate;
            BpfApi::ProbeType type;
            bool optional;
        };

        static const std::string DEFAULT_PROGRAM;
        static const ProbePoint DEFAULT_HOOK_LIST[];
        static const ProbePoint EL9Aarch64_EXEC_RESLT_LIST[];
        static const ProbePoint PREFERRED_EXEC_RESULT_LIST[];

        static const struct libbpf_kprobe     DEFAULT_KPROBE_LIST[];
        static const struct libbpf_tracepoint DEFAULT_TP_LIST[];
        static const struct libbpf_tracepoint DEFAULT_EXEC_RESULT_LIST[];
        static const struct libbpf_kprobe     EL9_WORKAROUND;

        static bool InstallHookList(
            IBpfApi          &bpf_api,
            const ProbePoint *hook_list);

        static bool InstallHooks(
            IBpfApi          &bpf_api,
            const ProbePoint *hook_list);

        static bool InstallLibbpfHooks(IBpfApi &bpf_api);

    };

}}
