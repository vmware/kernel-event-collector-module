/* Copyright 2021 VMware Inc.  All rights reserved. */

#pragma once

#include "BpfApi.h"

namespace cb_endpoint {
namespace cb_ebpf {
    #define BPF_REQUIRED false
    #define BPF_OPTIONAL true

    #define BPF_ENTRY_HOOK(NAME, CALLBACK)                    {(NAME), (CALLBACK), nullptr, BpfApi::ProbeType::Entry,        BPF_REQUIRED}
    #define BPF_RETURN_HOOK(NAME, CALLBACK)                   {(NAME), (CALLBACK), nullptr, BpfApi::ProbeType::Return,       BPF_REQUIRED}
    #define BPF_LOOKUP_ENTRY_HOOK(NAME, CALLBACK)             {(NAME), (CALLBACK), nullptr, BpfApi::ProbeType::LookupEntry,  BPF_REQUIRED}
    #define BPF_LOOKUP_RETURN_HOOK(NAME, CALLBACK)            {(NAME), (CALLBACK), nullptr, BpfApi::ProbeType::LookupReturn, BPF_REQUIRED}
    #define BPF_OPTIONAL_ENTRY_HOOK(NAME, CALLBACK)           {(NAME), (CALLBACK), nullptr, BpfApi::ProbeType::Entry,        BPF_OPTIONAL}
    #define BPF_OPTIONAL_RETURN_HOOK(NAME, CALLBACK)          {(NAME), (CALLBACK), nullptr, BpfApi::ProbeType::Return,       BPF_OPTIONAL}
    #define BPF_ALTERNATE_ENTRY_HOOK(NAME, ALT, CALLBACK)     {(NAME), (CALLBACK), (ALT),   BpfApi::ProbeType::Entry,        BPF_REQUIRED}
    #define BPF_ALTERNATE_RETURN_HOOK(NAME, ALT, CALLBACK)    {(NAME), (CALLBACK), (ALT),   BpfApi::ProbeType::Return,       BPF_REQUIRED}
    #define BPF_TRACEPOINT(NAME, CALLBACK)                    {(NAME), (CALLBACK), nullptr, BpfApi::ProbeType::Tracepoint,   BPF_REQUIRED}
    #define BPF_OPTIONAL_TRACEPOINT(NAME, CALLBACK)           {(NAME), (CALLBACK), nullptr, BpfApi::ProbeType::Tracepoint,   BPF_OPTIONAL}

    class BpfProgram
    {
    public:
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

        static bool InstallHooks(
            IBpfApi          &bpf_api,
            const ProbePoint *hook_list);
    };

}}
