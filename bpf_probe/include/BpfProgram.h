/* Copyright 2021 VMware Inc.  All rights reserved. */
/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

#pragma once

#include "BpfApi.h"

#define BPF_REQUIRED false
#define BPF_OPTIONAL true

namespace cb_endpoint {
namespace bpf_probe {
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
            IBpfApi          &bpf_api);
    };

}}
