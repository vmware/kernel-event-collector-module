// Copyright (c) 2020 VMWare, Inc. All rights reserved.

#pragma once

#include "bpf-core/BpfApi.h"

#include "mock/CbUtil.h"
#include "CppUTest/TestHarness.h"
#include "CppUTestExt/MockSupport.h"

namespace ebpf {
    class BPF {};
}

namespace cb_endpoint {
namespace cb_ebpf {
namespace tdd_mock {

    class BpfApi_Mock
    {
    public:
        #define BPF_API_SCOPE "BpfApi"

        static void setup_Init(bool result)
        {
            ::mock(BPF_API_SCOPE)
                    .expectOneCall("Init")
                    .andReturnValue((bool) result);
        }

        static void setup_Reset()
        {
            ::mock(BPF_API_SCOPE)
                    .expectOneCall("Reset");
        }

        static void setup_AttachProbe(const char *name,
                                      const char *callback,
                                      BpfApi::ProbeType type,
                                      bool result)
        {
            ::mock(BPF_API_SCOPE)
                    .expectOneCall("AttachProbe")
                    .andReturnValue(result);
        }

        static void setup_RegisterEventCallback(BpfApi::EventCallbackFn callback, bool result)
        {
            ::mock(BPF_API_SCOPE)
                    .expectOneCall("RegisterEventCallback")
                    .andReturnValue(result);
        }

        static void setup_PollEvents(int timeout_ms, int result)
        {
            ::mock(BPF_API_SCOPE)
                    .expectOneCall("PollEvents")
                    .andReturnValue(result);
        }
    };
}
}
}


