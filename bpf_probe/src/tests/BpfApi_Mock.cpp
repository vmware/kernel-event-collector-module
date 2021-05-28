// Copyright (c) 2020 VMWare, Inc. All rights reserved.

#include "BpfApi_Mock.h"

using namespace cb_endpoint::cb_ebpf;

BpfApi::BpfApi() :
    m_BPF(nullptr)
    , m_ErrorMessage("")
    , m_kptr_restrict_path("/proc/sys/kernel/kptr_restrict")
    , m_bracket_kptr_restrict(false)
    , m_first_syscall_lookup(true)
    , m_kptr_restrict_orig(0)
{
}

BpfApi::~BpfApi()
{
}

bool BpfApi::Init(const std::string & bpf_prog)
{
    ::mock(BPF_API_SCOPE)
            .actualCall(__FUNCTION__);
    return ::mock(BPF_API_SCOPE).boolReturnValue();
}

void BpfApi::Reset()
{
}

bool BpfApi::AttachProbe(const char * name,
                         const char * callback,
                         ProbeType    type)
{
    ::mock(BPF_API_SCOPE)
            .actualCall(__FUNCTION__);
    return ::mock(BPF_API_SCOPE).boolReturnValue();
}

bool BpfApi::RegisterEventCallback(EventCallbackFn callback)
{
    ::mock(BPF_API_SCOPE)
            .actualCall(__FUNCTION__);
    return ::mock(BPF_API_SCOPE).boolReturnValue();
}

int BpfApi::PollEvents(int timeout_ms)
{
    ::mock(BPF_API_SCOPE)
            .actualCall(__FUNCTION__);
    return ::mock(BPF_API_SCOPE).intReturnValue();
}
