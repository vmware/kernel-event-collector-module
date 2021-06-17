// Copyright (c) 2020 VMWare, Inc. All rights reserved.
// SPDX-License-Identifier: GPL-2.0

#include "BpfApi.h"

#include <BPF.h>
#include <climits>
#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

using namespace cb_endpoint::cb_ebpf;

BpfApi::BpfApi()
    : m_BPF(nullptr)
    , m_kptr_restrict_path("/proc/sys/kernel/kptr_restrict")
    , m_bracket_kptr_restrict(false)
    , m_first_syscall_lookup(true)
    , m_kptr_restrict_orig(0)
{
}

BpfApi::~BpfApi()
{
}

void BpfApi::CleanBuildDir()
{
    // delete the contents of the directory /var/tmp/bcc
    // resolves DSEN-13711

    system("rm -rf /var/tmp/bcc");
}

bool BpfApi::Init(const std::string & bpf_program)
{
    m_BPF = std::make_unique<ebpf::BPF>();
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

    return result.ok();
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


// When we need to lower kptr_restrict we only have to do it once.
// Alternatively we could manually guess what the name of the syscall prefix
// without changing kptr_restrict but would need  more work to do cleanly.
void BpfApi::LookupSyscallName(const char * name, std::string & syscall_name)
{
    if (!name)
    {
        return;
    }

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

bool BpfApi::RegisterEventCallback(EventCallbackFn callback)
{
    if (!m_BPF)
    {
        return false;
    }

    m_eventCallbackFn = std::move(callback);

    // Trying 1024 pages so we don't drop so many events, no dropped
    // even callback for now.
    auto result = m_BPF->open_perf_buffer(
            "events", on_perf_submit, nullptr, static_cast<void*>(this), 1024);

    if (!result.ok())
    {
        m_ErrorMessage = result.msg();
    }

    return result.ok();
}

int BpfApi::PollEvents(int timeout_ms)
{
    if (!m_BPF)
    {
        return -1;
    }

    return m_BPF->poll_perf_buffer("events", timeout_ms);
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

    auto fileHandle = open(m_kptr_restrict_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC);
    if (fileHandle <= 0)
    {
        return;
    }

    write(fileHandle, buffer, size);
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

void BpfApi::on_perf_submit(void *cb_cookie, void *data, int data_size)
{
    auto bpfApi = static_cast<BpfApi*>(cb_cookie);
    if (bpfApi)
    {
        bpfApi->m_eventCallbackFn(static_cast<data_t *>(data));
    }
}
