// Copyright 2021 VMware Inc.  All rights reserved.
// SPDX-License-Identifier: GPL-2.0

#include "BpfProgram.h"

#include <map>

using namespace cb_endpoint::bpf_probe;

bool BpfProgram::InstallHooks(
    IBpfApi          &bpf_api,
    const ProbePoint *hook_list)
{
    std::map<std::string, bool> status_map;

    // Loop over all the probes we need to install
    for (int i = 0; hook_list[i].name != NULL; ++i)
    {
        const char *name = hook_list[i].name;

        if (hook_list[i].alternate)
        {
            bool isInsterted = false;
            try
            {
                isInsterted = status_map.at(hook_list[i].name);
            }
            catch (std::out_of_range)
            {
                //pass
            }
            // If the hook we depend on inserted correctly than skip this.
            //  Otherwise attempt to insert this hook.
            if (isInsterted)
            {
                status_map[hook_list[i].alternate] = false;
                continue;
            }
            else
            {
                name = hook_list[i].alternate;
            }
        }

        auto didAttach = bpf_api.AttachProbe(
            name,
            hook_list[i].callback,
            hook_list[i].type);

        // Record the insertion status of this probe point
        status_map[name] = didAttach;
        if (!hook_list[i].optional && !didAttach)
        {
            // This probe point is required, so fail out
            return false;
        }
    }
    
    return true;
}

const BpfProgram::ProbePoint BpfProgram::DEFAULT_HOOK_LIST[] = {

    BPF_ENTRY_HOOK ("tcp_v4_connect", "trace_connect_v4_entry"),
    BPF_RETURN_HOOK("tcp_v4_connect", "trace_connect_v4_return"),

    BPF_ENTRY_HOOK ("tcp_v6_connect", "trace_connect_v6_entry"),
    BPF_RETURN_HOOK("tcp_v6_connect", "trace_connect_v6_return"),

    BPF_RETURN_HOOK("inet_csk_accept", "trace_accept_return"),

    BPF_ENTRY_HOOK ("tcp_sendmsg", "trace_tcp_sendmsg"),

    BPF_ENTRY_HOOK ("udp_recvmsg", "trace_udp_recvmsg"),
    BPF_RETURN_HOOK("udp_recvmsg", "trace_udp_recvmsg_return"),

    BPF_ENTRY_HOOK ("udpv6_recvmsg", "trace_udp_recvmsg"),
    BPF_RETURN_HOOK("udpv6_recvmsg", "trace_udp_recvmsg_return"),

    BPF_ENTRY_HOOK ("udp_sendmsg", "trace_udp_sendmsg"),
    BPF_RETURN_HOOK("udp_sendmsg", "trace_udp_sendmsg_return"),

    BPF_ENTRY_HOOK ("udpv6_sendmsg", "trace_udp_sendmsg"),
    BPF_RETURN_HOOK("udpv6_sendmsg", "trace_udp_sendmsg_return"),

    BPF_ENTRY_HOOK("security_inode_rename", "on_security_inode_rename"),
    BPF_ENTRY_HOOK("security_inode_unlink", "on_security_inode_unlink"),

    // File Event Hooks
    BPF_OPTIONAL_ENTRY_HOOK("__vfs_write",                    "trace_write_entry"),
    BPF_ALTERNATE_ENTRY_HOOK("__vfs_write", "vfs_write",      "trace_write_entry"),
    BPF_ALTERNATE_ENTRY_HOOK("__vfs_write", "__kernel_write", "trace_write_entry"),
    BPF_ENTRY_HOOK("security_mmap_file", "on_security_mmap_file"),
    BPF_ENTRY_HOOK("security_file_open", "on_security_file_open"),
    BPF_ENTRY_HOOK("security_file_free", "on_security_file_free"),

    // Process Event Hooks
    BPF_ENTRY_HOOK("wake_up_new_task",   "on_wake_up_new_task"),

    // we have 2 exit hooks because depending on how a process
    // exits it might not call one or the other. it's also possible
    // it dosent call either. we remove duplicates in userspace
    BPF_ENTRY_HOOK("security_task_free", "on_security_task_free"),
    BPF_OPTIONAL_TRACEPOINT("sched:sched_process_exit", "on_sched_process_exit"),

    // we have one more exit hook because older kernels dont do tracepoints
    BPF_ALTERNATE_ENTRY_HOOK("sched:sched_process_exit", "profile_task_exit", "on_security_task_free"),

    // Exec Syscall Hooks
    BPF_LOOKUP_ENTRY_HOOK ("execve",   "syscall__on_sys_execve"),
    BPF_LOOKUP_RETURN_HOOK("execve",   "after_sys_execve"),
    BPF_LOOKUP_ENTRY_HOOK ("execveat", "syscall__on_sys_execveat"),
    BPF_LOOKUP_RETURN_HOOK("execveat", "after_sys_execve"),

    // Network Event Hooks (only for udp recv event)
    BPF_OPTIONAL_RETURN_HOOK("__skb_recv_udp",                         "trace_skb_recv_udp"),
    BPF_ALTERNATE_RETURN_HOOK("__skb_recv_udp", "__skb_recv_datagram", "trace_skb_recv_udp"),

    BPF_ENTRY_HOOK(nullptr,nullptr)
};