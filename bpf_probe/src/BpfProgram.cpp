// Copyright 2021 VMware Inc.  All rights reserved.
// SPDX-License-Identifier: GPL-2.0

#include "BpfProgram.h"

#include "sensor.skel.h"


#include <map>

using namespace cb_endpoint::bpf_probe;

// bool BpfProgram::InstallHooks(
//     IBpfApi          &bpf_api,
//     const ProbePoint *hook_list)
// {
//     std::map<std::string, bool> status_map;

//     // Loop over all the probes we need to install
//     for (int i = 0; hook_list[i].name != NULL; ++i)
//     {
//         const char *name = hook_list[i].name;

//         if (hook_list[i].alternate)
//         {
//             bool isInsterted = false;
//             try
//             {
//                 isInsterted = status_map.at(hook_list[i].name);
//             }
//             catch (std::out_of_range)
//             {
//                 //pass
//             }
//             // If the hook we depend on inserted correctly than skip this.
//             //  Otherwise attempt to insert this hook.
//             if (isInsterted)
//             {
//                 status_map[hook_list[i].alternate] = false;
//                 continue;
//             }
//             else
//             {
//                 name = hook_list[i].alternate;
//             }
//         }

//         auto didAttach = bpf_api.AttachProbe(
//             name,
//             hook_list[i].callback,
//             hook_list[i].type);

//         // Record the insertion status of this probe point
//         status_map[name] = didAttach;
//         if (!hook_list[i].optional && !didAttach)
//         {
//             // This probe point is required, so fail out
//             return false;
//         }
//     }
    
//     return true;
// }
struct kprobe {
    char *program_name;
    char *kprobe_name;
    bool is_kretprobe;
};

// TODO: add __x64_ prefix to sys_* hook names only for kernels >= 4.17
const struct kprobe kprobes[] = {
        {
                .program_name = (char *)"syscall__on_sys_execve",
                .kprobe_name = (char *)"__x64_sys_execve",
                .is_kretprobe = false
        },
        {
                .program_name = (char *)"syscall__on_sys_execveat",
                .kprobe_name = (char *)"__x64_sys_execveat",
                .is_kretprobe = false
        },
        {
                .program_name = (char *)"after_sys_execve",
                .kprobe_name = (char *)"__x64_sys_execve",
                .is_kretprobe = true
        },
        {
                .program_name = (char *)"after_sys_execve",
                .kprobe_name = (char *)"__x64_sys_execveat",
                .is_kretprobe = true
        },
        {
                .program_name = (char *)"trace_connect_v4_entry",
                .kprobe_name = (char *)"tcp_v4_connect",
                .is_kretprobe = false
        },
        {
                .program_name = (char *)"trace_connect_v6_entry",
                .kprobe_name = (char *)"tcp_v6_connect",
                .is_kretprobe = false
        },
        {
                .program_name = (char *)"trace_connect_v4_return",
                .kprobe_name = (char *)"tcp_v4_connect",
                .is_kretprobe = true
        },
        {
                .program_name = (char *)"trace_connect_v6_return",
                .kprobe_name = (char *)"tcp_v6_connect",
                .is_kretprobe = true
        },
        {
                .program_name = (char *)"on_security_file_free",
                .kprobe_name = (char *)"security_file_free",
                .is_kretprobe = false
        },
        {
                .program_name = (char *)"on_security_mmap_file",
                .kprobe_name = (char *)"security_mmap_file",
                .is_kretprobe = false
        },
        {
                .program_name = (char *)"on_security_file_open",
                .kprobe_name = (char *)"security_file_open",
                .is_kretprobe = false
        },
        {
                .program_name = (char *)"on_security_inode_unlink",
                .kprobe_name = (char *)"security_inode_unlink",
                .is_kretprobe = false
        },
        {
                .program_name = (char *)"on_security_inode_rename",
                .kprobe_name = (char *)"security_inode_rename",
                .is_kretprobe = false
        },
        {
                .program_name = (char *)"on_wake_up_new_task",
                .kprobe_name = (char *)"wake_up_new_task",
                .is_kretprobe = false
        },
        {
                .program_name = (char *)"on_do_exit",
                .kprobe_name = (char *)"do_exit",
                .is_kretprobe = false
        },
        {
                .program_name = (char *)"trace_skb_recv_udp",
                .kprobe_name = (char *)"__skb_recv_udp",
                .is_kretprobe = true
        },
        {
                .program_name = (char *)"trace_accept_return",
                .kprobe_name = (char *)"inet_csk_accept",
                .is_kretprobe = true
        },
        {
                .program_name = (char *)"trace_udp_recvmsg",
                .kprobe_name = (char *)"udp_recvmsg",
                .is_kretprobe = false
        },
        {
                .program_name = (char *)"trace_udp_recvmsg_return",
                .kprobe_name = (char *)"udp_recvmsg",
                .is_kretprobe = true
        },
        {
                .program_name = (char *)"trace_udp_recvmsg",
                .kprobe_name = (char *)"udpv6_recvmsg",
                .is_kretprobe = false
        },
        {
                .program_name = (char *)"trace_udp_recvmsg_return",
                .kprobe_name = (char *)"udpv6_recvmsg",
                .is_kretprobe = true
        },

        {
                .program_name = (char *)"trace_udp_sendmsg",
                .kprobe_name = (char *)"udp_sendmsg",
                .is_kretprobe = false
        },
        {
                .program_name = (char *)"trace_udp_sendmsg_return",
                .kprobe_name = (char *)"udp_sendmsg",
                .is_kretprobe = true
        },
        {
                .program_name = (char *)"trace_udp_sendmsg",
                .kprobe_name = (char *)"udpv6_sendmsg",
                .is_kretprobe = false
        },
        {
                .program_name = (char *)"trace_udp_sendmsg_return",
                .kprobe_name = (char *)"udpv6_sendmsg",
                .is_kretprobe = true
        },

};

bool BpfProgram::InstallHooks(
    IBpfApi          &bpf_api
    )
{
    int num_of_kprobes = sizeof(kprobes) / sizeof(kprobes[0]);
    for (int i = 0; i < num_of_kprobes; i++) {
        struct kprobe kprobe = kprobes[i];
        if (!bpf_api.AttachProbe(kprobe.program_name, kprobe.kprobe_name, kprobe.is_kretprobe)) {
            return false;
        }
    }

    return true;

}