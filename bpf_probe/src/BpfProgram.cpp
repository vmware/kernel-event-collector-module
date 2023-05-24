// Copyright 2021 VMware Inc.  All rights reserved.
// SPDX-License-Identifier: GPL-2.0

#include "BpfProgram.h"

#include <map>

using namespace cb_endpoint::bpf_probe;

bool BpfProgram::InstallHookList(IBpfApi &bpf_api,
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
            catch (std::out_of_range const&)
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

bool BpfProgram::InstallLibbpfHooks(IBpfApi &bpf_api)
{
    for (int i = 0; DEFAULT_KPROBE_LIST[i].bpf_prog; i++)
    {
        if (!bpf_api.AttachLibbpf(DEFAULT_KPROBE_LIST[i]))
        {
            return false;
        }
    }

    for (int i = 0; DEFAULT_TP_LIST[i].bpf_prog; i++)
    {
        if (!bpf_api.AttachLibbpf(DEFAULT_TP_LIST[i]))
        {
            return false;
        }
    }

    // IsEL9Aarch64 is true for all of aarch64 instances.
    // Handle Special Case: PSCLNX-12211
    //  Some EL9 and Ubuntu kernels of 2023 have broken tracepoints.
    if (bpf_api.IsEL9Aarch64())
    {
        const struct libbpf_tracepoint tp_sched_exec = {
            .bpf_prog = "tp__sched_process_exec",
            .tp_category = "sched",
            .tp_name = "sched_process_exec",
        };
        bool use_kretprobes = false;

        // Try the EXEC_RESULT tracepoints with bugs before trying
        // sched_process_exec tracepoint. The default EXEC_RESULT tracepoints
        // are good indicators for if we should even try sched_process_exec.
        for (int i = 0; DEFAULT_EXEC_RESULT_LIST[i].bpf_prog; i++)
        {
            if (!bpf_api.AttachLibbpf(DEFAULT_EXEC_RESULT_LIST[i]))
            {
                use_kretprobes = true;
                break;
            }
        }

        if (!use_kretprobes)
        {
            // The normal case for libbpf tracepoint enabled systems.
            // Aka most if not all BTF/libbpf systems.
            if (bpf_api.AttachLibbpf(tp_sched_exec))
            {
                return true;
            }
            else
            {
                // This should not happen if we could attach
                // syscalls/sys_exit_exec* tracepoints. Those tracepoints
                // are less likely to be attachable than sched_process_exec.
                use_kretprobes = true;

                // TODO: Create DetachLibbpf BpfApi methods.
                // Due to this case being very unlikely, it's okay to keep going.
            }
        }

        if (use_kretprobes)
        {
            const struct libbpf_kprobe kexecve = {
                .bpf_prog = "kret_syscall__execve",
                .target_func = "__arm64_sys_execve",
                .is_retprobe = true,
            };
            const struct libbpf_kprobe kexecveat = {
                .bpf_prog = "kret_syscall__execveat",
                .target_func = "__arm64_sys_execveat",
                .is_retprobe = true,
            };

            // try do_execveat_common, this might only work on special
            // EL9 kernels. Some EL9 kretprobes on exec syscalls were weird.
            if (bpf_api.AttachLibbpf(EL9_WORKAROUND))
            {
                return true;
            }
            // try 
            else if (bpf_api.AttachLibbpf(kexecve) &&
                     bpf_api.AttachLibbpf(kexecveat))
            {
                return true;
            }
            else
            {
                return false;
            }
        }
    }
    else
    {
        for (int i = 0; DEFAULT_EXEC_RESULT_LIST[i].bpf_prog; i++)
        {
            if (!bpf_api.AttachLibbpf(DEFAULT_EXEC_RESULT_LIST[i]))
            {
                return false;
            }
        }
    }

    return true;
}

bool BpfProgram::InstallHooks(IBpfApi &bpf_api,
                              const ProbePoint *hook_list)
{
    bool result = true;

    if (bpf_api.GetProgInstanceType() == BpfApi::ProgInstanceType::Libbpf)
    {
        return InstallLibbpfHooks(bpf_api);
    }

    result = InstallHookList(bpf_api, hook_list);
    if (!result)
    {
        return false;
    }

    if (bpf_api.IsEL9Aarch64())
    {
        result = InstallHookList(bpf_api, PREFERRED_EXEC_RESULT_LIST);
        if (result)
        {
            // On aarch64 we use two sources for EXEC_RESULT due to ugly
            // bugs in RedHat and Ubuntu syscall tracepoints.
            // This hook provides the successful exec result events.
            const ProbePoint tp_sched_exec[] = {
                 BPF_TRACEPOINT("sched:sched_process_exec", "on_sched_process_exec"),
                 BPF_ENTRY_HOOK(nullptr,nullptr),
            };

            result = InstallHookList(bpf_api, tp_sched_exec);
            if (result)
            {
                return true;
            }

            // TODO: Detach extra residual EXEC_RESULT tracepoints.
            // This is unlikely to happen since we try to attach the
            // least likely to attach tracepoint first.
        }
        else
        {
            result = InstallHookList(bpf_api, EL9Aarch64_EXEC_RESLT_LIST);
        }

        // When tracepoints fail on aarch64 fallback to regular syscall
        // exec kretprobes.
        if (!result)
        {
            const ProbePoint sys_exec_ret_hooks[] = {
                BPF_LOOKUP_RETURN_HOOK("execveat", "after_sys_execve"),
                BPF_LOOKUP_RETURN_HOOK("execve", "after_sys_execve"),
                BPF_ENTRY_HOOK(nullptr,nullptr),
            };

            result = InstallHookList(bpf_api, sys_exec_ret_hooks);
        }
    }
    else
    {
        result = InstallHookList(bpf_api, PREFERRED_EXEC_RESULT_LIST);
    }

    return result;
}

// Probes to explicitly only hook on RHEL9 Aarch64
const BpfProgram::ProbePoint BpfProgram::EL9Aarch64_EXEC_RESLT_LIST[] = {
    BPF_RETURN_HOOK("do_execveat_common", "after_sys_execve"),
    BPF_ENTRY_HOOK(nullptr,nullptr),
};

#if defined(__aarch64__)
// The caller for aarch64 should not fall back to kretprobes, yet.
const BpfProgram::ProbePoint BpfProgram::PREFERRED_EXEC_RESULT_LIST[] = {
    BPF_TRACEPOINT("syscalls:sys_exit_execveat", "on_sys_exit_execveat"),
    BPF_TRACEPOINT("syscalls:sys_exit_execve", "on_sys_exit_execve"),
    BPF_ENTRY_HOOK(nullptr, nullptr),
};
#else
const BpfProgram::ProbePoint BpfProgram::PREFERRED_EXEC_RESULT_LIST[] = {
    BPF_OPTIONAL_TRACEPOINT("syscalls:sys_exit_execveat", "on_sys_exit_execveat"),
    BPF_LOOKUP_ALTERNATE_RETURN_HOOK("syscalls:sys_exit_execveat", "execveat", "after_sys_execve"),
    BPF_OPTIONAL_TRACEPOINT("syscalls:sys_exit_execve", "on_sys_exit_execve"),
    BPF_LOOKUP_ALTERNATE_RETURN_HOOK("syscalls:sys_exit_execve", "execve", "after_sys_execve"),
    BPF_ENTRY_HOOK(nullptr,nullptr),
};
#endif

const BpfProgram::ProbePoint BpfProgram::DEFAULT_HOOK_LIST[] = {

    BPF_ENTRY_HOOK ("tcp_v4_connect", "trace_connect_v4_entry"),
    BPF_RETURN_HOOK("tcp_v4_connect", "trace_connect_v4_return"),

    BPF_ENTRY_HOOK ("tcp_v6_connect", "trace_connect_v6_entry"),
    BPF_RETURN_HOOK("tcp_v6_connect", "trace_connect_v6_return"),

    BPF_RETURN_HOOK("inet_csk_accept", "trace_accept_return"),

    // TODO: The collector is not currently handling the proxy event, so dont't bother collecting
    //BPF_ENTRY_HOOK ("tcp_sendmsg", "trace_tcp_sendmsg"),

    BPF_ENTRY_HOOK ("udp_recvmsg", "trace_udp_recvmsg"),
    BPF_RETURN_HOOK("udp_recvmsg", "trace_udp_recvmsg_return"),

    BPF_ENTRY_HOOK ("udpv6_recvmsg", "trace_udp_recvmsg"),
    BPF_RETURN_HOOK("udpv6_recvmsg", "trace_udp_recvmsg_return"),

    BPF_ENTRY_HOOK ("udp_sendmsg", "trace_udp_sendmsg"),
    BPF_RETURN_HOOK("udp_sendmsg", "trace_udp_sendmsg_return"),

    BPF_ENTRY_HOOK ("udpv6_sendmsg", "trace_udp_sendmsg"),
    BPF_RETURN_HOOK("udpv6_sendmsg", "trace_udp_sendmsg_return"),

    // Network Event Hooks (only for udp recv event)
    BPF_OPTIONAL_RETURN_HOOK("__skb_recv_udp",                         "trace_skb_recv_udp"),
    BPF_ALTERNATE_RETURN_HOOK("__skb_recv_udp", "__skb_recv_datagram", "trace_skb_recv_udp"),

    BPF_ENTRY_HOOK("security_inode_rename", "on_security_inode_rename"),
    BPF_ENTRY_HOOK("security_inode_unlink", "on_security_inode_unlink"),

    // File Event Hooks
    BPF_ENTRY_HOOK("security_mmap_file", "on_security_mmap_file"),
    BPF_ENTRY_HOOK("security_file_open", "on_security_file_open"),
    BPF_ENTRY_HOOK("security_file_free", "on_security_file_free"),

    // Process Event Hooks
    BPF_ENTRY_HOOK("wake_up_new_task",   "on_wake_up_new_task"),

    BPF_ENTRY_HOOK("do_exit", "on_do_exit"),

    // Exec Syscall Hooks
    BPF_LOOKUP_ENTRY_HOOK ("execve",   "syscall__on_sys_execve"),
    BPF_LOOKUP_ENTRY_HOOK ("execveat", "syscall__on_sys_execveat"),

    BPF_ENTRY_HOOK(nullptr,nullptr)
};

const struct libbpf_tracepoint BpfProgram::DEFAULT_EXEC_RESULT_LIST[] = {
    {
        .bpf_prog = "tracepoint__syscalls__sys_exit_execve",
        .tp_category = "syscalls",
        .tp_name = "sys_exit_execve",
    },
    {
        .bpf_prog = "tracepoint__syscalls__sys_exit_execveat",
        .tp_category = "syscalls",
        .tp_name = "sys_exit_execveat",
    },
    {
        .bpf_prog = nullptr,
    },
};

const struct libbpf_kprobe BpfProgram::EL9_WORKAROUND = {
    .bpf_prog = "kret_do_execveat_common",
    .target_func = "do_execveat_common",
    .is_retprobe = true,
};

// TODO: After migrating to libbpf-1.x.x, the default set of
// probe points can be set to auto-attach and the non-stable
// probe points should be set to not auto-attach.

const struct libbpf_tracepoint BpfProgram::DEFAULT_TP_LIST[] = {
    {
        .bpf_prog = "tracepoint__syscalls__sys_enter_execve",
        .tp_category = "syscalls",
        .tp_name = "sys_enter_execve",
    },
    {
        .bpf_prog = "tracepoint__syscalls__sys_enter_execveat",
        .tp_category = "syscalls",
        .tp_name = "sys_enter_execveat",
    },
    {
        .bpf_prog = nullptr,
    },
};

const struct libbpf_kprobe BpfProgram::DEFAULT_KPROBE_LIST[] = {
    {
        .bpf_prog = "on_security_file_free",
        .target_func = "security_file_free",
        .is_retprobe = false,
    },
    {
        .bpf_prog = "on_security_mmap_file",
        .target_func = "security_mmap_file",
        .is_retprobe = false,
    },
    {
        .bpf_prog = "on_security_file_open",
        .target_func = "security_file_open",
        .is_retprobe = false,
    },
    {
        .bpf_prog = "on_security_inode_unlink",
        .target_func = "security_inode_unlink",
        .is_retprobe = false,
    },
    {
        .bpf_prog = "on_security_inode_rename",
        .target_func = "security_inode_rename",
        .is_retprobe = false,
    },
    {
        .bpf_prog = "on_wake_up_new_task",
        .target_func = "wake_up_new_task",
        .is_retprobe = false,
    },
    {
        .bpf_prog = "on_do_exit",
        .target_func = "do_exit",
        .is_retprobe = false,
    },
    {
        .bpf_prog = "trace_connect_v4_entry",
        .target_func = "tcp_v4_connect",
        .is_retprobe = false,
    },
    {
        .bpf_prog = "trace_connect_v6_entry",
        .target_func = "tcp_v6_connect",
        .is_retprobe = false,
    },
    {
        .bpf_prog = "trace_connect_v4_return",
        .target_func = "tcp_v4_connect",
        .is_retprobe = true,
    },
    {
        .bpf_prog = "trace_connect_v6_return",
        .target_func = "tcp_v6_connect",
        .is_retprobe = true,
    },
    {
        .bpf_prog = "trace_skb_recv_udp",
        .target_func = "__skb_recv_udp",
        .is_retprobe = true,
    },
    {
        .bpf_prog = "trace_accept_return",
        .target_func = "inet_csk_accept",
        .is_retprobe = true,
    },
    {
        .bpf_prog = "trace_udp_recvmsg",
        .target_func = "udp_recvmsg",
        .is_retprobe = false,
    },
    {
        .bpf_prog = "trace_udp_recvmsg_return",
        .target_func = "udp_recvmsg",
        .is_retprobe = true,
    },
    {
        .bpf_prog = "kprobe_udp_sendmsg",
        .target_func = "udp_sendmsg",
        .is_retprobe = false,
    },
    {
        .bpf_prog = "kprobe_udpv6_sendmsg",
        .target_func = "udpv6_sendmsg",
        .is_retprobe = false,
    },
    {
        .bpf_prog = "kretpobe_udp_sendmsg",
        .target_func = "udp_sendmsg",
        .is_retprobe = true,
    },
    {
        .bpf_prog = "kretpobe_udpv6_sendmsg",
        .target_func = "udpv6_sendmsg",
        .is_retprobe = true,
    },
    {
        .bpf_prog = nullptr,
    },
};
