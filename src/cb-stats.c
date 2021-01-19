// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#include "priv.h"
#include "mem-cache.h"

typedef int     (*fp_readCallback)  (struct seq_file *m, void *v);
typedef ssize_t (*fp_writeCallback) (struct file *, const char __user *, size_t, loff_t *);

// Common
struct _ec_procs {
    const char        *name;
    fp_readCallback    r_callback;
    fp_writeCallback   w_callback;
};

static const struct _ec_procs proc_callbacks[] = {
    { "cache",                    ec_mem_cache_show,                NULL                            },
    { "events-avg",               ec_proc_show_events_avg,          NULL                            },
    { "events-detail",            ec_proc_show_events_det,          NULL                            },
    { "events-reset",             NULL,                             ec_proc_show_events_rst         },
    { "net-track-old",            ec_net_track_show_old,            NULL                            },
    { "net-track-new",            ec_net_track_show_new,            NULL                            },
    { "net-track-purge-age",      NULL,                             ec_net_track_purge_age          },
    { "net-track-purge-all",      NULL,                             ec_net_track_purge_all          },
    { "proc-track-table",         ec_proc_track_show_table,         NULL                            },
    { "proc-track-stats",         ec_proc_track_show_stats,         NULL                            },
    { "file-track-table",         ec_file_track_show_table,         NULL                            },
    { "mem",                      ec_proc_current_memory_avg,       NULL                            },
    { "mem-detail",               ec_proc_current_memory_det,       NULL                            },
    { "active-hooks",             ec_show_active_hooks,             NULL                            },

#ifdef HOOK_SELECTOR
    { "syscall-clone",            ec_syscall_clone_get,             ec_syscall_clone_set            },
    { "syscall-fork",             ec_syscall_fork_get,              ec_syscall_fork_set             },
    { "syscall-vfork",            ec_syscall_vfork_get,             ec_syscall_vfork_set            },
    { "syscall-recvfrom",         ec_syscall_recvfrom_get,          ec_syscall_recvfrom_set         },
    { "syscall-recvmsg",          ec_syscall_recvmsg_get,           ec_syscall_recvmsg_set          },
    { "syscall-recvmmsg",         ec_syscall_recvmmsg_get,          ec_syscall_recvmmsg_set         },
    { "syscall-write",            ec_syscall_write_get,             ec_syscall_write_set            },
    { "syscall-delete-module",    ec_syscall_delete_module,         ec_syscall_delete_module        },
    { "netfilter-out",            ec_netfilter_local_out_get,       ec_netfilter_local_out_set      },
    { "lsm-bprm_check_security",  ec_lsm_bprm_check_security_get,   ec_lsm_bprm_check_security_set  },
    { "lsm-bprm_committed_creds", ec_lsm_bprm_committed_creds_get,  ec_lsm_bprm_committed_creds_set },
    { "lsm-task_wait",            ec_lsm_task_wait_get,             ec_lsm_task_wait_set            },
    { "lsm-inode_create",         ec_lsm_inode_create_get,          ec_lsm_inode_create_set         },
    { "lsm-inode_rename",         ec_lsm_inode_rename_get,          ec_lsm_inode_rename_set         },
    { "lsm-inode_unlink",         ec_lsm_inode_unlink_get,          ec_lsm_inode_unlink_set         },
    { "lsm-file_permission",      ec_lsm_file_permission_get,       ec_lsm_file_permission_set      },
    { "lsm-file_free_security",   ec_lsm_file_free_security_get,    ec_lsm_file_free_security_set   },
    { "lsm-socket_connect",       ec_lsm_socket_connect_get,        ec_lsm_socket_connect_set       },
    { "lsm-inet_conn_request",    ec_lsm_inet_conn_request_get,     ec_lsm_inet_conn_request_set    },
    { "lsm-socket_sock_rcv_skb",  ec_lsm_socket_sock_rcv_skb_get,   ec_lsm_socket_sock_rcv_skb_set  },
    { "lsm-socket_post_create",   ec_lsm_socket_post_create_get,    ec_lsm_socket_post_create_set   },
    { "lsm-socket_sendmsg",       ec_lsm_socket_sendmsg_get,        ec_lsm_socket_sendmsg_set       },
    { "lsm-socket_recvmsg",       ec_lsm_socket_recvmsg_get,        ec_lsm_socket_recvmsg_set       },

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
    { "lsm-mmap_file",            ec_lsm_mmap_file_get,             ec_lsm_mmap_file_set            },
#else
    { "lsm-file_mmap",            ec_lsm_file_mmap_get,             ec_lsm_file_mmap_set            },
#endif
#endif
    { 0 }
};

int ec_dummy_show(struct seq_file *m, void *v)
{
    return 0;
}

int ec_proc_open(struct inode *inode, struct file *file)
{
    uint64_t          procId   = (uint64_t)PDE_DATA(inode);
    fp_readCallback   callback = proc_callbacks[procId].r_callback;

    if (procId >= (sizeof(proc_callbacks) / sizeof(struct _ec_procs)))
        return -EINVAL;

    return single_open(file, (callback ? callback : ec_dummy_show), PDE_DATA(inode));
}

ssize_t ec_proc_write(struct file *file, const char __user *buf, size_t size, loff_t *ppos)
{
    uint64_t procId = (uint64_t)((struct seq_file *)file->private_data)->private;
    ssize_t  len    = 0;
    char buffer[20] = { 0 };

    size = (size < 20 ? size : 19);
    if (copy_from_user(buffer, buf, size))
        size = 0;
    buffer[size] = 0;

    if (proc_callbacks[procId].w_callback)
    {
        len = proc_callbacks[procId].w_callback(file, buffer, size, ppos);
    }

    return len;
}

const struct file_operations ec_fops = {
    .owner      = THIS_MODULE,
    .open       = ec_proc_open,
    .read       = seq_read,
    .write      = ec_proc_write,
    .release    = single_release,
};

bool ec_stats_proc_initialize(ProcessContext *context)
{
    uint64_t i;

    for (i = 0; proc_callbacks[i].name != NULL; ++i)
    {
        int mode = (proc_callbacks[i].r_callback ? 0400 : 0) | (proc_callbacks[i].w_callback ? 0200 : 0);

        if (!proc_create_data(proc_callbacks[i].name, mode, g_cb_proc_dir, &ec_fops, (void *)i))
        {
            TRACE(DL_ERROR, "Failed to create proc directory entry %s", proc_callbacks[i].name);
        }
    }

    return true;
}

void ec_stats_proc_shutdown(ProcessContext *context)
{
    int i;

    for (i = 0; proc_callbacks[i].name != NULL; ++i)
    {
        remove_proc_entry(proc_callbacks[i].name, g_cb_proc_dir);
    }

}
