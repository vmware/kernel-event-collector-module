// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2022 VMware, Inc. All rights reserved.

#include <linux/module.h>
#include <linux/version.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#include "dynsec.h"
#include "stall_tbl.h"
#include "inode_cache.h"
#include "task_cache.h"

    // Globals
    const char *event_stats = CB_APP_MODULE_NAME "_stats";

    // Externs
    extern struct stall_tbl *stall_tbl;
    extern atomic_t  stall_timeout_ctr, access_denied_ctr;

// function to cleanup entries in /proc file system
void dynsec_cleanup_proc_entries(void)
{
    remove_proc_entry(event_stats, NULL);
}

// function when echo (write) gets executed on proc file
ssize_t dynsec_proc_write(struct file *file, const char *buf, size_t size, loff_t *ppos)
{
    // no effect this time
    return -EPERM;
}

// function when cat (read) gets executed on proc file
int dynsec_proc_read(struct seq_file *m, void *v)
{
    int ctr;
    seq_printf(m, "   dynsec_config: bypass:%d stall:%d",
            global_config.bypass_mode, global_config.stall_mode);
    seq_puts(m, "\n");
    seq_printf(m, " %20s %d", "stall queue size: ", stall_queue_size(stall_tbl));
    seq_puts(m, "\n");

    // write the timeout value (if non-zero) to proc file
    pr_debug("Display stalled timed out event counter\n");
    ctr = atomic_read(&stall_timeout_ctr);
    seq_printf(m, " %24s %d", "stall timeout events: ", ctr);
    seq_puts(m, "\n");
    ctr = atomic_read(&access_denied_ctr);
    seq_printf(m, " %24s %d", "access denied events: ", ctr);
    seq_puts(m, "\n");

    stall_tbl_wait_statistics(m);
    stall_tbl_display_buckets(stall_tbl, m);
    task_cache_display_buckets(m);
    inode_cache_display_buckets(m);

    return 0;
}

// proc file operation for open syscall
int dynsec_proc_open(struct inode *inode, struct file *file)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
#define PDE_DATA(a) container_of((a), struct proc_inode, vfs_inode)->pde->data
#endif
#if defined(RHEL_MAJOR) && defined(RHEL_MINOR) && RHEL_MAJOR == 9 && RHEL_MINOR > 0
// CentoOS 9 Stream (5.14.0-134.el9) removed PDE_DATA but supplies a pde_data
// helper function.
#define PDE_DATA(inode) pde_data(inode)
#endif
    return single_open(file, dynsec_proc_read, PDE_DATA(inode));
}

// dynsec proc file operations
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 6, 0)
const struct file_operations dynsec_proc_fops = {
    .owner      = THIS_MODULE,
    .open       = dynsec_proc_open,
    .read       = seq_read,
    .write      = dynsec_proc_write,
    .release    = single_release,
#else
const struct proc_ops dynsec_proc_fops = {
    .proc_open    = dynsec_proc_open,
    .proc_read    = seq_read,
    .proc_write   = dynsec_proc_write,
    .proc_release = single_release,
#endif
};

// function to create entries in /proc file system
void dynsec_register_proc_entries(void)
{
    static struct proc_dir_entry *ent;

#define PROC_FILE_MODE_RD  0400
#define PROC_FILE_MODE_WR  0200

    ent = proc_create_data(event_stats, PROC_FILE_MODE_RD, NULL,
                        &dynsec_proc_fops, (void *)stall_tbl);
    if (!ent) {
        pr_err("Unable to create proc file entries\n");
    }
}
