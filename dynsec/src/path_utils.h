/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2021 VMware, Inc. All rights reserved.

#pragma once

extern bool dynsec_path_utils_init(void);

extern bool dynsec_current_chrooted(void);

extern char *dynsec_dentry_path(const struct dentry *dentry, char *buf, int buflen);

extern char *dynsec_d_path(const struct path *path, char *buf, int buflen);

extern char *dynsec_path_safeish(const struct path *path, char *buf, int buflen);

extern char *dynsec_build_path(struct path *path, uint16_t *size, gfp_t mode);
extern char *dynsec_build_dentry(struct dentry *dentry, uint16_t *size, gfp_t mode);


#include <linux/sched.h>
#include <linux/nsproxy.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
#include <linux/sched/task.h>
#include <linux/ns_common.h>
struct mnt_namespace {
    struct ns_common    ns;
};
#elif LINUX_VERSION_CODE >=  KERNEL_VERSION(4, 0, 0)
#include <linux/sched/task.h>
#include <linux/ns_common.h>
struct mnt_namespace {
    atomic_t        count;
    struct ns_common    ns;
};
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
struct mnt_namespace {
    atomic_t        count;
    unsigned int        proc_inum;
};
#else
// Nope
#endif

static inline unsigned int get_mnt_ns_id(const struct task_struct *task)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)
    return (task->nsproxy && task->nsproxy->mnt_ns) ? 
            task->nsproxy->mnt_ns->ns.inum : 0;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
    return (task->nsproxy && task->nsproxy->mnt_ns) ?
            task->nsproxy->mnt_ns->proc_inum : 0;
#else
    return 0;
#endif
}

static inline bool is_init_mnt_ns(const struct task_struct *task)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
    return &init_task == task ||
           !init_task.nsproxy ||
           !task->nsproxy ||
           !task->nsproxy->mnt_ns ||
           init_task.nsproxy->mnt_ns == task->nsproxy->mnt_ns;
#else
    return true;
#endif
}

