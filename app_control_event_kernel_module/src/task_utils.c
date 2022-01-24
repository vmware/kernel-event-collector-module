// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 VMware, Inc. All rights reserved.
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/pid_namespace.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)
#include <linux/sched/task.h>
#include <linux/sched/signal.h>
#endif

#include "symbols.h"
#include "task_utils.h"
#include "dynsec.h"

struct task_symz {
    struct pid *(*find_ge_pid)(int nr, struct pid_namespace *ns);
    struct file *(*get_mm_exe_file)(struct mm_struct *mm);
    pid_t (*pid_nr_ns)(struct pid *pid, struct pid_namespace *ns);
};

struct task_symz task_syms;

bool dynsec_task_utils_init(void)
{
    find_symbol_indirect("find_ge_pid",
                         (unsigned long *)&task_syms.find_ge_pid);

    // Could directly be used in newer kernels
#if LINUX_VERSION_CODE <= KERNEL_VERSION(3, 10, 0)
    find_symbol_indirect("get_mm_exe_file",
                         (unsigned long *)&task_syms.get_mm_exe_file);
#else
    task_syms.get_mm_exe_file = get_mm_exe_file;
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
    find_symbol_indirect("pid_nr_ns",
                         (unsigned long *)&task_syms.pid_nr_ns);
#else
    task_syms.pid_nr_ns = pid_nr_ns;
#endif

    if (!task_syms.find_ge_pid) {
        return false;
    }

    return true;
}
bool may_iterate_tasks(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
    return task_syms.pid_nr_ns && task_syms.find_ge_pid;
#else
    return task_syms.find_ge_pid;
#endif
}

static pid_t dynsec_pid_nr_ns(struct pid *pid, struct pid_namespace *ns)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
    if (likely(task_syms.pid_nr_ns))
        return task_syms.pid_nr_ns(pid, ns);
    return 0;
#else
    return pid_nr_ns(pid, ns);
#endif
}

// On success call fput
struct file *dynsec_get_mm_exe_file(struct mm_struct *mm)
{
    if (unlikely(!task_syms.get_mm_exe_file) || !mm) {
        return NULL;
    }
    return task_syms.get_mm_exe_file(mm);
}

static struct pid *dynsec_find_ge_pid(int nr, struct pid_namespace *ns)
{
    if (unlikely(!task_syms.find_ge_pid) || !ns) {
        return NULL;
    }
    return task_syms.find_ge_pid(nr, ns);
}

// Caller responsible for calling put_task_struct() when done!
static struct task_struct *__dynsec_get_next_tgid(pid_t *tgid, struct pid_namespace *ns)
{
    struct pid *pid;
    struct task_struct *task = NULL;
    pid_t local_tgid;

    if (!task_syms.find_ge_pid || !tgid || !ns) {
        return NULL;
    }
    local_tgid = *tgid;

    rcu_read_lock();
retry:
    task = NULL;
    // Finds the next pid start at given id
    pid = dynsec_find_ge_pid(local_tgid, ns);
    if (pid) {
        local_tgid = dynsec_pid_nr_ns(pid, ns);
// TODO: Find when PIDTYPE_TGID is really defined
#if LINUX_VERSION_CODE <= KERNEL_VERSION(3,10,0) || defined(RHEL_MAJOR) && RHEL_MAJOR == 8 && RHEL_MINOR == 0
        task = pid_task(pid, PIDTYPE_PID);
        if (!task || !has_group_leader_pid(task)) {
            local_tgid += 1;
            goto retry;
        }
#else
        task = pid_task(pid, PIDTYPE_TGID);
        if (!task) {
            local_tgid += 1;
            goto retry;
        }
#endif
        get_task_struct(task);
        *tgid = local_tgid;
    }
    rcu_read_unlock();

    return task;
}

static struct task_struct *__dynsec_get_next_tid(pid_t *tid, struct pid_namespace *ns)
{
    struct pid *pid;
    struct task_struct *task = NULL;
    pid_t local_tid;

    if (!task_syms.find_ge_pid || !tid || !ns) {
        return NULL;
    }
    local_tid = *tid;

    rcu_read_lock();
retry:
    task = NULL;
    // Finds the next pid start at given id
    pid = dynsec_find_ge_pid(local_tid, ns);
    if (pid) {
        local_tid = dynsec_pid_nr_ns(pid, ns);
        task = pid_task(pid, PIDTYPE_PID);
        if (!task) {
            local_tid += 1;
            goto retry;
        }
        get_task_struct(task);
        *tid = local_tid;
    }
    rcu_read_unlock();

    return task;
}

struct task_struct *dynsec_get_next_task(uint16_t opts, pid_t *pid)
{
    if (opts & DUMP_NEXT_THREAD) {
        return __dynsec_get_next_tid(pid, task_active_pid_ns(current));
    }
    if (opts & DUMP_NEXT_TGID) {
        return __dynsec_get_next_tgid(pid, task_active_pid_ns(current));
    }
    return NULL;
}
