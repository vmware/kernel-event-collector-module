/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2021 VMware, Inc. All rights reserved.

#pragma once

extern bool dynsec_task_utils_init(void);
extern bool may_iterate_tasks(void);
extern struct file *dynsec_get_mm_exe_file(struct mm_struct *mm);
extern struct task_struct *dynsec_get_next_task(uint16_t opts, pid_t *pid);

static inline pid_t task_parent_tgid(const struct task_struct *task)
{
    pid_t tgid = 0;
    struct task_struct *parent = NULL;

    rcu_read_lock();
    parent = rcu_dereference(task->real_parent);
    if (!parent) {
        parent = rcu_dereference(task->parent);
    }
    if (parent) {
        tgid = parent->tgid;
    }
    rcu_read_unlock();

    return tgid;
}
