/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#pragma once

#include <linux/version.h>
#include <linux/time.h>
#include <linux/binfmts.h>

#include "process-context.h"

// ------------------------------------------------
//
// Task helpers
//
extern bool task_initialize(ProcessContext *context);
extern void task_shutdown(ProcessContext *context);

extern pid_t getcurrentpid(void);
extern pid_t getpid(struct task_struct *task);
extern pid_t gettid(struct task_struct *task);
extern pid_t getppid(struct task_struct *task);
extern void cb_get_task_struct(struct task_struct *task);
extern void cb_put_task_struct(struct task_struct *task);
extern void get_starttime(struct timespec *start_time);
extern uint64_t get_path_buffer_memory_usage(void);
bool task_get_path(struct task_struct *task, char *buffer, unsigned int buflen, char **pathname);
extern bool is_task_valid(struct task_struct *task);
extern bool is_task_alive(struct task_struct *task);
struct task_struct *cb_find_task(pid_t pid);
void get_devinfo_from_task(struct task_struct *task, uint64_t *device, uint64_t *ino);
struct inode *get_inode_from_task(struct task_struct *task);
bool get_cmdline_from_binprm(struct linux_binprm *bprm, char *cmdLine, size_t cmdLineSize);
bool sync_to_clone_hook(pid_t        pid,
                        int          max_sleep_count,
                        uint32_t     context,
                        const char *message);
void enumerate_and_track_all_tasks(ProcessContext *context);

#define IS_CURRENT_TASK(a)   (strcmp(current->comm, (a)) == 0)
