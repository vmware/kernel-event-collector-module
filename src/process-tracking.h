/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#pragma once

#include <linux/sched.h>
#include "hash-table-generic.h"
#include "rbtree-helper.h"
#include "raw_event.h"

typedef struct pt_table_key {
    pid_t    pid;
} PT_TBL_KEY;

#define FAKE_START false
#define REAL_START true

// List struct for use by RUNNING_BANNED_INODE_S
typedef struct processes_to_ban {
    void *procp; // Pointer for the process tracking element to ban
    struct list_head list;
} RUNNING_PROCESSES_TO_BAN;

typedef struct running_banned_inode_info_s {
    uint64_t count;
    uint64_t device;
    uint64_t inode;
    RUNNING_PROCESSES_TO_BAN BanList;
} RUNNING_BANNED_INODE_S;

typedef struct shared_tracking_data {
    ProcessDetails    exec_details;
    ProcessDetails    exec_parent_details;
    ProcessDetails    exec_grandparent_details;

    char             *path;
    char             *cmdline;
    bool              path_found;

    // Processes with this set report file open events
    bool              is_interpreter;
    uint64_t          exec_count;

    // This list contains all the open files tracked by the kernel for this process.
    //  Manipulation of this list is only done in file-process-tracking, and is protected
    //  by a mutex
    void            *tracked_files;

    // This tracks the owners of this struct (can be more than the number of active processes)
    atomic64_t        reference_count;

    // This tracks the number of active processes so that we can identify the last running process for an exec identity
    //  when sending an exit event.
    atomic64_t        active_process_count;

    // This holds a PCB_EVENT for the exit event for this process; which will only be enqueued
    // when the final process exits AND all outstanding events for the process have been read by the agent.
    // It is stored as an atomic so we can replace the pointer atomically
    atomic64_t        exit_event;
} SharedTrackingData;

typedef struct file_tree_handle {
    CB_RBTREE *tree;
    SharedTrackingData *shared_data;
} FILE_TREE_HANDLE;

typedef struct process_tracking {
    HashTableNode     pt_link;
    PT_TBL_KEY        pt_key;

    // This tracks the owners of this struct (can be more than the number of active processes)
    atomic64_t        reference_count;

    ProcessDetails    posix_details;
    ProcessDetails    posix_parent_details;
    ProcessDetails    posix_grandparent_details;

    pid_t       tid;
    uid_t       uid;
    uid_t       euid;
    int         action;   // How did we start

    bool        exec_blocked;
    bool        is_real_start;
    uint64_t    op_cnt;

    uint64_t    net_op_cnt;
    uint64_t    net_connect;
    uint64_t    net_accept;
    uint64_t    net_dns;

    uint64_t    file_op_cnt;
    uint64_t    file_create;
    uint64_t    file_delete;
    uint64_t    file_open;      // First write equals open
    uint64_t    file_write;
    uint64_t    file_close;
    uint64_t    file_map_write;
    uint64_t    file_map_exec;

    uint64_t    process_op_cnt;
    uint64_t    process_create;
    uint64_t    process_exit;
    uint64_t    process_create_by_fork;
    uint64_t    process_create_by_exec;

    uint64_t    childproc_cnt;

    SharedTrackingData *shared_data;

    // This will hold a refernce to the parents shared_data AFTER a processes exec
    //  and UNTIL the event is queued.
    SharedTrackingData *parent_shared_data;

} ProcessTracking;

bool process_tracking_initialize(ProcessContext *context);
void process_tracking_shutdown(ProcessContext *context);

ProcessTracking *process_tracking_create_process(
        pid_t               pid,
        pid_t               parent,
        pid_t               tid,
        uid_t               uid,
        uid_t               euid,
        time_t              start_time,
        int                 action,
        struct task_struct *taskp,
        bool                is_real_start,
        ProcessContext *context);
ProcessTracking *process_tracking_update_process(
        pid_t               pid,
        pid_t               tid,
        uid_t               uid,
        uid_t               euid,
        uint64_t            device,
        uint64_t            inode,
        char *path,
        bool                path_found,
        time_t              start_time,
        int                 action,
        struct task_struct *taskp,
        CB_EVENT_TYPE       event_type,
        bool                is_real_start,
        ProcessContext *context);

ProcessTracking *process_tracking_get_process(pid_t pid, ProcessContext *context);
void process_tracking_put_process(ProcessTracking *procp, ProcessContext *context);
void process_tracking_remove_process(ProcessTracking *procp, ProcessContext *context);
bool is_process_tracked(pid_t pid, ProcessContext *context);
void is_process_tracked_get_state_by_inode(RUNNING_BANNED_INODE_S *psRunningInodesToBan, ProcessContext *context);
void process_tracking_set_cmdline(ProcessTracking *procp, char *cmdline, ProcessContext *context);
bool process_tracking_report_exit(pid_t pid, ProcessContext *context);
char *process_tracking_get_path(SharedTrackingData *shared_data);

// Discovery
void process_tracking_send_process_discovery(ProcessContext *context);

// Hook Helpers
void process_tracking_mark_as_blocked(ProcessTracking *procp);
bool process_tracking_is_blocked(ProcessTracking *procp);
pid_t process_tracking_exec_pid(ProcessTracking *procp);
void create_process_start_by_exec_event(struct task_struct *task, ProcessContext *context);
ProcessTracking *get_procinfo_and_create_process_start_if_needed(pid_t pid, const char *msg, ProcessContext *context);
SharedTrackingData *process_tracking_get_shared_data_ref(SharedTrackingData *shared_data, ProcessContext *context);
void process_tracking_release_shared_data_ref(SharedTrackingData *shared_data, ProcessContext *context);

// Event Helper
void process_tracking_set_event_info(ProcessTracking *procp, CB_EVENT_TYPE eventType, PCB_EVENT event, ProcessContext *context);
void process_tracking_store_exit_event(ProcessTracking *procp, PCB_EVENT event, ProcessContext *context);
bool process_tracking_should_track_user(void);
bool process_tracking_has_active_process(ProcessTracking *procp);

// File helpers
typedef void (*process_tracking_for_each_tree_callback)(void *tree, void *priv, ProcessContext *context);
bool process_tracking_get_file_tree(pid_t pid, FILE_TREE_HANDLE *handle, ProcessContext *context);
void process_tracking_put_file_tree(FILE_TREE_HANDLE *handle, ProcessContext *context);
void process_tracking_for_each_file_tree(process_tracking_for_each_tree_callback callback, void *priv, ProcessContext *context);

// List of interpreters. The SharedTrackingData::is_interpreter flag
// is set for any process whose path contains a name in this list.
extern char **g_interpreter_names;
extern int    g_interpreter_names_count;
