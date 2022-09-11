/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2021 VMware, Inc. All rights reserved.

#pragma once
#include <linux/ioctl.h>

#ifndef PATH_MAX
#ifdef __KERNEL__
#include <linux/limits.h>
#else
#include <limits.h>
#endif
#endif /* ! PATH_MAX */

#define DYNSEC_HOOK_TYPE_EXEC       0x00000001
#define DYNSEC_HOOK_TYPE_RENAME     0x00000002
#define DYNSEC_HOOK_TYPE_UNLINK     0x00000004
#define DYNSEC_HOOK_TYPE_RMDIR      0x00000008
#define DYNSEC_HOOK_TYPE_MKDIR      0x00000010
#define DYNSEC_HOOK_TYPE_CREATE     0x00000020
#define DYNSEC_HOOK_TYPE_SETATTR    0x00000040
#define DYNSEC_HOOK_TYPE_OPEN       0x00000080
#define DYNSEC_HOOK_TYPE_LINK       0x00000100
#define DYNSEC_HOOK_TYPE_SYMLINK    0x00000200
#define DYNSEC_HOOK_TYPE_SIGNAL     0x00000400
#define DYNSEC_HOOK_TYPE_PTRACE     0x00000800
#define DYNSEC_HOOK_TYPE_MMAP       0x00001000
#define DYNSEC_HOOK_TYPE_CLOSE      0x00002000
#define DYNSEC_HOOK_TYPE_TASK_FREE  0x00004000
#define DYNSEC_HOOK_TYPE_EXIT       0x00008000
#define DYNSEC_HOOK_TYPE_CLONE      0x00010000
#define DYNSEC_HOOK_TYPE_INODE_FREE 0x00020000

// Tracepoints
#define DYNSEC_TP_HOOK_TYPE_CLONE       DYNSEC_HOOK_TYPE_CLONE
#define DYNSEC_TP_HOOK_TYPE_EXIT        DYNSEC_HOOK_TYPE_EXIT
#define DYNSEC_TP_HOOK_TYPE_TASK_FREE   DYNSEC_HOOK_TYPE_TASK_FREE

// Event Message Flags aka Report
#define DYNSEC_REPORT_STALL         0x0001
// Event provide supplemental information (not stallable)
#define DYNSEC_REPORT_INTENT        0x0002
// Eventually may use to prevent enqueueing events
#define DYNSEC_REPORT_AUDIT         0x0004
// Event did not stall due to a cache option
#define DYNSEC_REPORT_CACHED        0x0008
#define DYNSEC_REPORT_UNSTALL       DYNSEC_REPORT_CACHED
// Event Denied. Decision made within kernel module.
// If POST flag is set, the operation was denied somewhere.
#define DYNSEC_REPORT_DENIED        0x0010
// Event came from a the client
#define DYNSEC_REPORT_SELF          0x0020
// Used to determine importance on queue and wake_up usage
#define DYNSEC_REPORT_HI_PRI        0x0040
#define DYNSEC_REPORT_LO_PRI        0x0080
// Unused but could provide supplemental information POST create.
// To provide the created inode value if desired.
#define DYNSEC_REPORT_POST          0x0100
// Event found there was a previous intent event via intent_req_id
// where the two event's data can be combined by client
#define DYNSEC_REPORT_INTENT_FOUND  0x0200
#define DYNSEC_REPORT_LAST_TASK     0x0400
// File event was not stalled due to the read only cache.
#define DYNSEC_REPORT_INODE_CACHED  0x0800
// When set and sent to userspace. The event can be discarded.
// Also helpful for debugging what would be ignored.
#define DYNSEC_REPORT_IGNORE        0x1000
// Clue for POST events that an operation failed.
#define DYNSEC_REPORT_FAIL          0x2000

// Response Type For Stalls
#define DYNSEC_RESPONSE_ALLOW       0x00000000
#define DYNSEC_RESPONSE_EPERM       0x00000001
#define DYNSEC_RESPONSE_CONTINUE    0x00010000
//
// Task and Inode Event Labeling (Cache) Options
//

// Keep Event Cache Enabled Until Explicitly Disabled
#define DYNSEC_CACHE_ENABLE           0x00000001
// Keep Event Cache Enabled If Prev Event Also Cachable
#define DYNSEC_CACHE_ENABLE_EXCL      0x00000002
// Keep Event Cache Enabled If Prev Event Same Type.
#define DYNSEC_CACHE_ENABLE_STRICT    0x00000004
// Explicitly Disable Caching For Event Type
#define DYNSEC_CACHE_DISABLE          0x00000010
// Clear All Caching Explicitly
#define DYNSEC_CACHE_CLEAR            0x00000020
// Clear All Caching For An Event Type
#define DYNSEC_CACHE_CLEAR_ON_EVENT   0x00000040
// Unused - Instead of not stalling, don't send the event
#define DYNSEC_CACHE_IGNORE           0x00000100
#define DYNSEC_CACHE_INHERIT          0x00001000
#define DYNSEC_CACHE_INHERIT_RECURSE  0x00002000

// For Setattr Event
#define DYNSEC_SETATTR_MODE     (1 << 0)
#define DYNSEC_SETATTR_UID      (1 << 1)
#define DYNSEC_SETATTR_GID      (1 << 2)
#define DYNSEC_SETATTR_SIZE     (1 << 3)
#define DYNSEC_SETATTR_FILE     (1 << 13)
#define DYNSEC_SETATTR_OPEN     (1 << 15)

// Currently all structs exposed to userspace are packed.
// Packed structs have their pros and cons, take them into consideration.
#pragma pack(push, 1)
// Event Message Types
enum dynsec_event_type {
    DYNSEC_EVENT_TYPE_EXEC,
    DYNSEC_EVENT_TYPE_RENAME,
    DYNSEC_EVENT_TYPE_UNLINK,
    DYNSEC_EVENT_TYPE_RMDIR,
    DYNSEC_EVENT_TYPE_MKDIR,
    DYNSEC_EVENT_TYPE_CREATE,
    DYNSEC_EVENT_TYPE_SETATTR,
    DYNSEC_EVENT_TYPE_OPEN,
    DYNSEC_EVENT_TYPE_CLOSE,
    DYNSEC_EVENT_TYPE_LINK,
    DYNSEC_EVENT_TYPE_SYMLINK,
    DYNSEC_EVENT_TYPE_SIGNAL,
    DYNSEC_EVENT_TYPE_PTRACE,
    DYNSEC_EVENT_TYPE_MMAP,
    DYNSEC_EVENT_TYPE_CLONE,
    DYNSEC_EVENT_TYPE_EXIT,
    DYNSEC_EVENT_TYPE_TASK_DUMP,
    // Special Events
    DYNSEC_EVENT_TYPE_HEALTH,
    DYNSEC_EVENT_TYPE_GENERIC_AUDIT,
    DYNSEC_EVENT_TYPE_GENERIC_DEBUG,
    DYNSEC_EVENT_TYPE_MAX,
};

struct dynsec_msg_hdr {
    uint16_t payload;
    uint16_t report_flags;
    uint32_t hook_type;  // Context for non-stalling events
    uint32_t tid;
    uint64_t req_id;
    uint64_t intent_req_id; // Valid when DYNSEC_REPORT_INTENT_FOUND set
    enum dynsec_event_type event_type;
};

// Response from usermode
struct dynsec_response {
    uint32_t tid;
    uint64_t req_id;
    enum dynsec_event_type event_type;
    int32_t response;
    uint32_t cache_flags;
    uint32_t inode_cache_flags;
    uint32_t task_label_flags;

    // allow this to override global continue value
    // when continuation response set.
    uint32_t overrided_stall_timeout;
};

// Eventually have dynsec_task_ctx contain this
struct dynsec_cred {
    uint32_t uid;
    uint32_t euid;
    uint32_t gid;
    uint32_t egid;
    uint32_t fsuid;
    uint32_t fsgid;
    uint32_t securebits;
};

struct dynsec_task_ctx {
    uint32_t tid;
    uint32_t pid;
    uint32_t ppid;
    uint32_t real_parent_id;
    // Eventually replace with struct dynsec_cred
    uint32_t uid;
    uint32_t euid;
    uint32_t gid;
    uint32_t egid;
    uint32_t mnt_ns;
    uint32_t flags;
    uint64_t start_time;
#define DYNSEC_TASK_IN_EXECVE               0x0001
#define DYNSEC_TASK_HAS_MM                  0x0002
#define DYNSEC_TASK_IMPRECISE_START_TIME    0x0004
#define DYNSEC_TASK_HAS_MNT_NS              0x0008
    uint16_t extra_ctx;

#define DYNSEC_TASK_COMM_LEN   16
    char     comm[DYNSEC_TASK_COMM_LEN];
};

//
// NOTE:
//  Offset fields describe the location or the number of bytes
//  the blob or string is from the beginning of an event's header.
//
// EXAMPLE:
//
//      if (hdr->event_type == DYNSEC_EVENT_TYPE_EXEC)
//          p = get_exec_event_path((struct dynsec_exec_umsg *)hdr);
//      ...
//
//      char *get_exec_event_path(struct dynsec_exec_umsg *exec) {
//          if (exec && exec->msg.path_offset)
//              return (char *)exec + exec->msg.path_offset;
//          return NULL;
//      }
//

struct dynsec_blob {
    uint16_t offset;    // Offset of blob from event header.
    uint16_t size;      // Size of blob. Not NUL '\0' terminated
};

struct dynsec_file {
// ino, uid, gid, size, umode
#define DYNSEC_FILE_ATTR_INODE          0x0001
// dev, sb_magic
#define DYNSEC_FILE_ATTR_DEVICE         0x0002
// parent_[ino,uid,gid,umode]
#define DYNSEC_FILE_ATTR_PARENT_INODE   0x0004
// parent_dev
#define DYNSEC_FILE_ATTR_PARENT_DEVICE  0x0008
// Path Type/Path Confidence Level
#define DYNSEC_FILE_ATTR_PATH_FULL      0x0010
#define DYNSEC_FILE_ATTR_PATH_DENTRY    0x0020
// Hints path needs normalization and is raw intent
#define DYNSEC_FILE_ATTR_PATH_RAW       0x0040
// Tell us some part of the path may be truncated
#define DYNSEC_FILE_ATTR_PATH_TRUNC     0x0080
// Hints that umode will likely inherit parent DAC perms
#define DYNSEC_FILE_ATTR_POSIX_ACL      0x0100
#define DYNSEC_FILE_ATTR_DELETED        0x0200
// Hints device likely has an entry in /sys
#define DYNSEC_FILE_ATTR_HAS_BACKING    0x0400
// Hints parent's device likely has an entry in /sys
#define DYNSEC_FILE_ATTR_PARENT_HAS_BACKING    0x0800
    uint16_t attr_mask;
    uint64_t ino;
    uint32_t dev;
    uint16_t umode;
    uint32_t uid;
    uint32_t gid;
    uint64_t size;
    uint32_t count;
    uint32_t nlink;
    uint64_t sb_magic;
    uint64_t parent_ino;
    uint32_t parent_dev;
    uint32_t parent_uid;
    uint32_t parent_gid;
    uint16_t parent_umode;
    uint16_t path_offset;   // offset of path from beginning of event header
    uint16_t path_size;     // includes the terminating NUL '\0'
};

// Core Exec Context
struct dynsec_exec_msg {
    struct dynsec_task_ctx task;
    struct dynsec_cred new_cred;
    struct dynsec_file file;
};

struct dynsec_exec_umsg {
    struct dynsec_msg_hdr hdr;
    struct dynsec_exec_msg msg;
};

// Core Unlink Content
struct dynsec_unlink_msg {
    struct dynsec_task_ctx task;
    struct dynsec_file file;
};

struct dynsec_unlink_umsg {
    struct dynsec_msg_hdr hdr;
    struct dynsec_unlink_msg msg;
};

// Core Rename Content
struct dynsec_rename_msg {
    struct dynsec_task_ctx task;
    struct dynsec_file old_file;
    struct dynsec_file new_file;
};

struct dynsec_rename_umsg {
    struct dynsec_msg_hdr hdr;
    struct dynsec_rename_msg msg;
};

// Core Setattr Content
struct dynsec_setattr_msg {
    struct dynsec_task_ctx task;
    uint32_t attr_mask;
    uint16_t attr_umode;
    uint32_t attr_uid;
    uint32_t attr_gid;
    uint64_t attr_size;
    struct dynsec_file file;
};

struct dynsec_setattr_umsg {
    struct dynsec_msg_hdr hdr;
    struct dynsec_setattr_msg msg;
};

// Core Create/Mkdir Content
struct dynsec_create_msg {
    struct dynsec_task_ctx task;
    struct dynsec_file file;
};

struct dynsec_create_umsg {
    struct dynsec_msg_hdr hdr;
    struct dynsec_create_msg msg;
};

// Core Generic File Content
struct dynsec_file_msg {
    struct dynsec_task_ctx task;
    uint32_t f_mode;
    uint32_t f_flags;
    struct dynsec_file file;
    // file descriptor we might send to userspace in the future
    int32_t fd;
};

struct dynsec_file_umsg {
    struct dynsec_msg_hdr hdr;
    struct dynsec_file_msg msg;
};

// Core Link Content
struct dynsec_link_msg {
    struct dynsec_task_ctx task;
    struct dynsec_file old_file;
    struct dynsec_file new_file;
};

struct dynsec_link_umsg {
    struct dynsec_msg_hdr hdr;
    struct dynsec_link_msg msg;
};

// Core Symlink Content
struct dynsec_symlink_msg {
    struct dynsec_task_ctx task;
    struct dynsec_file file;
    struct dynsec_blob target;
};

struct dynsec_symlink_umsg {
    struct dynsec_msg_hdr hdr;
    struct dynsec_symlink_msg msg;
};

// Core Mmap Content
struct dynsec_mmap_msg {
    struct dynsec_task_ctx task;
    uint64_t mmap_prot;
    uint64_t mmap_flags;
    uint32_t f_mode;
    uint32_t f_flags;
    struct dynsec_file file;
};

struct dynsec_mmap_umsg {
    struct dynsec_msg_hdr hdr;
    struct dynsec_mmap_msg msg;
};

// Core Ptrace Content
struct dynsec_ptrace_msg {
    struct dynsec_task_ctx source;
    struct dynsec_task_ctx target;
};

struct dynsec_ptrace_umsg {
    struct dynsec_msg_hdr hdr;
    struct dynsec_ptrace_msg msg;
};

// Core Signal Content
struct dynsec_signal_msg {
    struct dynsec_task_ctx source;
    int32_t signal;
    struct dynsec_task_ctx target;
};

struct dynsec_signal_umsg {
    struct dynsec_msg_hdr hdr;
    struct dynsec_signal_msg msg;
};

// Core Task Event
struct dynsec_task_msg {
    struct dynsec_task_ctx task;
    struct dynsec_file exec_file;
};

struct dynsec_task_umsg {
    struct dynsec_msg_hdr hdr;
    struct dynsec_task_msg msg;
};

// Core Task Dump Event
struct dynsec_task_dump_msg {
    struct dynsec_task_ctx task;
    struct dynsec_file exec_file;
};

struct dynsec_task_dump_umsg {
    struct dynsec_msg_hdr hdr;
    struct dynsec_task_dump_msg msg;
};

// Ioctls
#define DYNSEC_IOC_BASE            'V'
#define DYNSEC_IOC_OFFSET          'M'
// Request to directly get a dump of a task back to the ioctl
#define DYNSEC_IOC_TASK_DUMP       _IO(DYNSEC_IOC_BASE, DYNSEC_IOC_OFFSET + 1)
// Request to dump tasks from a starting pid value to the event queue
#define DYNSEC_IOC_TASK_DUMP_ALL   _IO(DYNSEC_IOC_BASE, DYNSEC_IOC_OFFSET + 2)
// Return the current struct dynsec_config
#define DYNSEC_IOC_GET_CONFIG      _IO(DYNSEC_IOC_BASE, DYNSEC_IOC_OFFSET + 3)
// All enabled hooks go into a pass-through mode
#define DYNSEC_IOC_BYPASS_MODE     _IO(DYNSEC_IOC_BASE, DYNSEC_IOC_OFFSET + 4)
// Enable or disable stalling
#define DYNSEC_IOC_STALL_MODE      _IO(DYNSEC_IOC_BASE, DYNSEC_IOC_OFFSET + 5)
// Disable or fine tune several queue and poll notifer options
#define DYNSEC_IOC_QUEUE_OPTS      _IO(DYNSEC_IOC_BASE, DYNSEC_IOC_OFFSET + 6)
// TODO: Remove from char dev registry. Will only work in Bypass Mode
#define DYNSEC_IOC_DELETE_DEVICE   _IO(DYNSEC_IOC_BASE, DYNSEC_IOC_OFFSET + 7)
// Change the default stall timeout by milliseconds
#define DYNSEC_IO_STALL_TIMEOUT_MS _IO(DYNSEC_IOC_BASE, DYNSEC_IOC_OFFSET + 8)
// Set options for sending files on open events
#define DYNSEC_IOC_SEND_FILE       _IO(DYNSEC_IOC_BASE, DYNSEC_IOC_OFFSET + 9)
// Operation to request
#define DYNSEC_IOC_PROTECT         _IO(DYNSEC_IOC_BASE, DYNSEC_IOC_OFFSET + 10)
// Set ignore events to disable, enable or debug enable
#define DYNSEC_IOC_IGNORE_MODE     _IO(DYNSEC_IOC_BASE, DYNSEC_IOC_OFFSET + 11)
// Explicitly set a task's label
#define DYNSEC_IOC_LABEL_TASK      _IO(DYNSEC_IOC_BASE, DYNSEC_IOC_OFFSET + 12)
#define DYNSEC_IOC_STALL_OPTS      _IO(DYNSEC_IOC_BASE, DYNSEC_IOC_OFFSET + 13)
// Set file system specific stall mask
#define DYNSEC_IOC_FS_STALL_MASK   _IO(DYNSEC_IOC_BASE, DYNSEC_IOC_OFFSET + 14)

// May want a request to print out what kernel objects
// that are blocking a clean rmmod.


// Ioctls Transport Data

// Dump Task Header
struct dynsec_task_dump_hdr {
    // size - payload of userspace buffer and itself. And
    //      assumes offset to userspace buffer is after header.
    uint16_t size;

// Optionally request the next matching thread or process
#define DUMP_NEXT_THREAD 0x0001
#define DUMP_NEXT_TGID   0x0002
    uint16_t opts;
    pid_t pid;
};

// Base Payload for DYNSEC_IOC_TASK_DUMP
// Do not use struct for storage size. Use a backing
// buffer/blob as storage. This is to allow for extra storage
// for the dynamic data like strings or binary data to be sent back.
//    aka hdr.size = sizeof(blob)
// So a good number for the blob size:
//    sizeof(hdr) +
//    sizeof(umsg) +
//    max path for file (PATH_MAX) +
//    cmdline space if we ever decide to provide it
struct dynsec_task_dump {
    struct dynsec_task_dump_hdr hdr;

    struct dynsec_task_dump_umsg umsg;
};

// Dump All Tasks Ioctl
struct dynsec_task_dump_all {
    struct dynsec_task_dump_hdr hdr;
};

struct dynsec_match {
#define DYNSEC_MATCHING_PATH_EQ             0x00000001
#define DYNSEC_MATCHING_PATH_CONTAINS       0x00000002
#define DYNSEC_MATCHING_PATH_STARTS_WITH    0x00000004
#define DYNSEC_MATCHING_PATH_ENDS_WITH      0x00000008
#define DYNSEC_MATCHING_MAY_SIGNAL_CLIENT   0x00010000
    uint64_t match_flags;

    union {
        char path[PATH_MAX];
    };
};

struct dynsec_protect_ioc_hdr {
    uint16_t size;
#define DYNSEC_PROTECT_DISABLE  0x0001
// CLEAR only valid if DISABLE bit set or protect mode already disabled.
#define DYNSEC_PROTECT_CLEAR    0x0002
// When ADD set, size must be:
//     sizeof(struct dynsec_protect_ioc_hdr) + sizeof(struct dynsec_match).
#define DYNSEC_PROTECT_ADD      0x0004
#define DYNSEC_PROTECT_ENABLE   0x0008
    uint16_t protect_flags;
};

struct dynsec_label_task_hdr {
    pid_t tid;
    pid_t pid;
    uint32_t task_label_flags;
};

// Multiplex stall and stall timeout options
struct dynsec_stall_ioc_hdr {
#define DYNSEC_STALL_MODE_SET             0x00000001
#define DYNSEC_STALL_DEFAULT_TIMEOUT      0x00000002
#define DYNSEC_STALL_CONTINUE_TIMEOUT     0x00000004
#define DYNSEC_STALL_DEFAULT_DENY         0x00000008
    uint32_t flags;
    uint32_t stall_mode;
    uint32_t stall_timeout;
    uint32_t stall_timeout_continue;
    uint32_t stall_timeout_deny;
};

// 1 minute time, 5 sec timeout...
// 60/5 = 12 counter
#define DYNSEC_STALL_TIMEOUT_CTR_LIMIT      12

// Eventually will contain mix of global
// and per-client settings and state of kmod.
struct dynsec_config {
    // Don't do anything but propagate callbacks
    uint32_t bypass_mode;
    // Unsets STALL in report flags when disabled aka ZERO
    uint32_t stall_mode;
    // Tells us how long we may initially stall in milliseconds
    uint32_t stall_timeout;
    // Tells us how long we may continue stalling in milliseconds
    uint32_t stall_timeout_continue;
    // Tells if we are in default deny for stall timeouts.
    uint32_t stall_timeout_deny;

    // Lazy notifer may not always notify when a new event is available
    uint32_t lazy_notifier;
    // Hard limit on events to send per-read.
    uint32_t queue_threshold;
    // Max events before enforcing a wake_up
    uint32_t notify_threshold;

    // Option to send files to client reading events.
    uint32_t send_files;

    // Protect a connected client and secondary applications.
    uint32_t protect_mode;

    // Allow kernel level ignoring.
    uint32_t ignore_mode;

    // Available hooks. Currently Immutable.
    uint64_t lsm_hooks;
    uint64_t process_hooks;
    uint64_t preaction_hooks;

    // File system types to stall or ignore
    // Based on the definitions in linux/magic.h
    // enums defined in src/fs_utils.h
    uint64_t file_system_stall_mask;

};

// enums based on MAGIC definitions of file system types
// from linux/magic.h kernel version 5.18
enum file_system_magic_bits_e {
     EXT2_SUPER_MAGIC_BIT,  // 0
     BTRFS_SUPER_MAGIC_BIT,
     HPFS_SUPER_MAGIC_BIT,
     ISOFS_SUPER_MAGIC_BIT,
     JFFS2_SUPER_MAGIC_BIT,
     XFS_SUPER_MAGIC_BIT,
     FUSE_SUPER_MAGIC_BIT,
     MSDOS_SUPER_MAGIC_BIT,
     NFS_SUPER_MAGIC_BIT,
     REISERFS_SUPER_MAGIC_BIT,
     SMB_SUPER_MAGIC_BIT,  // 10
     CIFS_SUPER_MAGIC_BIT,
     SMB2_SUPER_MAGIC_BIT,
     USBDEVICE_SUPER_MAGIC_BIT,
};

#pragma pack(pop)

