/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2021 VMware, Inc. All rights reserved.

#pragma once

#include "dynsec.h"
#include <linux/version.h>
#include <linux/path.h>

struct iattr;

// Important for these structs to be packed as
// they are critical to copying events to userspace.
#pragma pack(push, 1)
// Helper kernel structs in queue
struct dynsec_exec_kmsg {
    struct dynsec_msg_hdr hdr;
    struct dynsec_exec_msg msg;
};
struct dynsec_unlink_kmsg {
    struct dynsec_msg_hdr hdr;
    struct dynsec_unlink_msg msg;
};
struct dynsec_rename_kmsg {
    struct dynsec_msg_hdr hdr;
    struct dynsec_rename_msg msg;
};
struct dynsec_setattr_kmsg {
    struct dynsec_msg_hdr hdr;
    struct dynsec_setattr_msg msg;
};
struct dynsec_create_kmsg {
    struct dynsec_msg_hdr hdr;
    struct dynsec_create_msg msg;
};
struct dynsec_file_kmsg {
    struct dynsec_msg_hdr hdr;
    struct dynsec_file_msg msg;
};
struct dynsec_mmap_kmsg {
    struct dynsec_msg_hdr hdr;
    struct dynsec_mmap_msg msg;
};
struct dynsec_link_kmsg {
    struct dynsec_msg_hdr hdr;
    struct dynsec_link_msg msg;
};
struct dynsec_symlink_kmsg {
    struct dynsec_msg_hdr hdr;
    struct dynsec_symlink_msg msg;
};
struct dynsec_task_kmsg {
    struct dynsec_msg_hdr hdr;
    struct dynsec_task_msg msg;
};
struct dynsec_ptrace_kmsg {
    struct dynsec_msg_hdr hdr;
    struct dynsec_ptrace_msg msg;
};
struct dynsec_signal_kmsg {
    struct dynsec_msg_hdr hdr;
    struct dynsec_signal_msg msg;
};
struct dynsec_task_dump_kmsg {
    struct dynsec_msg_hdr hdr;
    struct dynsec_task_dump_msg msg;
};

// Base struct in queue
struct dynsec_event {
    uint32_t tid;
    uint64_t req_id;
    enum dynsec_event_type event_type;
    struct list_head list;
    uint16_t report_flags;
    uint64_t intent_req_id;
    unsigned long inode_addr;
};

// Child event structs
struct dynsec_exec_event {
    struct dynsec_event event;
    struct dynsec_exec_kmsg kmsg;
    char *path;
};

struct dynsec_unlink_event {
    struct dynsec_event event;
    struct dynsec_unlink_kmsg kmsg;
    char *path;
};

struct dynsec_rename_event {
    struct dynsec_event event;
    struct dynsec_rename_kmsg kmsg;
    char *old_path;
    char *new_path;
};

struct dynsec_setattr_event {
    struct dynsec_event event;
    struct dynsec_setattr_kmsg kmsg;
    char *path;
};

struct dynsec_create_event {
    struct dynsec_event event;
    struct dynsec_create_kmsg kmsg;
    char *path;
};

struct dynsec_file_event {
    struct dynsec_event event;
    struct dynsec_file_kmsg kmsg;
    char *path;
    struct path open_path;
};

struct dynsec_mmap_event {
    struct dynsec_event event;
    struct dynsec_mmap_kmsg kmsg;
    char *path;
};

struct dynsec_link_event {
    struct dynsec_event event;
    struct dynsec_link_kmsg kmsg;
    char *old_path;
    char *new_path;
};

struct dynsec_symlink_event {
    struct dynsec_event event;
    struct dynsec_symlink_kmsg kmsg;
    char *path;
    char *target_path;
};

struct dynsec_task_event {
    struct dynsec_event event;
    struct dynsec_task_kmsg kmsg;
    char *exec_path;
};

struct dynsec_ptrace_event {
    struct dynsec_event event;
    struct dynsec_ptrace_kmsg kmsg;
};

struct dynsec_signal_event {
    struct dynsec_event event;
    struct dynsec_signal_kmsg kmsg;
};

struct dynsec_task_dump_event {
    struct dynsec_event event;
    struct dynsec_task_dump_kmsg kmsg;
    char *exec_path;
};
#pragma pack(pop)

// container_of helpers

// Exec Event container_of helper
static inline struct dynsec_exec_event *
dynsec_event_to_exec(const struct dynsec_event *dynsec_event)
{
    return container_of(dynsec_event, struct dynsec_exec_event, event);
}

static inline struct dynsec_unlink_event *
dynsec_event_to_unlink(const struct dynsec_event *dynsec_event)
{
    return container_of(dynsec_event, struct dynsec_unlink_event, event);
}

static inline struct dynsec_rename_event *
dynsec_event_to_rename(const struct dynsec_event *dynsec_event)
{
    return container_of(dynsec_event, struct dynsec_rename_event, event);
}

static inline struct dynsec_setattr_event *
dynsec_event_to_setattr(const struct dynsec_event *dynsec_event)
{
    return container_of(dynsec_event, struct dynsec_setattr_event, event);
}

static inline struct dynsec_create_event *
dynsec_event_to_create(const struct dynsec_event *dynsec_event)
{
    return container_of(dynsec_event, struct dynsec_create_event, event);
}

static inline struct dynsec_link_event *
dynsec_event_to_link(const struct dynsec_event *dynsec_event)
{
    return container_of(dynsec_event, struct dynsec_link_event, event);
}

static inline struct dynsec_symlink_event *
dynsec_event_to_symlink(const struct dynsec_event *dynsec_event)
{
    return container_of(dynsec_event, struct dynsec_symlink_event, event);
}

static inline struct dynsec_file_event *
dynsec_event_to_file(const struct dynsec_event *dynsec_event)
{
    return container_of(dynsec_event, struct dynsec_file_event, event);
}

static inline struct dynsec_mmap_event *
dynsec_event_to_mmap(const struct dynsec_event *dynsec_event)
{
    return container_of(dynsec_event, struct dynsec_mmap_event, event);
}

static inline struct dynsec_task_event *
dynsec_event_to_task(const struct dynsec_event *dynsec_event)
{
    return container_of(dynsec_event, struct dynsec_task_event, event);
}

static inline struct dynsec_ptrace_event *
dynsec_event_to_ptrace(const struct dynsec_event *dynsec_event)
{
    return container_of(dynsec_event, struct dynsec_ptrace_event, event);
}

static inline struct dynsec_signal_event *
dynsec_event_to_signal(const struct dynsec_event *dynsec_event)
{
    return container_of(dynsec_event, struct dynsec_signal_event, event);
}

static inline struct dynsec_task_dump_event *
dynsec_event_to_task_dump(const struct dynsec_event *dynsec_event)
{
    return container_of(dynsec_event, struct dynsec_task_dump_event, event);
}

extern void prepare_dynsec_event(struct dynsec_event *dynsec_event, gfp_t mode);

extern void prepare_non_report_event(enum dynsec_event_type event_type, gfp_t mode);

extern uint16_t get_dynsec_event_payload(struct dynsec_event *dynsec_event);

extern struct dynsec_event *alloc_dynsec_event(enum dynsec_event_type event_type,
                                               uint32_t hook_type,
                                               uint16_t report_flags,
                                               gfp_t mode);

extern void free_dynsec_event(struct dynsec_event *dynsec_event);

extern ssize_t copy_dynsec_event_to_user(const struct dynsec_event *dynsec_event,
                                         char *__user p, size_t count);

// Event fillers
#include <linux/binfmts.h>
extern bool fill_in_bprm_set_creds(struct dynsec_event *dynsec_event,
                                   const struct linux_binprm *bprm, gfp_t mode);

extern bool fill_in_inode_unlink(struct dynsec_event *dynsec_event,
                                 struct inode *dir, struct dentry *dentry, gfp_t mode);

extern bool fill_in_inode_rename(struct dynsec_event *dynsec_event,
                                 struct inode *old_dir, struct dentry *old_dentry,
                                 struct inode *new_dir, struct dentry *new_dentry,
                                 gfp_t mode);

extern bool fill_in_inode_setattr(struct dynsec_event *dynsec_event,
                           unsigned int attr_mask, struct dentry *dentry,
                           struct iattr *attr, gfp_t mode);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
extern bool fill_in_inode_create(struct dynsec_event *dynsec_event,
                                 struct inode *dir, struct dentry *dentry,
                                 umode_t umode, gfp_t mode);
#else
extern bool fill_in_inode_create(struct dynsec_event *dynsec_event,
                                 struct inode *dir, struct dentry *dentry,
                                 int umode, gfp_t mode);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
extern bool fill_in_inode_mkdir(struct dynsec_event *dynsec_event,
                                struct inode *dir, struct dentry *dentry,
                                umode_t umode, gfp_t mode);
#else
extern bool fill_in_inode_mkdir(struct dynsec_event *dynsec_event,
                                struct inode *dir, struct dentry *dentry,
                                int umode, gfp_t mode);
#endif

extern bool fill_in_inode_link(struct dynsec_event *dynsec_event,
                               struct dentry *old_dentry,
                               struct inode *dir, struct dentry *new_dentry,
                               gfp_t mode);

extern bool fill_in_inode_symlink(struct dynsec_event *dynsec_event,
                                  struct inode *dir, struct dentry *dentry,
                                  const char *old_name, gfp_t mode);

extern bool fill_in_file_open(struct dynsec_event *dynsec_event, struct file *file,
                              gfp_t mode);

extern bool fill_in_file_free(struct dynsec_event *dynsec_event, struct file *file,
                              gfp_t mode);

extern bool fill_in_file_mmap(struct dynsec_event *dynsec_event, struct file *file,
                              unsigned long prot, unsigned long flags, gfp_t mode);

extern bool fill_task_free(struct dynsec_event *dynsec_event,
                           const struct task_struct *task);

extern bool fill_in_clone(struct dynsec_event *dynsec_event,
                          const struct task_struct *parent,
                          const struct task_struct *child, uint16_t extra_ctx);

extern bool fill_in_ptrace(struct dynsec_event *dynsec_event,
                           const struct task_struct *source,
                           const struct task_struct *target);

extern bool fill_in_task_kill(struct dynsec_event *dynsec_event,
                              const struct task_struct *target, int sig);

//#ifndef CONFIG_SECURITY_PATH
extern bool fill_in_preaction_create(struct dynsec_event *dynsec_event,
                                     int dfd, const char __user *filename,
                                     int flags, umode_t umode);
extern bool fill_in_preaction_rename(struct dynsec_event *dynsec_event,
                                     int olddfd, const char __user *oldname,
                                     int newdfd, const char __user *newname);
extern bool fill_in_preaction_unlink(struct dynsec_event *dynsec_event,
                                     struct path *path, gfp_t mode);

extern bool fill_in_preaction_symlink(struct dynsec_event *dynsec_event,
                                      const char *old_name,
                                      int newdfd, const char __user *linkpath);

extern bool fill_in_preaction_link(struct dynsec_event *dynsec_event,
                                   struct path *oldpath,
                                   int newdfd, const char __user *newname);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
extern bool fill_in_preaction_setattr(struct dynsec_event *dynsec_event,
                                      struct iattr *attr, struct path *path);
#endif
//#endif /* ! CONFIG_SECURITY_PATH */

extern struct dynsec_event *fill_in_dynsec_task_dump(struct task_struct *task,
                                                     gfp_t mode);
