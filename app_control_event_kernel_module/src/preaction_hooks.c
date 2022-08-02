// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 VMware, Inc. All rights reserved.
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/capability.h>
#include <linux/unistd.h>
#include <linux/namei.h>

#include "preaction_hooks.h"
#include "symbols.h"
#include "dynsec.h"
#include "fs_utils.h"
#include "lsm_mask.h"

#include "stall_tbl.h"
#include "stall_reqs.h"
#include "factory.h"
#include "mem.h"


struct syscall_hooks {
#ifdef USE_PT_REGS
#define DEF_SYS_HOOK(NAME, ...) asmlinkage long (*NAME)(struct pt_regs *regs)
#else
#define DEF_SYS_HOOK(NAME, ...) asmlinkage long (*NAME)(__VA_ARGS__)
#endif
    // Hook required on RHEL7 kernels and RHEL8 when other syscall hooks
    // are needed. Non-RHEL kernels do not need this hook.
    DEF_SYS_HOOK(delete_module, const char __user *name_user,
                 unsigned int flags);

    // CREATE Intents
    DEF_SYS_HOOK(open, const char __user *filename, int flags, umode_t mode);
    DEF_SYS_HOOK(creat, const char __user *pathname, umode_t mode);
    DEF_SYS_HOOK(openat, int dfd, const char __user *filename, int flags,
                 umode_t mode);
#ifdef __NR_openat2
    DEF_SYS_HOOK(openat2, int dfd, const char __user *filename,
                 struct open_how __user * how, size_t usize);
#endif /* __NR_openat2 */
    DEF_SYS_HOOK(mknod, const char __user *filename,
                 umode_t mode, unsigned dev);
    DEF_SYS_HOOK(mknodat, int dfd, const char __user *filename,
                 umode_t mode, unsigned dev);

    // RENAME Intents
    DEF_SYS_HOOK(rename, const char __user *oldname,
                 const char __user *newname);
#ifdef __NR_renameat
    DEF_SYS_HOOK(renameat, int olddfd, const char __user *oldname,
                 int newdfd, const char __user *newname);
#endif /* __NR_renameat */
#ifdef __NR_renameat2
    DEF_SYS_HOOK(renameat2, int olddfd, const char __user *oldname,
                 int newdfd, const char __user *newname, unsigned int flags);
#endif /* __NR_renameat2 */

    // MKDIR Intents
    DEF_SYS_HOOK(mkdir, const char __user *pathname, umode_t mode);
    DEF_SYS_HOOK(mkdirat, int dfd, const char __user *pathname, umode_t mode);

    // UNLINK and RMDIR Intents
    DEF_SYS_HOOK(unlink, const char __user *pathname);
    DEF_SYS_HOOK(unlinkat, int dfd, const char __user *pathname, int flag);
    DEF_SYS_HOOK(rmdir, const char __user *pathname);

    // SYMLINK Intents
    DEF_SYS_HOOK(symlink, const char __user *oldname,
                 const char __user *newname);
    DEF_SYS_HOOK(symlinkat, const char __user *oldname,
                 int newdfd, const char __user *newname);

    // LINK Intents
    DEF_SYS_HOOK(link, const char __user *oldname, const char __user *newname);
    DEF_SYS_HOOK(linkat, int olddfd, const char __user *oldname,
                 int newdfd, const char __user *newname, int flags);

    // TODO: Handle Chmod and Chown Intents when kprobes fail to load

#undef DEF_SYS_HOOK
};

static struct syscall_hooks *orig;
static struct syscall_hooks *ours;

static struct syscall_hooks in_kernel;
static struct syscall_hooks in_our_kmod;

// Mask of LSM hooks requesting PreActions
static uint64_t preaction_hooks_enabled;

static DEFINE_MUTEX(lookup_lock);
static void **sys_call_table;
#if CONFIG_X86_64
static void **ia32_sys_call_table;
#endif

// PreAction hooks we can support via kprobe
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
static void dynsec_do_setattr(struct iattr *iattr, const struct path *path)
{
    struct dynsec_event *event = NULL;
    uint16_t report_flags = DYNSEC_REPORT_AUDIT|DYNSEC_REPORT_INTENT;

    if (task_in_connected_tgid(current)) {
        report_flags |= DYNSEC_REPORT_SELF;
    }

    // check if connected client is interested in this
    // file system type
    if (path->dentry && !__is_client_concerned_filesystem(path->dentry->d_sb)) {
        prepare_non_report_event(DYNSEC_EVENT_TYPE_SETATTR, GFP_ATOMIC);
        return;
    }

    event = alloc_dynsec_event(DYNSEC_EVENT_TYPE_SETATTR, DYNSEC_HOOK_TYPE_SETATTR,
                               report_flags, GFP_ATOMIC);

    if (!fill_in_preaction_setattr(event, iattr, (struct path *)path)) {
        prepare_non_report_event(DYNSEC_EVENT_TYPE_SETATTR, GFP_ATOMIC);
        free_dynsec_event(event);
        return;
    }
    prepare_dynsec_event(event, GFP_ATOMIC);
    enqueue_nonstall_event(stall_tbl, event);
}

static int dynsec_chmod_common(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct iattr iattr;
    DECL_ARG_1(const struct path *, path);
    DECL_ARG_2(umode_t, mode);

    if (!hooks_enabled(stall_tbl)) {
        goto out;
    }
    if (!path || !path->dentry || !path->mnt) {
        goto out;
    }

    // check if connected client is interested in this
    if (path->dentry && !__is_client_concerned_filesystem(path->dentry->d_sb)) {
        prepare_non_report_event(DYNSEC_EVENT_TYPE_SETATTR, GFP_ATOMIC);
        goto out;
    }

    memset(&iattr, 0, sizeof(iattr));
    if (path->dentry && path->dentry->d_inode) {
        umode_t umode = path->dentry->d_inode->i_mode;
        if ((umode & (~S_IFMT)) != mode) {
            iattr.ia_valid |= ATTR_MODE;
            iattr.ia_mode = mode;
            iattr.ia_mode |= (S_IFMT & umode);
            dynsec_do_setattr(&iattr, path);
            goto out;
        }
    }
    prepare_non_report_event(DYNSEC_EVENT_TYPE_SETATTR, GFP_ATOMIC);

out:
    return 0;
}

static int dynsec_chown_common(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct iattr iattr;
    DECL_ARG_1(const struct path *, path);
    DECL_ARG_2(uid_t, user);
    DECL_ARG_3(gid_t, group);

    if (!hooks_enabled(stall_tbl)) {
        goto out;
    }
    if (!path || !path->dentry || !path->mnt) {
        goto out;
    }

    // check if connected client is interested in this
    if (!__is_client_concerned_filesystem(path->dentry->d_sb)) {
        prepare_non_report_event(DYNSEC_EVENT_TYPE_SETATTR, GFP_ATOMIC);
        goto out;
    }

    memset(&iattr, 0, sizeof(iattr));
    if (user != -1) {
        iattr.ia_valid |= ATTR_UID;
        iattr.ia_uid = make_kuid(current_user_ns(), user);
        if (!uid_valid(iattr.ia_uid)) {
            iattr.ia_uid = KUIDT_INIT(user);
        }
        // Does not handle mnt_userns id mapping
        if (path->dentry && path->dentry->d_inode &&
            uid_eq(path->dentry->d_inode->i_uid, iattr.ia_uid)) {
            iattr.ia_valid &= ~(ATTR_UID);
        }
    }
    if (group != -1) {
        iattr.ia_valid |= ATTR_GID;
        iattr.ia_gid = make_kgid(current_user_ns(), group);
        if (!gid_valid(iattr.ia_gid)) {
            iattr.ia_gid = KGIDT_INIT(group);
        }
        // Does not handle mnt_userns id mapping
        if (path->dentry && path->dentry->d_inode &&
            gid_eq(path->dentry->d_inode->i_gid, iattr.ia_gid)) {
            iattr.ia_valid &= ~(ATTR_GID);
        }
    }
    // Only set ATTR_FILE
    if (iattr.ia_valid) {
        dynsec_do_setattr(&iattr, path);
    } else {
        prepare_non_report_event(DYNSEC_EVENT_TYPE_SETATTR, GFP_ATOMIC);
    }

out:
    return 0;
}

static int ret_setattr(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    return 0;
}

static bool enabled_chmod_common;
static struct kretprobe kret_dynsec_chmod_common = {
    .kp.symbol_name = "chmod_common",
    .handler = ret_setattr,
    .entry_handler = dynsec_chmod_common,
    .data_size = 0,
    .maxactive = 40,
};

static bool enabled_chown_common;
static struct kretprobe kret_dynsec_chown_common = {
    .kp.symbol_name = "chown_common",
    .handler = ret_setattr,
    .entry_handler = dynsec_chown_common,
    .data_size = 0,
    .maxactive = 40,
};

#else
// Would have to rely on syscalls or syscall tracepoints
#endif


// Call with lock held
static void restore_syscalls(void);
static int syscall_changed(const struct syscall_hooks *old_hooks,
                           bool *entire_tbl_chg);
static bool may_restore_syscalls(void)
{
    bool entire_tbl_chg = false;
    int diff;

    if (!ours || !orig || !sys_call_table) {
        return true;
    }

    diff = syscall_changed(ours, &entire_tbl_chg);
    if (entire_tbl_chg == false && diff == 0) {
        return true;
    }
    pr_info("%sentire_tbl_chg:%d diff:%d\n", __func__,
            entire_tbl_chg, diff);
    return false;
}

// Stubbed to potentially handle further redirection
#define select_hook() (&in_kernel)
#ifdef USE_PT_REGS
#define DEF_DYNSEC_SYS(NAME, ...) static asmlinkage long dynsec_##NAME(struct pt_regs *regs)
#define ret_sys(NAME, ...) select_hook()->NAME(regs)
#else
#define DEF_DYNSEC_SYS(NAME, ...) static asmlinkage long dynsec_##NAME(__VA_ARGS__)
#define ret_sys(NAME, ...) select_hook()->NAME(__VA_ARGS__)
#endif

#ifdef USE_PT_REGS
#define SYS_ARG_1(...) DECL_ARG_1(__VA_ARGS__)
#define SYS_ARG_2(...) DECL_ARG_2(__VA_ARGS__)
#define SYS_ARG_3(...) DECL_ARG_3(__VA_ARGS__)
#define SYS_ARG_4(...) OUR_DECL(__VA_ARGS__)regs->r10
#define SYS_ARG_5(...) DECL_ARG_5(__VA_ARGS__)
#define SYS_ARG_6(...) DECL_ARG_6(__VA_ARGS__)
#else
#define SYS_ARG_1(...) ;
#define SYS_ARG_2(...) ;
#define SYS_ARG_3(...) ;
#define SYS_ARG_4(...) ;
#define SYS_ARG_5(...) ;
#define SYS_ARG_6(...) ;
#endif

DEF_DYNSEC_SYS(delete_module, const char __user *name_user, unsigned int flags)
{
    char name_kernel[MODULE_NAME_LEN];
    int ref_count;
    int ret;
    bool restored = false;
    SYS_ARG_1(const char __user *, name_user);
    SYS_ARG_2(unsigned int, flags);

    if (!capable(CAP_SYS_MODULE)) {
        // Allow event to audit
        goto out;
    }

    ret = strncpy_from_user(name_kernel, name_user, MODULE_NAME_LEN-1);
    if (ret < 0) {
        return -EFAULT;
    }
    name_kernel[MODULE_NAME_LEN - 1] = 0;

    if (strncmp(name_kernel, THIS_MODULE->name, MODULE_NAME_LEN) != 0) {
        goto out;
    }

    ref_count = module_refcount(THIS_MODULE);
    // Already unloading
    if (ref_count < 0) {
        return -EWOULDBLOCK;
    }

    // Client connected or some other kmod refcounted us
    if (ref_count > 0) {
        return -EWOULDBLOCK;
    }

    if (check_lsm_hooks_changed() != 0) {
        // If we wanted to check syscall hooks to be verbose
        // mutex_lock(&lookup_lock);
        // (void)may_restore_syscalls();
        // mutex_unlock(&lookup_lock);
        return -EWOULDBLOCK;
    }

    mutex_lock(&lookup_lock);
    if (may_restore_syscalls()) {
        restored = true;
        restore_syscalls();
    }
    mutex_unlock(&lookup_lock);

    // Should we return -EBUSY or -EWOULDBLOCK?
    if (restored) {
        return -EBUSY;
    }

out:
    return ret_sys(delete_module, name_user, flags);
}


static void dynsec_do_create(int dfd, const char __user *filename,
                             int flags, umode_t umode)
{
    int ret;
    struct path path;
    struct dynsec_event *event = NULL;
    uint16_t report_flags = DYNSEC_REPORT_AUDIT|DYNSEC_REPORT_INTENT;
    int lookup_flags = LOOKUP_FOLLOW;

    if (!hooks_enabled(stall_tbl)) {
        return;
    }

    // Hook is specifically for CREATE events
    // Worry about other open flags in security_file_open.
    if ((flags & O_CREAT) != O_CREAT ||
#ifdef O_PATH
        (flags & O_PATH) ||
#endif
        (flags & O_DIRECTORY)) {
        return;
    }
    if ((flags & O_NOFOLLOW) == O_NOFOLLOW) {
        lookup_flags &= ~(LOOKUP_FOLLOW);
    }

    if (task_in_connected_tgid(current)) {
        report_flags |= DYNSEC_REPORT_SELF;
    }

    ret = user_path_at(dfd, filename, lookup_flags, &path);
    if (!ret) {
        path_put(&path);
        return;
    }
    if (ret != -ENOENT) {
        return;
    }

    event = alloc_dynsec_event(DYNSEC_EVENT_TYPE_CREATE, DYNSEC_HOOK_TYPE_OPEN,
                               report_flags, GFP_KERNEL);

    if (!fill_in_preaction_create(event, dfd, filename, flags, umode | S_IFREG)) {
        prepare_non_report_event(DYNSEC_EVENT_TYPE_CREATE, GFP_KERNEL);
        free_dynsec_event(event);
        return;
    }
    prepare_dynsec_event(event, GFP_KERNEL);
    enqueue_nonstall_event(stall_tbl, event);

    return;
}
DEF_DYNSEC_SYS(open, const char __user *filename, int flags, umode_t mode)
{
    SYS_ARG_1(const char __user *, filename);
    SYS_ARG_2(int, flags);
    SYS_ARG_3(umode_t, mode);

    dynsec_do_create(AT_FDCWD, filename, flags, mode);

    return ret_sys(open, filename, flags, mode);
}
DEF_DYNSEC_SYS(creat, const char __user *pathname, umode_t mode)
{
    SYS_ARG_1(const char __user *, pathname);
    SYS_ARG_2(umode_t, mode);

    dynsec_do_create(AT_FDCWD, pathname, O_CREAT, mode);

    return ret_sys(creat, pathname, mode);
}
DEF_DYNSEC_SYS(openat, int dfd, const char __user *filename,
               int flags, umode_t mode)
{
    SYS_ARG_1(int, dfd);
    SYS_ARG_2(const char __user *, filename);
    SYS_ARG_3(int, flags);
    SYS_ARG_4(umode_t, mode);

    dynsec_do_create(dfd, filename, flags, mode);

    return ret_sys(openat, dfd, filename, flags, mode);
}
#ifdef __NR_openat2
DEF_DYNSEC_SYS(openat2, int dfd, const char __user *filename,
               struct open_how __user *how, size_t usize)
{
    struct open_how khow;
    SYS_ARG_1(int, dfd);
    SYS_ARG_2(const char __user *, filename);
    SYS_ARG_3(int, flags);
    SYS_ARG_4(struct open_how __user *, how);
    SYS_ARG_5(size_t, usize);
    // copy in how

    if (!copy_from_user(&khow, how, sizeof(khow))) {
        dynsec_do_create(dfd, filename, khow.flags, khow.mode);
    }

    return ret_sys(openat2, dfd, filename, how, usize);
}
#endif /* __NR_openat2 */

DEF_DYNSEC_SYS(mknod, const char __user *filename,
               umode_t mode, unsigned dev)
{
    umode_t local_mode;
    SYS_ARG_1(const char __user *, filename);
    SYS_ARG_2(umode_t, mode);
    SYS_ARG_3(unsigned, dev);

    // Empty file type defaults to regular file
    local_mode = mode;
    if (!(local_mode & S_IFMT)) {
        local_mode |= S_IFREG;
    }
    if (S_ISREG(local_mode)) {
        dynsec_do_create(AT_FDCWD, filename, O_CREAT, local_mode);
    }
    return ret_sys(mknod, filename, mode, dev);
}

DEF_DYNSEC_SYS(mknodat, int dfd, const char __user *filename,
               umode_t mode, unsigned dev)
{
    umode_t local_mode;
    SYS_ARG_1(int, dfd);
    SYS_ARG_2(const char __user *, filename);
    SYS_ARG_3(umode_t, mode);
    SYS_ARG_4(unsigned, dev);

    // Empty file type defaults to regular file
    local_mode = mode;
    if (!(local_mode & S_IFMT)) {
        local_mode |= S_IFREG;
    }
    if (S_ISREG(local_mode)) {
        dynsec_do_create(dfd, filename, O_CREAT, local_mode);
    }
    return ret_sys(mknodat, dfd, filename, mode, dev);
}

static void dynsec_do_rename_post(bool has_intent, uint64_t intent_req_id,
                                  unsigned long rc)
{
    struct dynsec_event *event = NULL;
    uint16_t report_flags = (DYNSEC_REPORT_AUDIT
        | DYNSEC_REPORT_POST
        | DYNSEC_REPORT_HI_PRI // tells to wakeup polling client immediate
    );

    if (has_intent) {
        report_flags |= DYNSEC_REPORT_INTENT_FOUND;
    }

    switch (rc) {
    case 0:
        break;
    // Operation was denied somewhere
    case -EACCES:
    case -EPERM:
        report_flags |= DYNSEC_REPORT_DENIED;
        break;
    // Operation failed
    default:
        report_flags |= DYNSEC_REPORT_FAIL;
        break;
    }
    event = alloc_dynsec_event(DYNSEC_EVENT_TYPE_RENAME, DYNSEC_HOOK_TYPE_RENAME,
                               report_flags, GFP_KERNEL);
    if (event) {
        struct dynsec_rename_event *rename_event = dynsec_event_to_rename(event);

        if (has_intent) {
            // The header that's really transferred over
            rename_event->kmsg.hdr.intent_req_id = intent_req_id;
            // Setting more for event queue metadata
            event->intent_req_id = intent_req_id;
        }

        (void)enqueue_nonstall_event(stall_tbl, event);
    }
}

static bool dynsec_do_rename(int olddfd, const char __user *oldname,
                             int newdfd, const char __user *newname,
                             uint64_t *intent_req_id)
{
    struct dynsec_event *event = NULL;
    uint16_t report_flags = DYNSEC_REPORT_AUDIT|DYNSEC_REPORT_INTENT;
    uint64_t local_intent_req_id = 0;
    bool filled;

    if (!hooks_enabled(stall_tbl)) {
        return false;
    }

    if (task_in_connected_tgid(current)) {
        report_flags |= DYNSEC_REPORT_SELF;
    }

    event = alloc_dynsec_event(DYNSEC_EVENT_TYPE_RENAME, DYNSEC_HOOK_TYPE_RENAME,
                               report_flags, GFP_KERNEL);

    filled = fill_in_preaction_rename(event, olddfd, oldname,
                                      newdfd, newname);
    if (!filled) {
        prepare_non_report_event(DYNSEC_EVENT_TYPE_RENAME, GFP_KERNEL);
        free_dynsec_event(event);
        return false;
    }
    prepare_dynsec_event(event, GFP_KERNEL);
    local_intent_req_id = event->req_id;
    if (enqueue_nonstall_event(stall_tbl, event)) {
        if (intent_req_id) {
            *intent_req_id = local_intent_req_id;
        }
        return true;
    }
    return false;
}
DEF_DYNSEC_SYS(rename, const char __user *oldname, const char __user *newname)
{
    bool did_preaction;
    unsigned long ret;
    uint64_t intent_req_id = 0;
    SYS_ARG_1(const char __user *, oldname);
    SYS_ARG_2(const char __user *, newname);

    did_preaction = dynsec_do_rename(AT_FDCWD, oldname, AT_FDCWD, newname,
                                     &intent_req_id);
    ret = ret_sys(rename, oldname, newname);
    dynsec_do_rename_post(did_preaction, intent_req_id, ret);

    return ret;
}
#ifdef __NR_renameat
DEF_DYNSEC_SYS(renameat, int olddfd, const char __user *oldname,
               int newdfd, const char __user *newname)
{
    bool did_preaction;
    unsigned long ret;
    uint64_t intent_req_id = 0;
    SYS_ARG_1(int, olddfd);
    SYS_ARG_2(const char __user *, oldname);
    SYS_ARG_3(int, newdfd);
    SYS_ARG_4(const char __user *, newname);

    did_preaction = dynsec_do_rename(olddfd, oldname, newdfd, newname,
                                     &intent_req_id);
    ret = ret_sys(renameat, olddfd, oldname, newdfd, newname);
    dynsec_do_rename_post(did_preaction, intent_req_id, ret);

    return ret;
}
#endif /* __NR_renameat */
#ifdef __NR_renameat2
DEF_DYNSEC_SYS(renameat2, int olddfd, const char __user *oldname,
               int newdfd, const char __user *newname, unsigned int flags)
{
    bool did_preaction;
    unsigned long ret;
    uint64_t intent_req_id = 0;
    SYS_ARG_1(int, olddfd);
    SYS_ARG_2(const char __user *, oldname);
    SYS_ARG_3(int, newdfd);
    SYS_ARG_4(const char __user *, newname);
    SYS_ARG_5(unsigned int, flags);

    did_preaction = dynsec_do_rename(olddfd, oldname, newdfd, newname,
                                     &intent_req_id);
    ret = ret_sys(renameat2, olddfd, oldname, newdfd, newname, flags);
    dynsec_do_rename_post(did_preaction, intent_req_id, ret);

    return ret;
}
#endif /* __NR_renameat2 */


static void dynsec_do_mkdir(int dfd, const char __user *pathname, umode_t umode)
{
    int ret;
    struct path path;
    struct dynsec_event *event = NULL;
    uint16_t report_flags = DYNSEC_REPORT_AUDIT|DYNSEC_REPORT_INTENT;

    if (!hooks_enabled(stall_tbl)) {
        return;
    }

    ret = user_path_at(dfd, pathname, LOOKUP_DIRECTORY, &path);
    if (!ret) {
        path_put(&path);
        return;
    }
    if (ret != -ENOENT) {
        return;
    }

    if (task_in_connected_tgid(current)) {
        report_flags |= DYNSEC_REPORT_SELF;
    }

    event = alloc_dynsec_event(DYNSEC_EVENT_TYPE_MKDIR, DYNSEC_HOOK_TYPE_MKDIR,
                               report_flags, GFP_KERNEL);
    if (!fill_in_preaction_create(event, dfd, pathname, O_CREAT, umode | S_IFDIR)) {
        prepare_non_report_event(DYNSEC_EVENT_TYPE_MKDIR, GFP_KERNEL);
        free_dynsec_event(event);
        return;
    }
    prepare_dynsec_event(event, GFP_KERNEL);
    enqueue_nonstall_event(stall_tbl, event);
}
DEF_DYNSEC_SYS(mkdir, const char __user *pathname, umode_t mode)
{
    SYS_ARG_1(const char __user *, pathname);
    SYS_ARG_2(umode_t, mode);

    dynsec_do_mkdir(AT_FDCWD, pathname, mode);
    return ret_sys(mkdir, pathname, mode);
}
DEF_DYNSEC_SYS(mkdirat, int dfd, const char __user *pathname, umode_t mode)
{
    SYS_ARG_1(int, dfd);
    SYS_ARG_2(const char __user *, pathname);
    SYS_ARG_3(umode_t, mode);

    dynsec_do_mkdir(dfd, pathname, mode);

    return ret_sys(mkdirat, dfd, pathname, mode);
}

static void dynsec_do_unlink(int dfd, const char __user *pathname,
                             int flag, uint32_t hook_type)
{
    int ret;
    struct path path;
    struct dynsec_event *event = NULL;
    uint16_t report_flags = DYNSEC_REPORT_AUDIT|DYNSEC_REPORT_INTENT;
    enum dynsec_event_type event_type = DYNSEC_EVENT_TYPE_UNLINK;
    bool filled;
    umode_t mode;

    if (!hooks_enabled(stall_tbl)) {
        return;
    }

    ret = user_path_at(dfd, pathname, 0, &path);
    if (ret) {
        return;
    }

    if (!path.dentry && !path.dentry->d_inode) {
        path_put(&path);
        return;
    }

    // On RMDIR only allow directory
    mode = path.dentry->d_inode->i_mode;
    if ((flag & AT_REMOVEDIR) && !S_ISDIR(mode)) {
        path_put(&path);
        return;
    }
    else if (!(S_ISLNK(mode) || S_ISREG(mode) || S_ISDIR(mode))) {
        path_put(&path);
        return;
    }

    // check if connected client is interested in this
    // file system type
    if (!__is_client_concerned_filesystem(path.dentry->d_sb)) {
        path_put(&path);
        prepare_non_report_event(DYNSEC_EVENT_TYPE_UNLINK, GFP_KERNEL);
        return;
    }

    if (flag & AT_REMOVEDIR) {
        event_type = DYNSEC_EVENT_TYPE_RMDIR;
    }

    if (task_in_connected_tgid(current)) {
        report_flags |= DYNSEC_REPORT_SELF;
    }

    event = alloc_dynsec_event(event_type,hook_type, report_flags,
                               GFP_KERNEL);
    filled = fill_in_preaction_unlink(event, &path, GFP_KERNEL);
    path_put(&path);
    if (!filled) {
        prepare_non_report_event(DYNSEC_EVENT_TYPE_UNLINK, GFP_KERNEL);
        free_dynsec_event(event);
        return;
    }
    prepare_dynsec_event(event, GFP_KERNEL);
    enqueue_nonstall_event(stall_tbl, event);
}
DEF_DYNSEC_SYS(unlink, const char __user *pathname)
{
    SYS_ARG_1(const char __user *, pathname);

    dynsec_do_unlink(AT_FDCWD, pathname, 0, DYNSEC_HOOK_TYPE_UNLINK);
    return ret_sys(unlink, pathname);
}
DEF_DYNSEC_SYS(unlinkat, int dfd, const char __user *pathname,
                                       int flag)
{
    SYS_ARG_1(int, dfd);
    SYS_ARG_2(const char __user *, pathname);
    SYS_ARG_3(int, flag);

    dynsec_do_unlink(dfd, pathname, flag, DYNSEC_HOOK_TYPE_UNLINK);
    return ret_sys(unlinkat, dfd, pathname, flag);
}
DEF_DYNSEC_SYS(rmdir, const char __user *pathname)
{
    SYS_ARG_1(const char __user *, pathname);

    dynsec_do_unlink(AT_FDCWD, pathname, AT_REMOVEDIR, DYNSEC_HOOK_TYPE_RMDIR);
    return ret_sys(rmdir, pathname);
}

static void dynsec_do_symlink(const char __user *target,
                              int newdfd, const char __user *linkpath)
{
    int ret;
    long len;
    struct path path;
    struct dynsec_event *event = NULL;
    uint16_t report_flags = DYNSEC_REPORT_AUDIT|DYNSEC_REPORT_INTENT;
    char *target_path = NULL;
    bool filled;

    if (!hooks_enabled(stall_tbl)) {
        return;
    }

    target_path = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!target_path) {
        return;
    }

    ret = user_path_at(newdfd, linkpath, 0, &path);
    if (!ret) {
        path_put(&path);
        kfree(target_path);
        target_path = NULL;
        return;
    }
    len = strncpy_from_user(target_path, target, PATH_MAX);
    if (unlikely(len <= 0)) {
        kfree(target_path);
        target_path = NULL;
        return;
    }
    if (unlikely(len >= PATH_MAX)) {
        kfree(target_path);
        target_path = NULL;
        return;
    }
    if (len == 0) {
        target_path[len] = 0;
    }

    if (task_in_connected_tgid(current)) {
        report_flags |= DYNSEC_REPORT_SELF;
    }
    event = alloc_dynsec_event(DYNSEC_EVENT_TYPE_SYMLINK,
                               DYNSEC_HOOK_TYPE_SYMLINK,
                               report_flags, GFP_KERNEL);
    filled = fill_in_preaction_symlink(event, target_path, newdfd, linkpath);
    kfree(target_path);
    target_path = NULL;
    if (!filled) {
        prepare_non_report_event(DYNSEC_EVENT_TYPE_SYMLINK, GFP_KERNEL);
        free_dynsec_event(event);
        return;
    }
    prepare_dynsec_event(event, GFP_KERNEL);
    enqueue_nonstall_event(stall_tbl, event);
}
DEF_DYNSEC_SYS(symlink, const char __user *target, const char __user *linkpath)
{
    SYS_ARG_1(const char __user *, target);
    SYS_ARG_2(const char __user *, linkpath);

    dynsec_do_symlink(target, AT_FDCWD, linkpath);
    return ret_sys(symlink, target, linkpath);
}
DEF_DYNSEC_SYS(symlinkat, const char __user *target,
               int newdfd, const char __user *linkpath)
{
    SYS_ARG_1(const char __user *, target);
    SYS_ARG_2(int, newdfd);
    SYS_ARG_3(const char __user *, linkpath);

    dynsec_do_symlink(target, AT_FDCWD, linkpath);
    return ret_sys(symlinkat, target, newdfd, linkpath);
}

static void dynsec_do_link(int olddfd, const char __user *oldname,
                           int newdfd, const char __user *newname,
                           int flags)
{
    int ret;
    struct path oldpath;
    struct path newpath;
    struct dynsec_event *event = NULL;
    uint16_t report_flags = DYNSEC_REPORT_AUDIT|DYNSEC_REPORT_INTENT;
    umode_t mode;
    bool filled;
    int lookup_flags = 0;

    if (!hooks_enabled(stall_tbl)) {
        return;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
    if ((flags & ~(AT_SYMLINK_FOLLOW | AT_EMPTY_PATH)) != 0) {
        return;
    }
    if (flags & AT_EMPTY_PATH) {
        // Do we really want to trigger a capability check?
        if (!capable(CAP_DAC_READ_SEARCH)) {
            return;
        }
        lookup_flags |= LOOKUP_EMPTY;
    }
#endif

    if (flags & AT_SYMLINK_FOLLOW) {
        lookup_flags |= LOOKUP_FOLLOW;
    }

    // Old path must exist
    ret = user_path_at(olddfd, oldname, lookup_flags, &oldpath);
    if (ret) {
        return;
    }

    // New path must not exist
    ret = user_path_at(newdfd, newname, lookup_flags, &newpath);
    if (!ret) {
        path_put(&oldpath);
        path_put(&newpath);
        return;
    }

    if (!oldpath.dentry && !oldpath.dentry->d_inode) {
        path_put(&oldpath);
        return;
    }
    mode = oldpath.dentry->d_inode->i_mode;
    if (!(S_ISLNK(mode) || S_ISREG(mode) || S_ISDIR(mode))) {
        path_put(&oldpath);
        return;
    }

    if (task_in_connected_tgid(current)) {
        report_flags |= DYNSEC_REPORT_SELF;
    }

    event = alloc_dynsec_event(DYNSEC_EVENT_TYPE_LINK, DYNSEC_HOOK_TYPE_LINK,
                               report_flags, GFP_KERNEL);

    filled = fill_in_preaction_link(event, &oldpath, newdfd, newname);
    path_put(&oldpath);
    if (!filled) {
        prepare_non_report_event(DYNSEC_EVENT_TYPE_LINK, GFP_KERNEL);
        free_dynsec_event(event);
        return;
    }
    prepare_dynsec_event(event, GFP_KERNEL);
    enqueue_nonstall_event(stall_tbl, event);
}
DEF_DYNSEC_SYS(link, const char __user *oldname, const char __user *newname)
{
    SYS_ARG_1(const char __user *, oldname);
    SYS_ARG_2(const char __user *, newname);

    dynsec_do_link(AT_FDCWD, oldname, AT_FDCWD, newname, 0);
    return ret_sys(link, oldname, newname);
}
DEF_DYNSEC_SYS(linkat, int olddfd, const char __user *oldname,
               int newdfd, const char __user *newname, int flags)
{
    SYS_ARG_1(int, olddfd);
    SYS_ARG_2(const char __user *, oldname);
    SYS_ARG_3(int, newdfd);
    SYS_ARG_4(const char __user *, newname);
    SYS_ARG_5(int, flags);

    dynsec_do_link(AT_FDCWD, oldname, AT_FDCWD, newname, flags);

    return ret_sys(linkat, olddfd, oldname, newdfd, newname, flags);
}

// On success unlock lookup_lock
static void get_syscall_tbl(void)
{
    sys_call_table = NULL;
    find_symbol_indirect("sys_call_table", (unsigned long *)&sys_call_table);

    ia32_sys_call_table = NULL;
    // Only get 32bit table if we can get the main tbl
    find_symbol_indirect("ia32_sys_call_table",
                         (unsigned long *)&ia32_sys_call_table);
}

static void get_syscall_hooks(void **table, struct syscall_hooks *hooks)
{
    if (hooks) {
        memset(hooks, 0, sizeof(*hooks));
    }

    if (!table || !hooks) {
        return;
    }

#define copy_syscall(NAME) \
    hooks->NAME = sys_call_table[__NR_##NAME]

    copy_syscall(delete_module);
    copy_syscall(open);
    copy_syscall(creat);
    copy_syscall(openat);
#ifdef __NR_openat2
    copy_syscall(openat2);
#endif /* __NR_openat2 */
    copy_syscall(mknod);
    copy_syscall(mknodat);
    copy_syscall(rename);
#ifdef __NR_renameat
    copy_syscall(renameat);
#endif /* __NR_renameat */
#ifdef __NR_renameat2
    copy_syscall(renameat2);
#endif /* __NR_renameat2 */
    copy_syscall(mkdir);
    copy_syscall(mkdirat);
    copy_syscall(unlink);
    copy_syscall(unlinkat);
    copy_syscall(rmdir);
    copy_syscall(symlink);
    copy_syscall(symlinkat);
    copy_syscall(link);
    copy_syscall(linkat);

#undef copy_syscall

    return;
}


static void init_our_syscall_hooks(uint64_t lsm_hooks)
{
    memset(&in_our_kmod, 0, sizeof(in_our_kmod));

    if (!lsm_hooks) {
        return;
    }

#define copy_hook(NAME) \
    in_our_kmod.NAME = dynsec_##NAME


#define cond_copy_hook(NAME, MASK) \
    do { \
        copy_hook(NAME); \
        if (lsm_hooks & (MASK)) { \
            preaction_hooks_enabled |= (MASK); \
        } \
    } while (0)

    copy_hook(delete_module);

    cond_copy_hook(open, DYNSEC_HOOK_TYPE_CREATE);
    cond_copy_hook(creat, DYNSEC_HOOK_TYPE_CREATE);
    cond_copy_hook(openat, DYNSEC_HOOK_TYPE_CREATE);
#ifdef __NR_openat2
    cond_copy_hook(openat2, DYNSEC_HOOK_TYPE_CREATE);
#endif /* __NR_openat2 */
    cond_copy_hook(mknod, DYNSEC_HOOK_TYPE_CREATE);
    cond_copy_hook(mknodat, DYNSEC_HOOK_TYPE_CREATE);

    cond_copy_hook(rename, DYNSEC_HOOK_TYPE_RENAME);
#ifdef __NR_renameat
    cond_copy_hook(renameat, DYNSEC_HOOK_TYPE_RENAME);
#endif /* __NR_renameat */
#ifdef __NR_renameat2
    cond_copy_hook(renameat2, DYNSEC_HOOK_TYPE_RENAME);
#endif /* __NR_renameat2 */

    cond_copy_hook(mkdir, DYNSEC_HOOK_TYPE_MKDIR);
    cond_copy_hook(mkdirat, DYNSEC_HOOK_TYPE_MKDIR);

    cond_copy_hook(unlink, DYNSEC_HOOK_TYPE_UNLINK);
    cond_copy_hook(unlinkat, DYNSEC_HOOK_TYPE_UNLINK|DYNSEC_HOOK_TYPE_RMDIR);
    cond_copy_hook(rmdir, DYNSEC_HOOK_TYPE_RMDIR);

    cond_copy_hook(symlink, DYNSEC_HOOK_TYPE_SYMLINK);
    cond_copy_hook(symlinkat, DYNSEC_HOOK_TYPE_SYMLINK);

    cond_copy_hook(link, DYNSEC_HOOK_TYPE_LINK);
    cond_copy_hook(linkat, DYNSEC_HOOK_TYPE_LINK);

#undef cond_copy_hook
#undef copy_syscall

    pr_info("preaction_hooks_enabled: %#018llx\n", preaction_hooks_enabled);

    ours = &in_our_kmod;
}

static void __set_syscall_table(struct syscall_hooks *hooks, void **table)
{
    unsigned long flags;
    static unsigned long page_rw_set;

#define set_syscall(NAME) \
    do { \
        if (hooks->NAME) { \
            table[__NR_##NAME] = hooks->NAME; \
        } \
    } while (0)

#define cond_set_syscall(NAME, MASK) \
    do { \
        if (hooks->NAME && (preaction_hooks_enabled & (MASK))) { \
            table[__NR_##NAME] = hooks->NAME; \
        } \
    } while (0)

    local_irq_save(flags);
    local_irq_disable();
    get_cpu();
    GPF_DISABLE();

    if (!set_page_state_rw((void *)table, &page_rw_set)) {
        goto out_unlock;
    }

    set_syscall(delete_module);

    // Always copy this when CONFIG_SECURITY_PATH disabled
    cond_set_syscall(open, DYNSEC_HOOK_TYPE_CREATE);
    cond_set_syscall(creat, DYNSEC_HOOK_TYPE_CREATE);
    cond_set_syscall(openat, DYNSEC_HOOK_TYPE_CREATE);
#ifdef __NR_openat2
    cond_set_syscall(openat2, DYNSEC_HOOK_TYPE_CREATE);
#endif /* __NR_openat2 */
    cond_set_syscall(mknod, DYNSEC_HOOK_TYPE_CREATE);
    cond_set_syscall(mknodat, DYNSEC_HOOK_TYPE_CREATE);

    cond_set_syscall(rename, DYNSEC_HOOK_TYPE_RENAME);
#ifdef __NR_renameat
    cond_set_syscall(renameat, DYNSEC_HOOK_TYPE_RENAME);
#endif /* __NR_renameat */
#ifdef __NR_renameat2
    cond_set_syscall(renameat2, DYNSEC_HOOK_TYPE_RENAME);
#endif /* __NR_renameat2 */

    cond_set_syscall(mkdir, DYNSEC_HOOK_TYPE_MKDIR);
    cond_set_syscall(mkdirat, DYNSEC_HOOK_TYPE_MKDIR);

    cond_set_syscall(unlink, DYNSEC_HOOK_TYPE_UNLINK);
    cond_set_syscall(unlinkat, DYNSEC_HOOK_TYPE_UNLINK|DYNSEC_HOOK_TYPE_RMDIR);
    cond_set_syscall(rmdir, DYNSEC_HOOK_TYPE_RMDIR);

    cond_set_syscall(symlink, DYNSEC_HOOK_TYPE_SYMLINK);
    cond_set_syscall(symlinkat, DYNSEC_HOOK_TYPE_SYMLINK);

    cond_set_syscall(link, DYNSEC_HOOK_TYPE_LINK);
    cond_set_syscall(linkat, DYNSEC_HOOK_TYPE_LINK);

#undef set_syscall
#undef cond_set_syscall

    restore_page_state((void *)table, page_rw_set);

out_unlock:
    GPF_ENABLE();
    put_cpu();
    local_irq_restore(flags);
}


static int syscall_changed(const struct syscall_hooks *old_hooks,
                           bool *entire_tbl_chg)
{
    int diff = 0;
    char modname[MODULE_NAME_LEN + 1];
    char old_modname[MODULE_NAME_LEN + 1];
    char *symname = NULL;
    char *old_symname = NULL;
    struct syscall_hooks *curr_hooks = NULL;
    void **curr_table = NULL;

    if (entire_tbl_chg) {
        *entire_tbl_chg = false;
    }

    if (!sys_call_table || !old_hooks) {
        return 0;
    }

    curr_hooks = kzalloc(sizeof(*curr_hooks), GFP_KERNEL);
    if (!curr_hooks) {
        return -ENOMEM;
    }

    // Don't assume existing sys_call_table addr is the same
    find_symbol_indirect("sys_call_table",
                         (unsigned long *)&curr_table);
    get_syscall_hooks(curr_table, curr_hooks);

    if (entire_tbl_chg) {
        *entire_tbl_chg = (curr_table != sys_call_table);
    }
    if (curr_table != sys_call_table) {
        diff += 1;
    }
    if (!curr_table) {
        kfree(curr_hooks);
        return diff;
    }

    symname = kzalloc(KSYM_NAME_LEN + 1, GFP_KERNEL);
    if (!symname) {
        kfree(curr_hooks);
        return -ENOMEM;
    }
    old_symname = kzalloc(KSYM_NAME_LEN + 1, GFP_KERNEL);
    if (!old_symname) {
        kfree(curr_hooks);
        kfree(symname);
        return -ENOMEM;
    }

#define __cmp_syscall(NAME, MASK, x) \
    do { \
        int __ret; \
        if (((preaction_hooks_enabled & (MASK)) || (x)) && \
            old_hooks->NAME != curr_hooks->NAME) { \
            diff += 1; \
            dynsec_module_name((unsigned long)curr_hooks->NAME, \
                               modname, MODULE_NAME_LEN); \
            if (symname) { \
                dynsec_lookup_symbol_name((unsigned long)curr_hooks->NAME, \
                                          symname); \
            } \
            __ret = dynsec_module_name((unsigned long)old_hooks->NAME, \
                               old_modname, MODULE_NAME_LEN); \
            if (__ret < 0) { \
                strcpy(old_modname, "kernel"); \
            } \
            if (old_symname) { \
                dynsec_lookup_symbol_name((unsigned long)old_hooks->NAME, \
                                          old_symname); \
            } \
            pr_info("syscall:" #NAME " change from %s::%s -> %s::%s\n", \
                    old_modname, old_symname, modname, symname); \
        } \
    } while (0)

#define cmp_syscall(NAME, MASK) \
    __cmp_syscall(NAME, MASK, 0)

    // No event mask for delete_module
    __cmp_syscall(delete_module, 0, 1);

    cmp_syscall(open, DYNSEC_HOOK_TYPE_CREATE);
    cmp_syscall(creat, DYNSEC_HOOK_TYPE_CREATE);
    cmp_syscall(openat, DYNSEC_HOOK_TYPE_CREATE);
#ifdef __NR_openat2
    cmp_syscall(openat2, DYNSEC_HOOK_TYPE_CREATE);
#endif /* __NR_openat2 */
    cmp_syscall(mknod, DYNSEC_HOOK_TYPE_CREATE);
    cmp_syscall(mknodat, DYNSEC_HOOK_TYPE_CREATE);

    cmp_syscall(rename, DYNSEC_HOOK_TYPE_RENAME);
#ifdef __NR_renameat
    cmp_syscall(renameat, DYNSEC_HOOK_TYPE_RENAME);
#endif /* __NR_renameat */
#ifdef __NR_renameat2
    cmp_syscall(renameat2, DYNSEC_HOOK_TYPE_RENAME);
#endif /* __NR_renameat2 */

    cmp_syscall(mkdir, DYNSEC_HOOK_TYPE_MKDIR);
    cmp_syscall(mkdirat, DYNSEC_HOOK_TYPE_MKDIR);

    cmp_syscall(unlink, DYNSEC_HOOK_TYPE_UNLINK);
    cmp_syscall(unlinkat, DYNSEC_HOOK_TYPE_UNLINK|DYNSEC_HOOK_TYPE_RMDIR);
    cmp_syscall(rmdir, DYNSEC_HOOK_TYPE_RMDIR);

    cmp_syscall(symlink, DYNSEC_HOOK_TYPE_SYMLINK);
    cmp_syscall(symlinkat, DYNSEC_HOOK_TYPE_SYMLINK);

    cmp_syscall(link, DYNSEC_HOOK_TYPE_LINK);
    cmp_syscall(linkat, DYNSEC_HOOK_TYPE_LINK);

#undef cmp_syscall
#undef __cmp_syscall

    kfree(curr_hooks);
    kfree(symname);
    kfree(old_symname);

    return diff;
}

static bool register_kprobe_hooks(uint64_t lsm_hooks)
{
    bool success = true;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
    enabled_chmod_common = false;
    enabled_chown_common = false;

    if (lsm_hooks & DYNSEC_HOOK_TYPE_SETATTR) {
        int ret = register_kretprobe(&kret_dynsec_chmod_common);
        if (ret >= 0) {
            enabled_chmod_common = true;
        } else {
            pr_err("Unable to hook kretprobe: %d %s\n", ret,
                    kret_dynsec_chmod_common.kp.symbol_name);
            success = false;
        }

        ret = register_kretprobe(&kret_dynsec_chown_common);
        if (ret >= 0) {
            enabled_chown_common = true;
            preaction_hooks_enabled |= DYNSEC_HOOK_TYPE_SETATTR;
        } else {
            pr_err("Unable to hook kretprobe: %d %s\n", ret,
                    kret_dynsec_chown_common.kp.symbol_name);
            success = false;
        }
    }
#endif

    return success;
}

static void unregister_kprobe_hooks(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
    if (enabled_chmod_common) {
        enabled_chmod_common = false;
        unregister_kretprobe(&kret_dynsec_chmod_common);
    }

    if (enabled_chown_common) {
        enabled_chown_common = false;
        unregister_kretprobe(&kret_dynsec_chown_common);
    }
#endif
}

bool register_preaction_hooks(struct dynsec_config *dynsec_config)
{
    preaction_hooks_enabled = 0;
    orig = NULL;
    ours = NULL;
    sys_call_table = NULL;
    ia32_sys_call_table = NULL;

    if (!dynsec_config) {
        return true;
    }
    dynsec_config->preaction_hooks = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
    if (!dynsec_config->lsm_hooks) {
        return true;
    }
#endif

    mutex_lock(&lookup_lock);
    get_syscall_tbl();
    if (!sys_call_table) {
        pr_err("Failed to grab syscall hooks\n");
        mutex_unlock(&lookup_lock);
        return false;
    }

    get_syscall_hooks(sys_call_table, &in_kernel);
    orig = &in_kernel;
    // Enable syscall hooks based which LSM hooks are set
    init_our_syscall_hooks(dynsec_config->lsm_hooks);

    if (ours) {
        if (sys_call_table) {
            orig = &in_kernel;
            __set_syscall_table(ours, sys_call_table);
        }
        if (orig) {
            (void)syscall_changed(orig, NULL);
        }
    }
    register_kprobe_hooks(dynsec_config->lsm_hooks);
    mutex_unlock(&lookup_lock);
    dynsec_config->preaction_hooks = preaction_hooks_enabled;

    return true;
}

// Call with lock held
static void restore_syscalls(void)
{
    if (orig) {
        orig = NULL;
        if (sys_call_table) {
            __set_syscall_table(&in_kernel, sys_call_table);
            sys_call_table = NULL;
        }
    }
}

void preaction_hooks_shutdown(void)
{
    unregister_kprobe_hooks();
    mutex_lock(&lookup_lock);
    restore_syscalls();
    mutex_unlock(&lookup_lock);
}
