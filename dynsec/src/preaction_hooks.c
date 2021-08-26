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
#include "version.h"
#include "dynsec.h"
#include "lsm_mask.h"

#include "stall_tbl.h"
#include "stall_reqs.h"
#include "factory.h"


struct syscall_hooks {
#ifdef USE_PT_REGS
#define DEF_SYS_HOOK(NAME, ...) asmlinkage long (*NAME)(struct pt_regs *regs)
#else
#define DEF_SYS_HOOK(NAME, ...) asmlinkage long (*NAME)(__VA_ARGS__)
#endif
    DEF_SYS_HOOK(delete_module, const char __user *name_user,
                 unsigned int flags);
    DEF_SYS_HOOK(open, const char __user *filename, int flags, umode_t mode);
    DEF_SYS_HOOK(creat, const char __user *pathname, umode_t mode);
    DEF_SYS_HOOK(openat, int dfd, const char __user *filename, int flags,
                 umode_t mode);
#ifdef __NR_openat2
    DEF_SYS_HOOK(openat2, int dfd, const char __user *filename,
                 struct open_how __user * how, size_t usize);
#endif /* __NR_openat2 */

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

    DEF_SYS_HOOK(mkdir, const char __user *pathname, umode_t mode);
    DEF_SYS_HOOK(mkdirat, int dfd, const char __user *pathname, umode_t mode);

    DEF_SYS_HOOK(unlink, const char __user *pathname);
    DEF_SYS_HOOK(unlinkat, int dfd, const char __user *pathname, int flag);
    DEF_SYS_HOOK(rmdir, const char __user *pathname);

    DEF_SYS_HOOK(symlink, const char __user *oldname,
                 const char __user *newname);
    DEF_SYS_HOOK(symlinkat, const char __user *oldname,
                 int newdfd, const char __user *newname);

    DEF_SYS_HOOK(link, const char __user *oldname, const char __user *newname);
    DEF_SYS_HOOK(linkat, int olddfd, const char __user *oldname,
                 int newdfd, const char __user *newname, int flags);

#undef DEF_SYS_HOOK
};

static struct syscall_hooks *orig;
static struct syscall_hooks *ours;

static struct syscall_hooks in_kernel;
static struct syscall_hooks in_our_kmod;

// Mask of LSM hooks requesting PreActions
static uint64_t syscall_hooks_enabled;

static DEFINE_MUTEX(lookup_lock);
static void **sys_call_table;
static void **ia32_sys_call_table;


// PreAction hooks we can support via kprobe
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
int dynsec_chmod_common(struct kprobe *kprobe, struct pt_regs *regs)
{
    return 0;
}

int dynsec_chown_common(struct kprobe *kprobe, struct pt_regs *regs)
{
    return 0;
}

int dynsec_vfs_truncate(struct kprobe *kprobe, struct pt_regs *regs)
{
    return 0;
}
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
    pr_info("%s:%d entire_tbl_chg:%d diff:%d\n", __func__, __LINE__,
            entire_tbl_chg, diff);
    return (entire_tbl_chg == false && diff == 0);
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


DEF_DYNSEC_SYS(delete_module, const char __user *name_user, unsigned int flags)
{
#ifdef USE_PT_REGS
    DECL_ARG_1(const char __user *, name_user);
    DECL_ARG_2(unsigned int, flags);
#endif
    char name_kernel[MODULE_NAME_LEN];
    int ref_count;
    int ret;
    bool restored = false;

    if (!capable(CAP_SYS_MODULE)) {
        // Allow event to audit
        goto out;
    }

    ret = strncpy_from_user(name_kernel, name_user, MODULE_NAME_LEN-1);
    if (ret < 0) {
        return -EFAULT;
    }
    name_kernel[MODULE_NAME_LEN - 1] = 0;

    // THIS_MODULE->name should work instead of CB_APP_MODULE_NAME
    if (strncmp(name_kernel, CB_APP_MODULE_NAME, MODULE_NAME_LEN) != 0) {
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

    if (!stall_tbl_enabled(stall_tbl)) {
        return;
    }

    // Hook is specifically for CREATE events
    // Worry about other open flags in security_file_open.
    if (flags == O_RDONLY ||
        (flags & (O_PATH|O_DIRECTORY)) ||
        (flags & O_CREAT) != O_CREAT) {
        return;
    }
    if ((flags & O_NOFOLLOW) == O_NOFOLLOW) {
        lookup_flags &= ~(LOOKUP_FOLLOW);
    }

    ret = user_path_at(dfd, filename, flags, &path);
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

    event = alloc_dynsec_event(DYNSEC_EVENT_TYPE_CREATE, DYNSEC_HOOK_TYPE_OPEN,
                               report_flags, GFP_KERNEL);

    if (!fill_in_preaction_create(event, dfd, filename, flags, umode)) {
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
#ifdef USE_PT_REGS
    DECL_ARG_1(const char __user *, filename);
    DECL_ARG_2(int, flags);
    DECL_ARG_3(umode_t, mode);
#endif

    dynsec_do_create(AT_FDCWD, filename, flags, mode);

    return ret_sys(open, filename, flags, mode);
}
DEF_DYNSEC_SYS(creat, const char __user *pathname, umode_t mode)
{
#ifdef USE_PT_REGS
    DECL_ARG_1(const char __user *, pathname);
    DECL_ARG_2(umode_t, mode);
#endif

    dynsec_do_create(AT_FDCWD, pathname, O_CREAT, mode);

    return ret_sys(creat, pathname, mode);
}
DEF_DYNSEC_SYS(openat, int dfd, const char __user *filename,
               int flags, umode_t mode)
{
#ifdef USE_PT_REGS
    DECL_ARG_1(int, dfd);
    DECL_ARG_2(const char __user *, filename);
    DECL_ARG_3(int, flags);
    DECL_ARG_4(umode_t, mode);
#endif

    dynsec_do_create(dfd, filename, flags, mode);

    return ret_sys(openat, dfd, filename, flags, mode);
}
#ifdef __NR_openat2
DEF_DYNSEC_SYS(openat2, int dfd, const char __user *filename,
               struct open_how __user *how, size_t usize)
{
#ifdef USE_PT_REGS
    DECL_ARG_1(int, dfd);
    DECL_ARG_2(const char __user *, filename);
    DECL_ARG_3(int, flags);
    DECL_ARG_4(struct open_how __user *, how);
    DECL_ARG_5(umode_t, mode);
#endif
    // copy in how

    dynsec_do_create(dfd, filename, khow->flags, mode);

out:
    return ret_sys(openat2, dfd, filename, how, usize);
}
#endif /* __NR_openat2 */


DEF_DYNSEC_SYS(rename, const char __user *oldname, const char __user *newname)
{
    return ret_sys(rename, oldname, newname);
}
#ifdef __NR_renameat
DEF_DYNSEC_SYS(renameat, int olddfd, const char __user *oldname,
               int newdfd, const char __user *newname)
{
    return ret_sys(renameat, olddfd, oldname, newdfd, newname);
}
#endif /* __NR_renameat */
#ifdef __NR_renameat2
DEF_DYNSEC_SYS(renameat2, int olddfd, const char __user *oldname,
               int newdfd, const char __user *newname, unsigned int flags)
{
    return ret_sys(renameat2, olddfd, oldname, newdfd, newname, flags);
}
#endif /* __NR_renameat2 */


static void dynsec_do_mkdir(int dfd, const char __user *pathname, umode_t umode)
{
    int ret;
    struct path path;
    struct dynsec_event *event = NULL;
    uint16_t report_flags = DYNSEC_REPORT_AUDIT|DYNSEC_REPORT_INTENT;

    if (!stall_tbl_enabled(stall_tbl)) {
        return;
    }

    ret = user_path_at(dfd, pathname, LOOKUP_FOLLOW, &path);
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
    if (!fill_in_preaction_create(event, dfd, pathname, O_CREAT, umode)) {
        prepare_non_report_event(DYNSEC_EVENT_TYPE_MKDIR, GFP_KERNEL);
        free_dynsec_event(event);
        return;
    }
    prepare_dynsec_event(event, GFP_KERNEL);
    enqueue_nonstall_event(stall_tbl, event);
}
DEF_DYNSEC_SYS(mkdir, const char __user *pathname, umode_t mode)
{
#ifdef USE_PT_REGS
    DECL_ARG_1(const char __user *, pathname);
    DECL_ARG_2(umode_t, mode);
#endif /* USE_PT_REGS */

    dynsec_do_mkdir(AT_FDCWD, pathname, mode);
    return ret_sys(mkdir, pathname, mode);
}
DEF_DYNSEC_SYS(mkdirat, int dfd, const char __user *pathname, umode_t mode)
{
#ifdef USE_PT_REGS
    DECL_ARG_1(int, dfd);
    DECL_ARG_2(const char __user *, pathname);
    DECL_ARG_3(umode_t, mode);
#endif /* USE_PT_REGS */

    dynsec_do_mkdir(dfd, pathname, mode);

    return ret_sys(mkdirat, dfd, pathname, mode);
}


DEF_DYNSEC_SYS(unlink, const char __user *pathname)
{
    return ret_sys(unlink, pathname);
}
DEF_DYNSEC_SYS(unlinkat, int dfd, const char __user *pathname,
                                       int flag)
{
    return ret_sys(unlinkat, dfd, pathname, flag);
}
DEF_DYNSEC_SYS(rmdir, const char __user *pathname)
{
    return ret_sys(rmdir, pathname);
}


DEF_DYNSEC_SYS(symlink, const char __user *oldname, const char __user *newname)
{
    return ret_sys(symlink, oldname, newname);
}
DEF_DYNSEC_SYS(symlinkat, const char __user *oldname,
               int newdfd, const char __user *newname)
{
    return ret_sys(symlinkat, oldname, newdfd, newname);
}


DEF_DYNSEC_SYS(link, const char __user *oldname, const char __user *newname)
{
    return ret_sys(link, oldname, newname);
}
DEF_DYNSEC_SYS(linkat, int olddfd, const char __user *oldname,
               int newdfd, const char __user *newname, int flags)
{
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
            syscall_hooks_enabled |= (MASK); \
        } \
    } while (0)

    copy_hook(delete_module);

    cond_copy_hook(open, DYNSEC_HOOK_TYPE_CREATE);
    cond_copy_hook(creat, DYNSEC_HOOK_TYPE_CREATE);
    cond_copy_hook(openat, DYNSEC_HOOK_TYPE_CREATE);
#ifdef __NR_openat2
    cond_copy_hook(openat2, DYNSEC_HOOK_TYPE_CREATE);
#endif /* __NR_openat2 */

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

    pr_info("syscall_hooks_enabled: %#018llx\n", syscall_hooks_enabled);

    ours = &in_our_kmod;
}

#ifdef CONFIG_X86_64
#define GPF_DISABLE() write_cr0(read_cr0() & (~ 0x10000))
#define GPF_ENABLE()  write_cr0(read_cr0() | 0x10000)

static inline bool set_page_state_rw(void **tbl, unsigned long *old_page_rw)
{
    unsigned int level;
    unsigned long irq_flags;
    pte_t *pte = NULL;

    local_irq_save(irq_flags);
    local_irq_disable();

    pte = lookup_address((unsigned long)tbl, &level);
    if (!pte) {
        local_irq_restore(irq_flags);
        return false;
    }

    *old_page_rw = pte->pte & _PAGE_RW;
    pte->pte |= _PAGE_RW;

    local_irq_restore(irq_flags);
    return true;
}

static inline void restore_page_state(void **tbl, unsigned long page_rw)
{
    unsigned int level;
    unsigned long irq_flags;
    pte_t *pte = NULL;

    local_irq_save(irq_flags);
    local_irq_disable();

    pte = lookup_address((unsigned long)tbl, &level);
    if (!pte)
    {
        local_irq_restore(irq_flags);
        return;
    }

    // If the page state was originally RO, restore it to RO.
    // We don't just assign the original value back here in case some other bits were changed.
    if (!page_rw) pte->pte &= ~_PAGE_RW;
    local_irq_restore(irq_flags);
}
#endif /* CONFIG_X86_64 */

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
        if (hooks->NAME && (syscall_hooks_enabled & (MASK))) { \
            table[__NR_##NAME] = hooks->NAME; \
        } \
    } while (0)

    local_irq_save(flags);
    local_irq_disable();
    get_cpu();
    GPF_DISABLE();

    if (!set_page_state_rw(table, &page_rw_set)) {
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

    restore_page_state(table, page_rw_set);

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

    symname = kzalloc(KSYM_NAME_LEN + 1, GFP_KERNEL);
    old_symname = kzalloc(KSYM_NAME_LEN + 1, GFP_KERNEL);

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
        return diff;
    }

#define __cmp_syscall(NAME, MASK, x) \
    do { \
        if (((syscall_hooks_enabled & (MASK)) || (x)) && \
            old_hooks->NAME != curr_hooks->NAME) { \
            diff += 1; \
            dynsec_module_name((unsigned long)curr_hooks->NAME, \
                               modname, MODULE_NAME_LEN); \
            if (symname) { \
                dynsec_lookup_symbol_name((unsigned long)curr_hooks->NAME, \
                                          symname); \
            } \
            dynsec_module_name((unsigned long)old_hooks->NAME, \
                               old_modname, MODULE_NAME_LEN); \
            if (old_symname) { \
                dynsec_lookup_symbol_name((unsigned long)old_hooks->NAME, \
                                          old_symname); \
            } \
            pr_info("syscall:" #NAME " change from %s -> %s  KMODS:%s -> %s\n", \
                    old_symname, symname, old_modname, modname); \
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

bool register_preaction_hooks(uint64_t lsm_hooks)
{
    syscall_hooks_enabled = 0;
    orig = NULL;
    ours = NULL;
    sys_call_table = NULL;
    ia32_sys_call_table = NULL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
    if (!lsm_hooks) {
        return true;
    }
#endif

    mutex_lock(&lookup_lock);
    get_syscall_tbl();
    if (!sys_call_table) {
        pr_info("Failed to grab syscall hooks\n");
        mutex_unlock(&lookup_lock);
        return false;
    }

    get_syscall_hooks(sys_call_table, &in_kernel);
    orig = &in_kernel;
    init_our_syscall_hooks(lsm_hooks);

    if (ours) {
        if (sys_call_table) {
            orig = &in_kernel;
            __set_syscall_table(ours, sys_call_table);
        }
        if (orig) {
            (void)syscall_changed(orig, NULL);
        }
    }
    mutex_unlock(&lookup_lock);

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
    mutex_lock(&lookup_lock);
    restore_syscalls();
    mutex_unlock(&lookup_lock);
}
