// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include "priv.h"
#include "syscall_stub.h"
#include "page-helpers.h"

#include <linux/unistd.h>

// checkpatch-ignore: AVOID_EXTERNS

// For File hooks
extern long (*ec_orig_sys_open)(const char __user *filename, int flags, umode_t mode);
extern long (*ec_orig_sys_openat)(int dfd, const char __user *filename, int flags, umode_t mode);
extern long (*ec_orig_sys_creat)(const char __user *pathname, umode_t mode);
extern long (*ec_orig_sys_unlink)(const char __user *pathname);
extern long (*ec_orig_sys_unlinkat)(int dfd, const char __user *pathname, int flag);
extern long (*ec_orig_sys_rename)(const char __user *oldname, const char __user *newname);
extern long (*ec_orig_sys_renameat)(int old_dfd, const char __user *oldname, int new_dfd, const char __user *newname);
extern long (*ec_orig_sys_renameat2)(int old_dfd, const char __user *oldname, int new_dfd, const char __user *newname, unsigned int flags);

extern asmlinkage long ec_sys_open(const char __user *filename, int flags, umode_t mode);
extern asmlinkage long ec_sys_openat(int dfd, const char __user *filename, int flags, umode_t mode);
extern asmlinkage long ec_sys_creat(const char __user *pathname, umode_t mode);
extern asmlinkage long ec_sys_unlink(const char __user *pathname);
extern asmlinkage long ec_sys_unlinkat(int dfd, const char __user *pathname, int flag);
extern asmlinkage long ec_sys_rename(const char __user *oldname, const char __user *newname);
extern asmlinkage long ec_sys_renameat(int old_dfd, const char __user *oldname, int new_dfd, const char __user *newname);
extern asmlinkage long ec_sys_renameat2(int old_dfd, const char __user *oldname, int new_dfd, const char __user *newname, unsigned int flags);

// Kernel module hooks
extern long (*ec_orig_sys_delete_module)(const char __user *name_user, unsigned int flags);

extern asmlinkage long ec_sys_delete_module(const char __user *name_user, unsigned int flags);

static unsigned long page_rw_set;

void __ec_save_old_hooks(p_sys_call_table syscall_table)
{
    ec_orig_sys_delete_module = syscall_table[__NR_delete_module];
    ec_orig_sys_creat         = syscall_table[__NR_creat];
    ec_orig_sys_open          = syscall_table[__NR_open];
    ec_orig_sys_openat        = syscall_table[__NR_openat];
    ec_orig_sys_unlink        = syscall_table[__NR_unlink];
    ec_orig_sys_unlinkat      = syscall_table[__NR_unlinkat];
    ec_orig_sys_rename        = syscall_table[__NR_rename];
    ec_orig_sys_renameat      = syscall_table[__NR_renameat];
    #if RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(7, 0)
    ec_orig_sys_renameat2     = syscall_table[__NR_renameat2];
    #endif
}

bool __ec_set_new_hooks(p_sys_call_table syscall_table, uint64_t enableHooks)
{
    bool rval = false;

    // Disable CPU write protect, and update the call table after disabling preemption for this cpu
    get_cpu();
    GPF_DISABLE;

    if (ec_set_page_state_rw(syscall_table, &page_rw_set))
    {
        if (enableHooks & CB__NR_delete_module) syscall_table[__NR_delete_module] = ec_sys_delete_module;
        if (enableHooks & CB__NR_creat) syscall_table[__NR_creat]    = ec_sys_creat;
        if (enableHooks & CB__NR_open) syscall_table[__NR_open]      = ec_sys_open;
        if (enableHooks & CB__NR_openat) syscall_table[__NR_openat]    = ec_sys_openat;
        if (enableHooks & CB__NR_unlink) syscall_table[__NR_unlink]    = ec_sys_unlink;
        if (enableHooks & CB__NR_unlinkat) syscall_table[__NR_unlinkat]  = ec_sys_unlinkat;
        if (enableHooks & CB__NR_rename) syscall_table[__NR_rename]    = ec_sys_rename;
        if (enableHooks & CB__NR_renameat) syscall_table[__NR_renameat]    = ec_sys_renameat;
        #if RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(7, 0)
        if (enableHooks & CB__NR_renameat2) syscall_table[__NR_renameat2]    = ec_sys_renameat2;
        #endif

        ec_restore_page_state(syscall_table, page_rw_set);
        rval = true;
    } else {
        TRACE(DL_ERROR, "Failed to make 64-bit call table RW!!\n");
    }

    GPF_ENABLE;
    put_cpu();

    return rval;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
bool set_new_32bit_hooks(p_sys_call_table syscall_table, uint64_t enableHooks)
{
    return true;
//    bool rval = false;
//
//    get_cpu();
//    GPF_DISABLE;
//
//    if (ec_set_page_state_rw(syscall_table, &page_rw_set))
//    {
//        // Set hooks here
//        ec_restore_page_state(syscall_table, page_rw_set);
//        rval = true;
//    } else {
//        TRACE(DL_ERROR, "Failed to make 32-bit call table RW!!\n");
//    }
//
//    GPF_ENABLE;
//    put_cpu();
//
//    return rval;
}
#endif

void __ec_restore_hooks(p_sys_call_table syscall_table, uint64_t enableHooks)
{
    // Disable CPU write protect, and restore the call table
    get_cpu();
    GPF_DISABLE;

    if (ec_set_page_state_rw(syscall_table, &page_rw_set))
    {
        if (enableHooks & CB__NR_delete_module) syscall_table[__NR_delete_module] = ec_orig_sys_delete_module;
        if (enableHooks & CB__NR_creat) syscall_table[__NR_creat]     = ec_orig_sys_creat;
        if (enableHooks & CB__NR_open) syscall_table[__NR_open]      = ec_orig_sys_open;
        if (enableHooks & CB__NR_openat) syscall_table[__NR_openat]    = ec_orig_sys_openat;
        if (enableHooks & CB__NR_unlink) syscall_table[__NR_unlink]    = ec_orig_sys_unlink;
        if (enableHooks & CB__NR_unlinkat) syscall_table[__NR_unlinkat]  = ec_orig_sys_unlinkat;
        if (enableHooks & CB__NR_rename) syscall_table[__NR_rename]    = ec_orig_sys_rename;
        if (enableHooks & CB__NR_renameat) syscall_table[__NR_renameat]    = ec_orig_sys_renameat;
        #if RHEL_RELEASE_CODE > RHEL_RELEASE_VERSION(7, 0)
        if (enableHooks & CB__NR_renameat2) syscall_table[__NR_renameat2]    = ec_orig_sys_renameat2;
        #endif
        ec_restore_page_state(syscall_table, page_rw_set);
    } else {
        TRACE(DL_ERROR, "Failed to make 64-bit call table RW!!\n");
    }

    GPF_ENABLE;
    put_cpu();
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
void restore_32bit_hooks(p_sys_call_table syscall_table, uint64_t enableHooks)
{
//    // Disable CPU write protect, and restore the call table
//    get_cpu();
//    GPF_DISABLE;
//
//    if (ec_set_page_state_rw(syscall_table, &page_rw_set))
//    {
//        // Set hooks here
//        ec_restore_page_state(syscall_table, page_rw_set);
//    } else {
//        TRACE(DL_ERROR, "Failed to make 32-bit call table RW!!\n");
//    }
//
//    GPF_ENABLE;
//    put_cpu();
}
#endif

static bool s_hooks_replaced;

bool ec_do_sys_initialize(ProcessContext *context)
{
    bool rval = false;
    p_sys_call_table syscall_table;

    // If the hooks are not enabled, then no point in continuing.
    if (!(g_enableHooks & SYSCALL_HOOK_MASK)) return true;

    // Find the syscall table addresses.
    TRY_CB_RESOLVED(sys_call_table);
    syscall_table = CB_RESOLVED(sys_call_table);

    __ec_save_old_hooks(syscall_table);
    rval = __ec_set_new_hooks(syscall_table, g_enableHooks);

    // Handle special cases for 32-bit system calls.
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
    {
        p_sys_call_table syscall_table_i32;

        TRY_CB_RESOLVED(ia32_sys_call_table);
        syscall_table_i32 = CB_RESOLVED(ia32_sys_call_table);

        rval &= set_new_32bit_hooks(syscall_table_i32, g_enableHooks);
    }
#endif

CATCH_DEFAULT:
    s_hooks_replaced = rval;
    return rval;
}


bool ec_do_sys_hooks_changed(ProcessContext *context)
{
    bool changed = false;
    p_sys_call_table syscall_table;

    TRY_CB_RESOLVED(sys_call_table);
    syscall_table = CB_RESOLVED(sys_call_table);

    if (g_enableHooks & CB__NR_delete_module) changed |= syscall_table[__NR_delete_module] != ec_sys_delete_module;
CATCH_DEFAULT:
    return changed;
}


void ec_do_sys_shutdown(ProcessContext *context)
{
    p_sys_call_table syscall_table;

    TRY(s_hooks_replaced);

    TRY_CB_RESOLVED(sys_call_table);
    syscall_table = CB_RESOLVED(sys_call_table);

    __ec_restore_hooks(syscall_table, g_enableHooks);

    // Handle special cases for 32-bit system calls.
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
    {
        p_sys_call_table syscall_table_i32;

        TRY_CB_RESOLVED(ia32_sys_call_table);
        syscall_table_i32 = CB_RESOLVED(ia32_sys_call_table);

        restore_32bit_hooks(syscall_table_i32, g_enableHooks);
    }
#endif
    s_hooks_replaced = false;

CATCH_DEFAULT:
    return;
}


#ifdef HOOK_SELECTOR  //{
static void setSyscall(const char *buf, const char *name, uint64_t syscall, int nr, void *cb_call, void *krn_call, void **table)
{
    int cpu;
    void *call = NULL;

    if ('1' == buf[0])
    {
        pr_info("Adding %s\n", name);
        g_enableHooks |= syscall;
        call = ec_call;
    } else if ('0' == buf[0])
    {
        pr_info("Removing %s\n", name);
        g_enableHooks &= ~syscall;
        call = krn_call;
    } else
    {
        pr_err("Error adding %s to %s\n", buf, name);
        return;
    }

    // Disable CPU write protect, and restore the call table
    cpu = get_cpu();
    GPF_DISABLE;
    if (ec_set_page_state_rw(table, &page_rw_set))
    {
        table[nr] = call;
        ec_restore_page_state(table, page_rw_set);
    }
    GPF_ENABLE;
    put_cpu();
}

int getSyscall(uint64_t syscall, struct seq_file *m)
{
    seq_printf(m, (g_enableHooks & syscall ? "1\n" : "0\n"));
    return 0;
}

int ec_get_sys_delete_module(struct seq_file *m, void *v) { return getSyscall(CB__NR_delete_module,    m); }
int ec_get_sys_creat(struct seq_file *m, void *v) { return getSyscall(CB__NR_creat,       m); }
int ec_get_sys_open(struct seq_file *m, void *v) { return getSyscall(CB__NR_open,         m); }
int ec_get_sys_openat(struct seq_file *m, void *v) { return getSyscall(CB__NR_openat,     m); }
int ec_get_sys_unlink(struct seq_file *m, void *v) { return getSyscall(CB__NR_unlink,     m); }
int ec_get_sys_unlinkat(struct seq_file *m, void *v) { return getSyscall(CB__NR_unlinkat, m); }
int ec_get_sys_rename(struct seq_file *m, void *v) { return getSyscall(CB__NR_rename,     m); }
int ec_get_sys_renameat(struct seq_file *m, void *v) { return getSyscall(CB__NR_renameat, m); }
int ec_get_sys_renameat2(struct seq_file *m, void *v) { return getSyscall(CB__NR_renameat2, m); }

ssize_t ec_set_sys_delete_module(struct file *file, const char *buf, size_t size, loff_t *ppos)
{
    setSyscall(buf, "delete_module", CB__NR_delete_module,   __NR_delete_module, ec_sys_delete_module, ec_orig_sys_delete_module, CB_RESOLVED(sys_call_table));
    return size;
}
#endif  //}
