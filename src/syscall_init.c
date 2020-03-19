// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include "priv.h"
#include "syscall_stub.h"
#include "page-helpers.h"

#include <linux/unistd.h>

// checkpatch-ignore: AVOID_EXTERNS
// For Network hooks
extern long (*cb_orig_sys_recvfrom)(int, void __user *, size_t, unsigned int, struct sockaddr __user *, int __user *);
extern long (*cb_orig_sys_recvmsg)(int fd, struct msghdr __user *msg, unsigned int flags);
extern long (*cb_orig_sys_recvmmsg)(int fd, struct mmsghdr __user *msg, unsigned int vlen, unsigned int flags, struct timespec __user *timeout);

extern asmlinkage long cb_sys_recvfrom(int fd, void __user *ubuf, size_t size, unsigned int flags,
                                       struct sockaddr __user *addr, int __user *addr_len);
extern asmlinkage long cb_sys_recvmsg(int fd, struct msghdr __user *msg, unsigned int flags);
extern asmlinkage long cb_sys_recvmmsg(int fd, struct mmsghdr __user *msg,
                                unsigned int vlen, unsigned int flags,
                                struct timespec __user *timeout);

// For File hooks
extern long (*cb_orig_sys_write)(unsigned int fd, const char __user *buf, size_t count);
extern long (*cb_orig_sys_close)(unsigned int fd);
extern long (*cb_orig_sys_open)(const char __user *filename, int flags, umode_t mode);
extern long (*cb_orig_sys_openat)(int dfd, const char __user *filename, int flags, umode_t mode);
extern long (*cb_orig_sys_creat)(const char __user *pathname, umode_t mode);
extern long (*cb_orig_sys_unlink)(const char __user *pathname);
extern long (*cb_orig_sys_unlinkat)(int dfd, const char __user *pathname, int flag);
extern long (*cb_orig_sys_rename)(const char __user *oldname, const char __user *newname);

extern asmlinkage long cb_sys_write(unsigned int fd, const char __user *buf, size_t count);
extern asmlinkage long cb_sys_close(unsigned int fd);
extern asmlinkage long cb_sys_open(const char __user *filename, int flags, umode_t mode);
extern asmlinkage long cb_sys_openat(int dfd, const char __user *filename, int flags, umode_t mode);
extern asmlinkage long cb_sys_creat(const char __user *pathname, umode_t mode);
extern asmlinkage long cb_sys_unlink(const char __user *pathname);
extern asmlinkage long cb_sys_unlinkat(int dfd, const char __user *pathname, int flag);
extern asmlinkage long cb_sys_rename(const char __user *oldname, const char __user *newname);


// Kernel module hooks
extern long (*cb_orig_sys_delete_module)(const char __user *name_user, unsigned int flags);

extern asmlinkage long cb_sys_delete_module(const char __user *name_user, unsigned int flags);

static unsigned long page_rw_set;

static void save_old_hooks(p_sys_call_table syscall_table)
{
    cb_orig_sys_delete_module = syscall_table[__NR_delete_module];
    cb_orig_sys_recvfrom      = syscall_table[__NR_recvfrom];
    cb_orig_sys_recvmsg       = syscall_table[__NR_recvmsg];
    cb_orig_sys_recvmmsg      = syscall_table[__NR_recvmmsg];
    cb_orig_sys_write         = syscall_table[__NR_write];
    cb_orig_sys_close         = syscall_table[__NR_close];
    cb_orig_sys_creat         = syscall_table[__NR_creat];
    cb_orig_sys_open          = syscall_table[__NR_open];
    cb_orig_sys_openat        = syscall_table[__NR_openat];
    cb_orig_sys_unlink        = syscall_table[__NR_unlink];
    cb_orig_sys_unlinkat      = syscall_table[__NR_unlinkat];
    cb_orig_sys_rename        = syscall_table[__NR_rename];
}

static bool set_new_hooks(p_sys_call_table syscall_table, uint64_t enableHooks)
{
    bool rval = false;

    // Disable CPU write protect, and update the call table after disabling preemption for this cpu
    get_cpu();
    GPF_DISABLE;

    if (set_page_state_rw(syscall_table, &page_rw_set))
    {
        if (enableHooks & CB__NR_delete_module) syscall_table[__NR_delete_module] = cb_sys_delete_module;
        if (enableHooks & CB__NR_recvfrom) syscall_table[__NR_recvfrom]  = cb_sys_recvfrom;
        if (enableHooks & CB__NR_recvmsg) syscall_table[__NR_recvmsg]   = cb_sys_recvmsg;
        if (enableHooks & CB__NR_recvmmsg) syscall_table[__NR_recvmmsg]  = cb_sys_recvmmsg;
        if (enableHooks & CB__NR_write) syscall_table[__NR_write]     = cb_sys_write;
        if (enableHooks & CB__NR_close) syscall_table[__NR_close]     = cb_sys_close;
        if (enableHooks & CB__NR_creat) syscall_table[__NR_creat]    = cb_sys_creat;
        if (enableHooks & CB__NR_open) syscall_table[__NR_open]      = cb_sys_open;
        if (enableHooks & CB__NR_openat) syscall_table[__NR_openat]    = cb_sys_openat;
        if (enableHooks & CB__NR_unlink) syscall_table[__NR_unlink]    = cb_sys_unlink;
        if (enableHooks & CB__NR_unlinkat) syscall_table[__NR_unlinkat]  = cb_sys_unlinkat;
        if (enableHooks & CB__NR_rename) syscall_table[__NR_rename]    = cb_sys_rename;

        restore_page_state(syscall_table, page_rw_set);
        rval = true;
    } else {
        TRACE(DL_ERROR, "Failed to make 64-bit call table RW!!\n");
    }

    GPF_ENABLE;
    put_cpu();

    return rval;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
static bool set_new_32bit_hooks(p_sys_call_table syscall_table, uint64_t enableHooks)
{
    bool rval = false;

    get_cpu();
    GPF_DISABLE;

    if (set_page_state_rw(syscall_table, &page_rw_set))
    {
        if (enableHooks & CB__NR_write) syscall_table[__NR_ia32_write] = cb_sys_write;
        restore_page_state(syscall_table, page_rw_set);
        rval = true;
    } else {
        TRACE(DL_ERROR, "Failed to make 32-bit call table RW!!\n");
    }

    GPF_ENABLE;
    put_cpu();

    return rval;
}
#endif

static void restore_hooks(p_sys_call_table syscall_table, uint64_t enableHooks)
{
    // Disable CPU write protect, and restore the call table
    get_cpu();
    GPF_DISABLE;

    if (set_page_state_rw(syscall_table, &page_rw_set))
    {
        if (enableHooks & CB__NR_recvfrom) syscall_table[__NR_recvfrom]  = cb_orig_sys_recvfrom;
        if (enableHooks & CB__NR_recvmsg) syscall_table[__NR_recvmsg]   = cb_orig_sys_recvmsg;
        if (enableHooks & CB__NR_recvmmsg) syscall_table[__NR_recvmmsg]  = cb_orig_sys_recvmmsg;
        if (enableHooks & CB__NR_write) syscall_table[__NR_write]     = cb_orig_sys_write;
        if (enableHooks & CB__NR_close) syscall_table[__NR_close]     = cb_orig_sys_close;
        if (enableHooks & CB__NR_delete_module) syscall_table[__NR_delete_module] = cb_orig_sys_delete_module;
        if (enableHooks & CB__NR_creat) syscall_table[__NR_creat]     = cb_orig_sys_creat;
        if (enableHooks & CB__NR_open) syscall_table[__NR_open]      = cb_orig_sys_open;
        if (enableHooks & CB__NR_openat) syscall_table[__NR_openat]    = cb_orig_sys_openat;
        if (enableHooks & CB__NR_unlink) syscall_table[__NR_unlink]    = cb_orig_sys_unlink;
        if (enableHooks & CB__NR_unlinkat) syscall_table[__NR_unlinkat]  = cb_orig_sys_unlinkat;
        if (enableHooks & CB__NR_rename) syscall_table[__NR_rename]    = cb_orig_sys_rename;
        restore_page_state(syscall_table, page_rw_set);
    } else {
        TRACE(DL_ERROR, "Failed to make 64-bit call table RW!!\n");
    }

    GPF_ENABLE;
    put_cpu();
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
static void restore_32bit_hooks(p_sys_call_table syscall_table, uint64_t enableHooks)
{
    // Disable CPU write protect, and restore the call table
    get_cpu();
    GPF_DISABLE;

    if (set_page_state_rw(syscall_table, &page_rw_set))
    {
        if (enableHooks & CB__NR_write) syscall_table[__NR_ia32_write] = cb_orig_sys_write;
        restore_page_state(syscall_table, page_rw_set);
    } else {
        TRACE(DL_ERROR, "Failed to make 32-bit call table RW!!\n");
    }

    GPF_ENABLE;
    put_cpu();
}
#endif

bool syscall_initialize(ProcessContext *context, uint64_t enableHooks)
{
    bool rval = false;
    p_sys_call_table syscall_table;

    // If the hooks are not enabled, then no point in continuing.
    if (!(enableHooks & SYSCALL_HOOK_MASK)) return true;

    // Find the syscall table addresses.
    TRY_CB_RESOLVED(sys_call_table);
    syscall_table = CB_RESOLVED(sys_call_table);

    save_old_hooks(syscall_table);
    rval = set_new_hooks(syscall_table, enableHooks);

    // Handle special cases for 32-bit system calls.
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
    {
        p_sys_call_table syscall_table_i32;

        TRY_CB_RESOLVED(ia32_sys_call_table);
        syscall_table_i32 = CB_RESOLVED(ia32_sys_call_table);

        rval &= set_new_32bit_hooks(syscall_table_i32, enableHooks);
    }
#endif

CATCH_DEFAULT:
    return rval;
}


bool syscall_hooks_changed(ProcessContext *context, uint64_t enableHooks)
{
    bool changed = false;
    p_sys_call_table syscall_table;

    TRY_CB_RESOLVED(sys_call_table);
    syscall_table = CB_RESOLVED(sys_call_table);

    if (enableHooks & CB__NR_delete_module) changed |= syscall_table[__NR_delete_module] != cb_sys_delete_module;
    if (enableHooks & CB__NR_recvfrom) changed |= syscall_table[__NR_recvfrom]  != cb_sys_recvfrom;
    if (enableHooks & CB__NR_recvmsg) changed |= syscall_table[__NR_recvmsg]   != cb_sys_recvmsg;
    if (enableHooks & CB__NR_recvmmsg) changed |= syscall_table[__NR_recvmmsg]  != cb_sys_recvmmsg;
    if (enableHooks & CB__NR_write) changed |= syscall_table[__NR_write]     != cb_sys_write;

CATCH_DEFAULT:
    return changed;
}


void syscall_shutdown(ProcessContext *context, uint64_t enableHooks)
{
    p_sys_call_table syscall_table;

    TRY_CB_RESOLVED(sys_call_table);
    syscall_table = CB_RESOLVED(sys_call_table);

    restore_hooks(syscall_table, enableHooks);

    // Handle special cases for 32-bit system calls.
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
    {
        p_sys_call_table syscall_table_i32;

        TRY_CB_RESOLVED(ia32_sys_call_table);
        syscall_table_i32 = CB_RESOLVED(ia32_sys_call_table);

        restore_32bit_hooks(syscall_table_i32, enableHooks);
    }
#endif

CATCH_DEFAULT:
    return;
}


#ifdef HOOK_SELECTOR
static void setSyscall(const char *buf, const char *name, uint64_t syscall, int nr, void *cb_call, void *krn_call, void **table)
{
    int cpu;
    void *call = NULL;

    if (0 == strncmp("1", buf, sizeof(char)))
    {
        pr_info("Adding %s\n", name);
        g_enableHooks |= syscall;
        call = cb_call;
    } else if (0 == strncmp("0", buf, sizeof(char)))
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
    if (set_page_state_rw(table, &page_rw_set))
    {
        table[nr] = call;
        restore_page_state(table, page_rw_set);
    }
    GPF_ENABLE;
    put_cpu();
}

static int getSyscall(uint64_t syscall, struct seq_file *m)
{
    seq_printf(m, (g_enableHooks & syscall ? "1\n" : "0\n"));
    return 0;
}

int cb_syscall_recvfrom_get(struct seq_file *m, void *v) { return getSyscall(CB__NR_recvfrom, m); }
int cb_syscall_recvmsg_get(struct seq_file *m, void *v) { return getSyscall(CB__NR_recvmsg,  m); }
int cb_syscall_recvmmsg_get(struct seq_file *m, void *v) { return getSyscall(CB__NR_recvmmsg, m); }
int cb_syscall_write_get(struct seq_file *m, void *v) { return getSyscall(CB__NR_write,    m); }
int cb_syscall_close_get(struct seq_file *m, void *v) { return getSyscall(CB__NR_close,    m); }
int cb_syscall_delete_module_get(struct seq_file *m, void *v) { return getSyscall(CB__NR_delete_module,    m); }
int cb_syscall_creat_get(struct seq_file *m, void *v) { return getSyscall(CB__NR_creat,       m); }
int cb_syscall_open_get(struct seq_file *m, void *v) { return getSyscall(CB__NR_open,         m); }
int cb_syscall_openat_get(struct seq_file *m, void *v) { return getSyscall(CB__NR_openat,     m); }
int cb_syscall_unlink_get(struct seq_file *m, void *v) { return getSyscall(CB__NR_unlink,     m); }
int cb_syscall_unlinkat_get(struct seq_file *m, void *v) { return getSyscall(CB__NR_unlinkat, m); }
int cb_syscall_rename_get(struct seq_file *m, void *v) { return getSyscall(CB__NR_rename,     m); }

ssize_t cb_syscall_recvfrom_set(struct file *file, const char *buf, size_t size, loff_t *ppos)
{
    setSyscall(buf, "recvfrom", CB__NR_recvfrom, __NR_recvfrom, cb_sys_recvfrom,       cb_orig_sys_recvfrom, CB_RESOLVED(sys_call_table));
    return size;
}

ssize_t cb_syscall_recvmsg_set(struct file *file, const char *buf, size_t size, loff_t *ppos)
{
    setSyscall(buf, "recvmsg", CB__NR_recvmsg, __NR_recvmsg,  cb_sys_recvmsg,          cb_orig_sys_recvmsg, CB_RESOLVED(sys_call_table));
    return size;
}

ssize_t cb_syscall_recvmmsg_set(struct file *file, const char *buf, size_t size, loff_t *ppos)
{
    setSyscall(buf, "recvmmsg", CB__NR_recvmmsg, __NR_recvmmsg, cb_sys_recvmmsg,       cb_orig_sys_recvmmsg, CB_RESOLVED(sys_call_table));
    return size;
}

ssize_t cb_syscall_write_set(struct file *file, const char *buf, size_t size, loff_t *ppos)
{
    setSyscall(buf, "write", CB__NR_write,   __NR_write,      cb_sys_write,            cb_orig_sys_write, CB_RESOLVED(sys_call_table));
    //setSyscall( buf, "write", CB__NR_write,   __NR_ia32_write, cb_sys_write,            cb_orig_sys_write, CB_RESOLVED(ia32_sys_call_table) );
    return size;
}

ssize_t cb_syscall_close_set(struct file *file, const char *buf, size_t size, loff_t *ppos)
{
    setSyscall(buf, "close", CB__NR_close,   __NR_close,      cb_sys_close,            cb_orig_sys_close, CB_RESOLVED(sys_call_table));
    return size;
}

ssize_t cb_syscall_delete_module(struct file *file, const char *buf, size_t size, loff_t *ppos)
{
    setSyscall(buf, "delete_module", CB__NR_delete_module,   __NR_delete_module, cb_sys_delete_module, cb_orig_sys_delete_module, CB_RESOLVED(sys_call_table));
    return size;
}
#endif
