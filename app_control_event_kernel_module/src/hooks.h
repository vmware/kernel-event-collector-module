/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2021 VMware, Inc. All rights reserved.
#pragma once

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0) || \
    (defined(RHEL_MAJOR) && defined(RHEL_MINOR) && \
        RHEL_MAJOR == 8 && RHEL_MINOR >= 6)
// TODO: Determine if bprm_creds_from_file requires a new hook
int dynsec_bprm_creds_for_exec(struct linux_binprm *bprm);
#else
int dynsec_bprm_set_creds(struct linux_binprm *bprm);
#endif

extern int dynsec_inode_unlink(struct inode *dir, struct dentry *dentry);

extern int dynsec_inode_rmdir(struct inode *dir, struct dentry *dentry);

extern int dynsec_inode_rename(struct inode *old_dir, struct dentry *old_dentry,
                               struct inode *new_dir, struct dentry *new_dentry);

extern int dynsec_inode_setattr(struct dentry *dentry, struct iattr *attr);


#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
extern int dynsec_inode_mkdir(struct inode *dir, struct dentry *dentry,
                              umode_t mode);
#else
extern int dynsec_inode_mkdir(struct inode *dir, struct dentry *dentry,
                              int mode);
#endif


#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
extern int dynsec_inode_create(struct inode *dir, struct dentry *dentry,
                               umode_t mode);
#else
extern int dynsec_inode_create(struct inode *dir, struct dentry *dentry,
                               int mode);
#endif

extern int dynsec_inode_link(struct dentry *old_dentry, struct inode *dir,
                      struct dentry *new_dentry);

extern int dynsec_inode_symlink(struct inode *dir, struct dentry *dentry,
                const char *old_name);

extern void dynsec_inode_free_security(struct inode *inode);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
extern int dynsec_file_open(struct file *file);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
extern int dynsec_file_open(struct file *file, const struct cred *cred);
#else
extern int dynsec_dentry_open(struct file *file, const struct cred *cred);
#endif

extern void dynsec_file_free_security(struct file *file);

extern int dynsec_ptrace_traceme(struct task_struct *parent);
extern int dynsec_ptrace_access_check(struct task_struct *child, unsigned int mode);


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
#if defined(RHEL_MAJOR) && RHEL_MAJOR == 8 && RHEL_MINOR == 0
extern int dynsec_task_kill(struct task_struct *p, struct siginfo *info,
                            int sig, const struct cred *cred);
#else
extern int dynsec_task_kill(struct task_struct *p, struct kernel_siginfo *info,
                            int sig, const struct cred *cred);
#endif
#else
extern int dynsec_task_kill(struct task_struct *p, struct siginfo *info,
                            int sig, u32 secid);
#endif


#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
extern int dynsec_mmap_file(struct file *file, unsigned long reqprot, unsigned long prot,
                            unsigned long flags);
#else
extern int dynsec_file_mmap(struct file *file, unsigned long reqprot, unsigned long prot,
                            unsigned long flags, unsigned long addr, unsigned long addr_only);
#endif

extern int dynsec_task_fix_setuid(struct cred *new, const struct cred *old, int flags);

extern int dynsec_task_fix_setgid(struct cred *new, const struct cred *old, int flags);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
extern void dynsec_task_free(struct task_struct *task);
#endif

extern int dynsec_task_dump_all(uint16_t opts, pid_t start_tgid);

extern ssize_t dynsec_task_dump_one(uint16_t opts, pid_t start_tgid,
                                    void __user *ubuf, size_t size);
