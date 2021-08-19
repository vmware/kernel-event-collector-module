#pragma once

#include <linux/unistd.h>

extern bool register_preaction_hooks(void);
extern void preaction_hooks_shutdown(void);

struct syscall_hooks {
    asmlinkage long (*delete_module)(const char __user *name_user, unsigned int flags);

    asmlinkage long (*open)(const char __user *filename, int flags, umode_t mode);
    asmlinkage long (*creat)(const char __user *pathname, umode_t mode);
    asmlinkage long (*openat)(int dfd, const char __user *filename, int flags, umode_t mode);
#ifdef __NR_openat2
    asmlinkage long (*openat2)(int dfd, const char __user *filename,
                               struct open_how __user * how, size_t usize);
#endif /* __NR_openat2 */

    asmlinkage long (*rename)(const char __user *oldname, const char __user *newname);
#ifdef __NR_renameat
    asmlinkage long (*renameat)(int olddfd, const char __user *oldname,
                                   int newdfd, const char __user *newname);
#endif /* __NR_renameat */
#ifdef __NR_renameat2
    asmlinkage long (*renameat2)(int olddfd, const char __user *oldname,
                                    int newdfd, const char __user *newname,
                                    unsigned int flags);
#endif /* __NR_renameat2 */

    asmlinkage long (*mkdir)(const char __user *pathname, umode_t mode);
    asmlinkage long (*mkdirat)(int dfd, const char __user *pathname, umode_t mode);

    asmlinkage long (*unlink)(const char __user *pathname);
    asmlinkage long (*unlinkat)(int dfd, const char __user *pathname, int flag);
    asmlinkage long (*rmdir)(const char __user *pathname);

    asmlinkage long (*symlink)(const char __user *oldname, const char __user *newname);
    asmlinkage long (*symlinkat)(const char __user *oldname,
                                 int newdfd, const char __user *newname);

    asmlinkage long (*link)(const char __user *oldname, const char __user *newname);
    asmlinkage long (*linkat)(int olddfd, const char __user *oldname,
                              int newdfd, const char __user *newname, int flags);
};
