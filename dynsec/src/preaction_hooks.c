

#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include "preaction_hooks.h"
#include "symbols.h"
#include "version.h"


static struct syscall_hooks *orig;
static struct syscall_hooks *ours;

static struct syscall_hooks in_kernel;
static struct syscall_hooks in_our_kmod;
// static struct syscall_hooks foreign;


static DEFINE_MUTEX(lookup_lock);
static void **sys_call_table;
static void **prev_sys_call_table;
static void **ia32_sys_call_table;
static void **prev_ia32_sys_call_table;

#define GPF_DISABLE() write_cr0(read_cr0() & (~ 0x10000))
#define GPF_ENABLE()  write_cr0(read_cr0() | 0x10000)


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
#endif


static inline struct syscall_hooks *select_hook(void)
{
    if (orig) {
        return orig;
    }
    return &in_kernel;
}

asmlinkage long dynsec_delete_module(const char __user *name_user, unsigned int flags)
{
    char *modname = NULL;
    int ret;
    static int count = 0;
    int local_count;

    modname = kzalloc(MODULE_NAME_LEN + 1, GFP_KERNEL);
    if (!modname) {
        return -ENOMEM;
    }

    ret = strncpy_from_user(modname, name_user, MODULE_NAME_LEN);
    if (ret < 0) {
        kfree(modname);
        return ret;
    }

    if (strncmp(modname, CB_APP_MODULE_NAME, MODULE_NAME_LEN) == 0) {
        kfree(modname);

        mutex_lock(&lookup_lock);
        count += 1;
        local_count = count;
        mutex_unlock(&lookup_lock);

        if (local_count == 1) {
            preaction_hooks_shutdown();
            return -EBUSY;
        }
    }

    kfree(modname);
    return select_hook()->delete_module(name_user, flags);
}

asmlinkage long dynsec_open(const char __user *filename, int flags, umode_t mode)
{
    return select_hook()->open(filename, flags, mode);
}
asmlinkage long dynsec_creat(const char __user *pathname, umode_t mode)
{
    return select_hook()->creat(pathname, mode);
}
asmlinkage long dynsec_openat(int dfd, const char __user *filename,
                              int flags, umode_t mode)
{
    return select_hook()->openat(dfd, filename, flags, mode);
}
#ifdef __NR_openat2
asmlinkage long dynsec_openat2(int dfd, const char __user *filename,
                               struct open_how __user *how, size_t usize)
{
    return select_hook()->openat2(dfd, filename, how, usize);
}
#endif /* __NR_openat2 */

asmlinkage long dynsec_rename(const char __user *oldname, const char __user *newname)
{
    return select_hook()->rename(oldname, newname);
}
#ifdef __NR_renameat
asmlinkage long dynsec_renameat(int olddfd, const char __user *oldname,
                                int newdfd, const char __user *newname)
{
    return select_hook()->renameat(olddfd, oldname, newdfd, newname);
}
#endif /* __NR_renameat */
#ifdef __NR_renameat2
asmlinkage long dynsec_renameat2(int olddfd, const char __user *oldname,
                                 int newdfd, const char __user *newname,
                                 unsigned int flags)
{
    return select_hook()->renameat2(olddfd, oldname, newdfd, newname, flags);
}
#endif /* __NR_renameat2 */


asmlinkage long dynsec_mkdir(const char __user *pathname, umode_t mode)
{
    return select_hook()->mkdir(pathname, mode);
}
asmlinkage long dynsec_mkdirat(int dfd, const char __user *pathname, umode_t mode)
{
    return select_hook()->mkdirat(dfd, pathname, mode);
}


asmlinkage long dynsec_unlink(const char __user *pathname)
{
    return select_hook()->unlink(pathname);
}
asmlinkage long dynsec_unlinkat(int dfd, const char __user *pathname, int flag)
{
    return select_hook()->unlinkat(dfd, pathname, flag);
}
asmlinkage long dynsec_rmdir(const char __user *pathname)
{
    return select_hook()->rmdir(pathname);
}


asmlinkage long dynsec_symlink(const char __user *oldname, const char __user *newname)
{
    return select_hook()->symlink(oldname, newname);
}

asmlinkage long dynsec_symlinkat(const char __user *oldname,
                                 int newdfd, const char __user *newname)
{
    return select_hook()->symlinkat(oldname, newdfd, newname);
}

asmlinkage long dynsec_link(const char __user *oldname, const char __user *newname)
{
    return select_hook()->link(oldname, newname);
}

asmlinkage long dynsec_linkat(int olddfd, const char __user *oldname,
                              int newdfd, const char __user *newname, int flags)
{
    return select_hook()->linkat(olddfd, oldname, newdfd, newname, flags);
}

// On success unlock lookup_lock
static int get_syscall_tbl(void)
{
    void **local_sys_call_table = NULL;
    void **local_ia32_sys_call_table = NULL;

    find_symbol_indirect("sys_call_table", (unsigned long *)&local_sys_call_table);

    if (local_sys_call_table) {
        // Only get 32bit table if we can get the main tbl
        find_symbol_indirect("ia32_sys_call_table",
                             (unsigned long *)&local_ia32_sys_call_table);

        mutex_lock(&lookup_lock);
        if (local_sys_call_table) {
            if (!sys_call_table) {
                prev_sys_call_table = local_sys_call_table;
            } else {
                prev_sys_call_table = sys_call_table;
            }
            sys_call_table = local_sys_call_table;
        }

        // For now grab the 32bit but not act on it yet
        if (local_ia32_sys_call_table) {
            if (!ia32_sys_call_table) {
                prev_ia32_sys_call_table = local_ia32_sys_call_table;
            } else {
                prev_ia32_sys_call_table = ia32_sys_call_table;
            }
            ia32_sys_call_table = local_ia32_sys_call_table;
        }

        return true;
    }

    return false;
}

static int get_current_syscall_hooks(struct syscall_hooks *hooks)
{
    int ret = 0;

    if (!get_syscall_tbl()) {
        return -ENOENT;
    }
    if (!sys_call_table) {
        mutex_unlock(&lookup_lock);
        return -ENOENT;
    }
    if (sys_call_table != prev_sys_call_table) {
        ret = 1;
    }

    if (!hooks) {
        goto out_unlock;
    }

    memset(hooks, 0, sizeof(*hooks));

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
#ifdef __NR_rename
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

out_unlock:
    mutex_unlock(&lookup_lock);

    return 0;
}


static void init_our_syscall_hooks(void)
{
    memset(&in_our_kmod, 0, sizeof(in_our_kmod));

#define copy_hook(NAME) \
    in_our_kmod.NAME = dynsec_##NAME

    copy_hook(delete_module);
    copy_hook(open);
    copy_hook(creat);
    copy_hook(openat);
#ifdef __NR_openat2
    copy_hook(openat2);
#endif /* __NR_openat2 */
    copy_hook(rename);
#ifdef __NR_rename
    copy_hook(renameat);
#endif /* __NR_renameat */
#ifdef __NR_renameat2
    copy_hook(renameat2);
#endif /* __NR_renameat2 */
    copy_hook(mkdir);
    copy_hook(mkdirat);
    copy_hook(unlink);
    copy_hook(unlinkat);
    copy_hook(rmdir);
    copy_hook(symlink);
    copy_hook(symlinkat);
    copy_hook(link);
    copy_hook(linkat);
#undef copy_syscall

    ours = &in_our_kmod;
}

bool ec_set_page_state_rw(void **tbl, unsigned long *old_page_rw)
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

void ec_restore_page_state(void **tbl, unsigned long page_rw)
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

static void __set_syscall_table(struct syscall_hooks *hooks, void **table)
{
    unsigned long flags;
    unsigned long page_rw_set;

#define set_syscall(NAME)                       \
    do {                                        \
        if (hooks->NAME)                        \
            table[__NR_##NAME] = hooks->NAME;   \
    } while (0)

    local_irq_save(flags);
    local_irq_disable();
    get_cpu();
    GPF_DISABLE();

    if (ec_set_page_state_rw(table, &page_rw_set))
    {

    set_syscall(delete_module);
    set_syscall(open);
    set_syscall(creat);
    set_syscall(openat);
#ifdef __NR_openat2
    set_syscall(openat2);
#endif /* __NR_openat2 */
    set_syscall(rename);
#ifdef __NR_rename
    set_syscall(renameat);
#endif /* __NR_renameat */
#ifdef __NR_renameat2
    set_syscall(renameat2);
#endif /* __NR_renameat2 */
    set_syscall(mkdir);
    set_syscall(mkdirat);
    set_syscall(unlink);
    set_syscall(unlinkat);
    set_syscall(rmdir);
    set_syscall(symlink);
    set_syscall(symlinkat);
    set_syscall(link);
    set_syscall(linkat);

        ec_restore_page_state(table, page_rw_set);
    }

    GPF_ENABLE();
    put_cpu();
    local_irq_restore(flags);

#undef set_syscall
}


static int syscall_changed(const struct syscall_hooks *old_hooks)
{
    int ret = 0;
    int diff = 0;

    char *modname = NULL;
    char *symname = NULL;
    char *old_modname = NULL;
    char *old_symname = NULL;
    struct syscall_hooks *curr_hooks = NULL;

    curr_hooks = kzalloc(sizeof(*curr_hooks), GFP_KERNEL);

    if (!curr_hooks) {
        return -ENOMEM;
    }

    modname = kzalloc(MODULE_NAME_LEN + 1, GFP_KERNEL);
    symname = kzalloc(KSYM_NAME_LEN + 1, GFP_KERNEL);
    old_modname = kzalloc(MODULE_NAME_LEN + 1, GFP_KERNEL);
    old_symname = kzalloc(KSYM_NAME_LEN + 1, GFP_KERNEL);

    ret = get_current_syscall_hooks(curr_hooks);
    if (ret < 0) {
        goto out;
    }
    if (ret > 0) {
        pr_info("Entire Syscall Table Changed\n");
    }

#define cmp_syscall(NAME) \
    do { \
        if (old_hooks->NAME != curr_hooks->NAME) { \
            ret += 1; \
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

    cmp_syscall(delete_module);
    cmp_syscall(open);
    cmp_syscall(creat);
    cmp_syscall(openat);
#ifdef __NR_openat2
    cmp_syscall(openat2);
#endif /* __NR_openat2 */
    cmp_syscall(rename);
#ifdef __NR_rename
    cmp_syscall(renameat);
#endif /* __NR_renameat */
#ifdef __NR_renameat2
    cmp_syscall(renameat2);
#endif /* __NR_renameat2 */
    cmp_syscall(mkdir);
    cmp_syscall(mkdirat);
    cmp_syscall(unlink);
    cmp_syscall(unlinkat);
    cmp_syscall(rmdir);
    cmp_syscall(symlink);
    cmp_syscall(symlinkat);
    cmp_syscall(link);
    cmp_syscall(linkat);

#undef cmp_syscall

    if (diff > 0) {
        ret = diff;
    }

out:
    kfree(curr_hooks);
    kfree(modname);
    kfree(symname);
    kfree(old_modname);
    kfree(old_symname);

    return ret;
}

bool register_preaction_hooks(void)
{
    int ret;
    char *modname;
    char *symname;

    modname = kzalloc(MODULE_NAME_LEN + 1, GFP_KERNEL);
    symname = kzalloc(KSYM_NAME_LEN + 1, GFP_KERNEL);
    orig = NULL;
    ours = NULL;

    ret = get_current_syscall_hooks(&in_kernel);
    if (ret < 0) {
        pr_info("Failed to grab syscall hooks: %d\n", ret);
        return false;
    }

    if (ret > 0) {
        pr_info("Syscall Table Has Been Modified\n");
    }

    init_our_syscall_hooks();

    if (in_kernel.delete_module) {
        dynsec_module_name((unsigned long)in_kernel.delete_module,
                           modname, MODULE_NAME_LEN);
        if (symname) {
            dynsec_lookup_symbol_name((unsigned long)in_kernel.delete_module,
                                      symname);
        }
        pr_info("%s symbol:%s modname:%s\n", __func__, symname, modname);
    }

    if (ours) {
        mutex_lock(&lookup_lock);
        if (sys_call_table) {
            orig = &in_kernel;
            __set_syscall_table(ours, sys_call_table);
        }
        mutex_unlock(&lookup_lock);

        if (orig) {
            syscall_changed(orig);
        }
    }

    kfree(modname);
    kfree(symname);
    return true;
}


void preaction_hooks_shutdown(void)
{
    if (ours) {
        syscall_changed(ours);
        ours = NULL;
    }

    if (orig) {
        mutex_lock(&lookup_lock);
        if (sys_call_table) {
            orig = NULL;
            __set_syscall_table(&in_kernel, sys_call_table);
        }
        mutex_unlock(&lookup_lock);
    }
}
