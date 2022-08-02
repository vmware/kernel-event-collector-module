// SPDX-License-Identifier: GPL-2.0
// Copyright 2022 VMware, Inc. All rights reserved.

#include <linux/err.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/sched.h>
#include <linux/path.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 10, 0)
#include <linux/sched/task.h>
#include <linux/sched/mm.h>
#endif

#include "dynsec.h"
#include "stall_tbl.h"
#include "stall_reqs.h"
#include "config.h"
#include "task_utils.h"
#include "path_utils.h"
#include "protect.h"

#define match_path_flags(flags) (\
    (flags) & ( DYNSEC_MATCHING_PATH_EQ \
        | DYNSEC_MATCHING_PATH_CONTAINS \
        | DYNSEC_MATCHING_PATH_STARTS_WITH \
        | DYNSEC_MATCHING_PATH_ENDS_WITH \
))

static DEFINE_MUTEX(protect_lock);

struct protect {
    spinlock_t lock;
    struct list_head list;
};

struct protect_entry {
    struct list_head list;

    u64 match_flags;

    long unsigned int blob_len;
    union {
        char *blob;
    };
};

static struct protect protect;

// May switch to a RCU oriented list
static inline unsigned long protect_read_lock(unsigned long flags)
{
    spin_lock_irqsave(&protect.lock, flags);
    return flags;
}
static inline void protect_read_unlock(unsigned long flags)
{
    spin_unlock_irqrestore(&protect.lock, flags);
}

static inline unsigned long protect_write_lock(unsigned long flags)
{
    spin_lock_irqsave(&protect.lock, flags);
    return flags;
}
static inline void protect_write_unlock(unsigned long flags)
{
    spin_unlock_irqrestore(&protect.lock, flags);
}

static void protect_free_entries(void)
{
    struct protect_entry *entry, *tmp;
    unsigned long flags = 0;

    flags = protect_write_lock(flags);
    list_for_each_entry_safe(entry, tmp, &protect.list, list) {
        list_del_init(&entry->list);
        if (entry->blob) {
            kfree(entry->blob);
            entry->blob = NULL;
        }
        kfree(entry);
    }
    protect_write_unlock(flags);
}

void dynsec_disable_protect(void)
{
    global_config.protect_mode = DEFAULT_DISABLED;
}

void dynsec_enable_protect(void)
{
    global_config.protect_mode = DEFAULT_ENABLED;
}

bool dynsec_is_protect_enabled(void)
{
    return protect_mode_enabled();
}

void dynsec_protect_shutdown(void)
{
    dynsec_disable_protect();

    protect_free_entries();
}

int dynsec_protect_init(void)
{
    static bool initialized = false;

    if (!initialized) {
        initialized = true;

        spin_lock_init(&protect.lock);
        INIT_LIST_HEAD(&protect.list);

        if (protect_on_connect) {
            dynsec_enable_protect();
        } else {
            dynsec_disable_protect();
        }
    }

    return 0;
}

static bool dynsec_may_enable_protect(gfp_t mode)
{
    if (bypass_mode_enabled()) {
        return false;
    }

    if (!stall_tbl_enabled(stall_tbl)) {
        return false;
    }

    if (current->ptrace) {
        return false;
    }

    // Eventually only allow this depending on global config options
    // that makes sense.
    return true;
}

static bool dynsec_clear_protect(void)
{
    if (dynsec_is_protect_enabled())
    {
        return false;
    }

    protect_free_entries();

    return true;
}

int handle_protect_on_open(const struct task_struct *task)
{
    if (task && task->ptrace) {
        if (protect_mode_enabled()) {
            dynsec_disable_protect();
        }
    }

    return 0;
}


// Caller must hold protect.list lock
static struct protect_entry *find_protect_entry_eq(const struct protect_entry *new_entry)
{
    struct protect_entry *entry, *tmp;

    list_for_each_entry_safe(entry, tmp, &protect.list, list) {
        if (unlikely(new_entry == entry)) {
            return entry;
        }
        if (new_entry->blob_len == entry->blob_len &&
            new_entry->match_flags == entry->match_flags &&
            new_entry->blob && entry->blob &&
            strcmp(new_entry->blob, entry->blob) == 0)
        {
            return entry;
        }
    }

    return NULL;
}

static int protect_insert_entry(const struct dynsec_match *match)
{
    struct protect_entry *entry = NULL;
    size_t blob_len = 0;
    unsigned long flags = 0;
    struct protect_entry *found_entry = NULL;

    if (!match || !match->match_flags) {
        return -EINVAL;
    }

    if (!match_path_flags(match->match_flags)) {
        return -EINVAL;
    }

    blob_len = strlen(match->path);
    if (!blob_len || blob_len > PATH_MAX) {
        return -EINVAL;
    }
    // Ensure matching string is of decent length
    if (blob_len <= 4 &&
        (match->match_flags & DYNSEC_MATCHING_PATH_CONTAINS)) {
        return -EINVAL;
    }

    // Not a bug but there's no point in having both options set.
    if (match->match_flags & DYNSEC_MATCHING_PATH_STARTS_WITH) {
        // These match options don't work with each other
        if (match->match_flags & DYNSEC_MATCHING_PATH_ENDS_WITH) {
            return -EINVAL;
        }

        // Paths must start with a '/'
        if (match->path[0] != '/') {
            return -EINVAL;
        }
    }
    else if (match->match_flags & DYNSEC_MATCHING_PATH_ENDS_WITH) {
        // Normalized paths do not end with a '/'
        if (match->path[blob_len - 1] == '/') {
            return -EINVAL;
        }
    }

    // Alright path/blob requested to match passed basic checks
    // Attempt to insert it.

    entry = kzalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry) {
        return -ENOMEM;
    }
    INIT_LIST_HEAD(&entry->list);
    entry->match_flags = match->match_flags;

    if (match_path_flags(match->match_flags)) {
        entry->blob_len = blob_len;
        entry->blob = kstrdup(match->path, GFP_KERNEL);

        if (!entry->blob) {
            kfree(entry);
            return -ENOMEM;
        }
    } else {
        kfree(entry);
        return -EINVAL;
    }

    // Check if there's already existing entry before inserting
    mutex_lock(&protect_lock);
    flags = protect_read_lock(flags);
    found_entry = find_protect_entry_eq(entry);
    protect_read_unlock(flags);

    if (found_entry) {
        if (entry->blob) {
            kfree(entry->blob);
            entry->blob = NULL;
        }
        kfree(entry);
        goto out_unlock;
    }

    // Insert entry to either head or tail of list
    flags = protect_write_lock(flags);
    if (match_path_flags(match->match_flags)) {
        if (match->match_flags & DYNSEC_MATCHING_PATH_CONTAINS) {
            list_add_tail(&entry->list, &protect.list);
        } else {
            list_add(&entry->list, &protect.list);
        }
    }
    protect_write_unlock(flags);

out_unlock:
    mutex_unlock(&protect_lock);

    return 0;
}

int handle_protect_ioc(unsigned long arg)
{
    int ret = -EINVAL;

    struct dynsec_protect_ioc_hdr hdr;
    const char __user*p = (const char *)arg;

    if (copy_from_user(&hdr, (void *)p, sizeof(hdr))) {
        return -EFAULT;
    }
    p += sizeof(hdr);

    switch (hdr.protect_flags)
    {
    case DYNSEC_PROTECT_DISABLE: {
        lock_config();
        dynsec_disable_protect();
        unlock_config();
        ret = 0;
        break;
    }
    case DYNSEC_PROTECT_CLEAR:
        if (!dynsec_is_protect_enabled()) {
            dynsec_clear_protect();
            ret = 0;
        }
        break;
    case (DYNSEC_PROTECT_DISABLE|DYNSEC_PROTECT_CLEAR):
        dynsec_disable_protect();
        mutex_lock(&protect_lock);
        dynsec_clear_protect();
        mutex_unlock(&protect_lock);

        ret = 0;
        break;

    case DYNSEC_PROTECT_ADD: {
        struct dynsec_match *match = NULL;
        unsigned int size = hdr.size;

        if (!hdr.size || hdr.size < sizeof(hdr)) {
            break;
        }
        size -= sizeof(hdr);
        // More for verification
        if (size != sizeof(struct dynsec_match)) {
            break;
        }

        match = kmalloc(size, GFP_KERNEL);
        if (!match) {
            ret = -ENOMEM;
            break;
        }
        if (copy_from_user(match, (void *)p, size)) {
            kfree(match);
            ret = -EFAULT;
            break;
        }

        ret = protect_insert_entry(match);
        kfree(match);
        break;
    }

    case DYNSEC_PROTECT_ENABLE:
        if (current->ptrace) {
            ret = -EACCES;
            break;
        }

        lock_config();
        if (dynsec_may_enable_protect(GFP_KERNEL)) {
            dynsec_enable_protect();
            if (dynsec_is_protect_enabled()) {
                ret = 0;
            }
        }
        unlock_config();
        break;

    default:
        break;
    }

    return ret;
}

static char *get_task_exe(struct task_struct *task,
                          char *buf, int buflen,
                          size_t *path_len,
                          gfp_t mode)
{
    struct mm_struct *mm = NULL;
    struct file *exe_file = NULL;
    int len = 0;

    if (path_len) {
        *path_len = 0;
    }

    if (!task || !task->mm ||
        !pid_alive(task) || task_is_exiting(task)) {
        return NULL;
    }
    if (!buf || !buflen) {
        return NULL;
    }

    if (has_gfp_atomic(mode)) {
        exe_file = task->mm->exe_file;
    } else {
        mm = get_task_mm(task);
        if (mm) {
            exe_file = dynsec_get_mm_exe_file(mm);
            mmput(mm);
        }
    }

    if (!IS_ERR_OR_NULL(exe_file)) {
        char *p = dynsec_d_path(&exe_file->f_path, buf,
                                buflen);

        if (!has_gfp_atomic(mode)) {
            fput(exe_file);
        }

        if (IS_ERR_OR_NULL(p) || !*p) {
            return NULL;
        }

        len = strlen(p);
        if (likely(p != buf)) {
            memmove(buf, p, len);
        }
        buf[len] = 0;
        if (path_len) {
            *path_len = len;
        }

        return buf;
    }

    return NULL;
}

// Helper to more easily order the string match operations
// from cheapest to most expensive.
static u64 __protect_match_path(const struct protect_entry *entry,
                                const char *path, size_t path_len)
{
    if (unlikely(!match_path_flags(entry->match_flags))) {
        return 0;
    }
    if (!entry->blob_len || !entry->blob || !entry->blob[0]) {
        return 0;
    }

    // Path can't be smaller than match's required length
    if (path_len < entry->blob_len) {
        return 0;
    }

    // Matches turn into strcmp if lengths are equal
    if (path_len == entry->blob_len) {
        if (strcmp(path, entry->blob) == 0) {
            pr_debug("%s: matched eq %s\n", __func__, entry->blob);
            return entry->match_flags;
        }
        return 0;
    }

    if (entry->match_flags & DYNSEC_MATCHING_PATH_STARTS_WITH) {
        if (strncmp(path, entry->blob, entry->blob_len) == 0) {
            pr_debug("%s: matched starts_with %s\n", __func__, entry->blob);
            return entry->match_flags;
        }
    }
    else if (entry->match_flags & DYNSEC_MATCHING_PATH_ENDS_WITH) {
        const char *path_pos = path + (path_len - entry->blob_len);

        if (strncmp(path_pos, entry->blob, entry->blob_len) == 0) {
            pr_debug("%s: matched ends_with %s\n", __func__, entry->blob);
            return entry->match_flags;
        }
    }

    if (entry->match_flags & DYNSEC_MATCHING_PATH_CONTAINS) {
        // Find the first substring occurence
        if (strstr(path, entry->blob) != NULL) {
            pr_debug("%s: matched substr %s\n", __func__, entry->blob);
            return entry->match_flags;
        }
    }

    return 0;
}

static int task_exe_matches(struct task_struct *task,
                            u64 *match_flags, gfp_t mode)
{
    struct protect_entry *entry, *tmp;
    char *buf, *exe_path = NULL;
    size_t path_len = 0;
    int ret = -ENOENT;
    unsigned long flags = 0;
    u64 local_match_flags = 0;

    if (!task || !task->mm ||
        !pid_alive(task) || task_is_exiting(task)) {
        return -EINVAL;
    }

    exe_path = kzalloc(PATH_MAX, mode);
    if (!exe_path) {
        return -ENOMEM;
    }

    buf = get_task_exe(task, exe_path, PATH_MAX, &path_len, mode);
    if (!buf || buf != exe_path) {
        kfree(exe_path);
        return -ENOENT;
    }

    flags = protect_read_lock(flags);
    list_for_each_entry_safe(entry, tmp, &protect.list, list) {
        local_match_flags = __protect_match_path(entry, exe_path, path_len);

        if (local_match_flags) {
            ret = 0;
            break;
        }
    }
    protect_read_unlock(flags);

    if (!ret) {
        if (match_flags) {
            *match_flags = local_match_flags;
        }
    }

    if (exe_path) {
        kfree(exe_path);
        exe_path = NULL;
    }

    return ret;
}

int dynsec_may_protect_kill(const struct task_struct *target, int sig)
{
    int err = 0;

    if (!target) {
        return 0;
    }

    if (!stall_tbl_enabled(stall_tbl)) {
        return 0;
    }
    if (!dynsec_is_protect_enabled()) {
        return 0;
    }

    if (task_in_connected_tgid(target)) {
        u64 match_flags = 0;

        // No point in trying to protect if already exiting
        if (task_is_exiting(target)) {
            return 0;
        }

        // Check if likely sender has permission to send a signal?
        // Perhaps only search if *_MAY_SIGNAL_CLIENT is set a
        // global mask?
        err = task_exe_matches((struct task_struct *)current,
                               &match_flags, GFP_ATOMIC);
        if (!err) {
            if (match_flags & DYNSEC_MATCHING_MAY_SIGNAL_CLIENT) {
                return 0;
            }
        }

        // Perhaps allow another protected task on a certain signal
        // disable protected mode.
        return 1;
    }
    // Check if the target is in our set of matchable protected processes
    else {
        err = task_exe_matches((struct task_struct *)target,
                                   NULL, GFP_ATOMIC);
        if (!err) {
            return 1;
        }
    }

    return 0;
}

int dynsec_may_protect_ptrace(const struct task_struct *src,
                              const struct task_struct *target)
{
    int ret = 0;

    if (!stall_tbl_enabled(stall_tbl)) {
        return 0;
    }

    if (!dynsec_is_protect_enabled()) {
        return 0;
    }

    // Target seems to matter most
    if (task_in_connected_tgid(target)) {
        ret = 1;
    }
    // Protecting ptrace that is a non-connected program is tricky.
    // We can softly attempt to protect them still.
    else {
        int err = task_exe_matches((struct task_struct *)target, NULL, GFP_ATOMIC);

        if (!err) {
            ret = 1;
        }
    }

    return ret;
}
