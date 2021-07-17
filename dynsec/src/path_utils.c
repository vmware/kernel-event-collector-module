// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 VMware, Inc. All rights reserved.

#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/version.h>

#include "symbols.h"
#include "path_utils.h"

struct path_symz {
    char *(* dentry_path_raw)(const struct dentry *dentry, char *buf, int buflen);
    char *(* dentry_path)(const struct dentry *dentry, char *buf, int buflen);
    char *(* d_absolute_path)(const struct path *path, char *buf, int buflen);
    char *(* d_path)(const struct path *path, char *buf, int buflen);

    // For custom pwdfs or rootfs
    char *(* __d_path)(const struct path *path, const struct path *root, char *buf, int buflen);
    // For safety checks
    bool (* current_chrooted)(void);
};
// Potentially manually simulate d_absolute_path for 2.6.32 kernels

struct path_symz path_syms;

bool dynsec_path_utils_init(void)
{
    memset(&path_syms, 0, sizeof(path_syms));

    // Might as well scrape possible path options
    find_symbol_indirect("dentry_path_raw", (unsigned long *)&path_syms.dentry_path_raw);
    find_symbol_indirect("dentry_path", (unsigned long *)&path_syms.dentry_path);

    find_symbol_indirect("d_absolute_path", (unsigned long *)&path_syms.d_absolute_path);
    find_symbol_indirect("d_path", (unsigned long *)&path_syms.d_path);

    find_symbol_indirect("__d_path", (unsigned long *)&path_syms.__d_path);
    find_symbol_indirect("current_chrooted", (unsigned long *)&path_syms.current_chrooted);

    if (path_syms.dentry_path) {
        return true;
    }

    return false;
}

bool dynsec_current_chrooted(void)
{
    if (likely(path_syms.current_chrooted)) {
        return path_syms.current_chrooted();
    }

    return true;
}

char *dynsec_dentry_path(const struct dentry *dentry, char *buf, int buflen)
{
    if (path_syms.dentry_path_raw) {
        return path_syms.dentry_path_raw(dentry, buf, buflen);
    }

    if (path_syms.dentry_path) {
        return path_syms.dentry_path(dentry, buf, buflen);
    }

    return NULL;
}

char *dynsec_d_path(const struct path *path, char *buf, int buflen)
{
    if (path_syms.d_absolute_path) {
        return path_syms.d_absolute_path(path, buf, buflen);
    }

    if (path_syms.d_path) {
        return path_syms.d_path(path, buf, buflen);
    }

    return NULL;
}

// Test this for stability before future use
char *dynsec_path_safeish(const struct path *path, char *buf, int buflen)
{
    if (dynsec_current_chrooted()) {
        // Potentialy secure dcache lock or rootfs lock to do dynsec_d_path ?
        return dynsec_dentry_path(path->dentry, buf, buflen);
    }

    return dynsec_d_path(path, buf, buflen);
}

#define PATH_SZ 4096

char *dynsec_build_path(struct path *path, uint16_t *size, gfp_t mode)
{
    char *buf = NULL;
    char *p;
    size_t len;

    if (!path) {
        goto out;
    }

    // Optionally provide both mnt_ns and global paths if 
    // path->mnt in init_task's mnt_ns.
    // if (!is_init_mnt_ns(current)) {
    //     // still need to check if exists in init_task mnt_ns
    //     return dynsec_build_dentry(path->dentry, size, mode);
    // }

    buf = kmalloc(PATH_SZ, mode);
    if (!buf) {
        goto out;
    }

    if (!(mode & __GFP_ATOMIC))
        path_get(path);
    p = dynsec_d_path(path, buf, PATH_SZ);
    if (!(mode & __GFP_ATOMIC))
        path_put(path);

    if (IS_ERR_OR_NULL(p) || !*p) {
        goto out_err;
    }

    len = strlen(p);
    if (likely(p != buf)) {
        memmove(buf, p, len);
    }
    buf[len] = 0;
    if (size) {
        *size = len + 1;
    }

out:
    return buf;

out_err:
    kfree(buf);
    buf = NULL;
    goto out;
}

// On RHEL7+ check if init_task->ns_proxy->mnt_ns NULL or current->ns_proxy->mnt_ns

char *dynsec_build_dentry(struct dentry *dentry, uint16_t *size, gfp_t mode)
{
    char *buf = NULL;
    char *p;
    size_t len;

    if (!dentry) {
        goto out;
    }

    buf = kmalloc(PATH_SZ, mode);
    if (!buf) {
        goto out;
    }

    if (!(mode & __GFP_ATOMIC))
        dget(dentry);
    p = dynsec_dentry_path(dentry, buf, PATH_SZ);
    if (!(mode & __GFP_ATOMIC))
        dput(dentry);

    if (IS_ERR_OR_NULL(p) || !*p) {
        goto out_err;
    }

    len = strlen(p);
    if (likely(p != buf)) {
        memmove(buf, p, len);
    }
    buf[len] = 0;
    if (size) {
        *size = len + 1;
    }

out:
    return buf;

out_err:
    kfree(buf);
    buf = NULL;
    goto out;
}
