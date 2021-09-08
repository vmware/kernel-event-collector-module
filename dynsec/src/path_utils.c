// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 VMware, Inc. All rights reserved.

#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/limits.h>

#include "symbols.h"
#include "path_utils.h"
#include "dynsec.h"

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

// Would be nice to provide on task dumps
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

char *dynsec_build_path(struct path *path, struct dynsec_file *file, gfp_t mode)
{
    char *buf = NULL;
    char *p;
    size_t len;

    if (!path) {
        goto out;
    }

    buf = kzalloc(PATH_MAX, mode);
    if (!buf) {
        goto out;
    }

    if (!has_gfp_atomic(mode))
        path_get(path);
    p = dynsec_d_path(path, buf, PATH_MAX);
    if (!has_gfp_atomic(mode))
        path_put(path);

    if (IS_ERR_OR_NULL(p) || !*p) {
        goto out_err;
    }

    len = strlen(p);
    if (likely(p != buf)) {
        memmove(buf, p, len);
    }
    buf[len] = 0;
    if (file) {
        file->path_size = len + 1;
        file->attr_mask |= DYNSEC_FILE_ATTR_PATH_FULL;
    }

out:
    return buf;

out_err:
    kfree(buf);
    buf = NULL;
    goto out;
}

char *dynsec_build_path_greedy(struct path *path, struct dynsec_file *file, gfp_t mode)
{
    char *buf = NULL;
    char *p;
    size_t len;
    size_t alloc_size = DEFAULT_PATH_ALLOC_SZ;

    if (!path) {
        goto out;
    }

retry_d_path:
    buf = kmalloc(alloc_size, mode);
    if (!buf) {
        goto out;
    }

    if (!has_gfp_atomic(mode))
        path_get(path);
    p = dynsec_d_path(path, buf, alloc_size);
    if (!has_gfp_atomic(mode))
        path_put(path);

    if (IS_ERR_OR_NULL(p) || !*p) {
        if (alloc_size >= PATH_MAX) {
            goto out_err;
        }
        kfree(buf);
        alloc_size = PATH_MAX;
        goto retry_d_path;
    }

    len = strlen(p);
    if (likely(p != buf)) {
        memmove(buf, p, len);
    }
    buf[len] = 0;
    if (file) {
        file->path_size = len + 1;
        file->attr_mask |= DYNSEC_FILE_ATTR_PATH_FULL;
    }

out:
    return buf;

out_err:
    kfree(buf);
    buf = NULL;
    goto out;
}

char *dynsec_build_dentry(struct dentry *dentry, struct dynsec_file *file, gfp_t mode)
{
    char *buf = NULL;
    char *p;
    size_t len;
    size_t alloc_size = DEFAULT_PATH_ALLOC_SZ;

    if (!dentry) {
        goto out;
    }

retry_dentry_path:
    buf = kmalloc(alloc_size, mode);
    if (!buf) {
        goto out;
    }

    if (!has_gfp_atomic(mode))
        dget(dentry);
    p = dynsec_dentry_path(dentry, buf, alloc_size);
    if (!has_gfp_atomic(mode))
        dput(dentry);

    if (IS_ERR_OR_NULL(p) || !*p) {
        if (alloc_size >= PATH_MAX) {
            goto out_err;
        }
        kfree(buf);
        alloc_size = PATH_MAX;
        goto retry_dentry_path;
    }

    len = strlen(p);
    if (likely(p != buf)) {
        memmove(buf, p, len);
    }
    buf[len] = 0;
    if (file) {
        file->path_size = len + 1;
        file->attr_mask |= DYNSEC_FILE_ATTR_PATH_DENTRY;
    }

out:
    return buf;

out_err:
    kfree(buf);
    buf = NULL;
    goto out;
}
