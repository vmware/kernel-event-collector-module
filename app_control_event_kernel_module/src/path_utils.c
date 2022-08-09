// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 VMware, Inc. All rights reserved.

#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/limits.h>

#include <linux/namei.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/stat.h>
#include <linux/uaccess.h>

#include "symbols.h"
#include "path_utils.h"
#include "dynsec.h"
#include "fs_utils.h"

#define DYNSEC_PATH_MAX (PATH_MAX)

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
    BUILD_BUG_ON(DYNSEC_PATH_MAX <= DEFAULT_PATH_ALLOC_SZ);
    BUILD_BUG_ON(DYNSEC_PATH_MAX > PAGE_SIZE * 2);
    BUILD_BUG_ON(DEFAULT_PATH_ALLOC_SZ >= 2048);
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

// Helper to use when ENAMETOOLONG is returned
static const char *find_trunc_path(const char *buf, int buflen)
{
    int i;

    if (unlikely(!buf)) {
        return NULL;
    }
    for (i = 0; i < buflen && i <= NAME_MAX + 1; i++) {
        if (buf[i]) {
            return &buf[i];
        }
    }
    return NULL;
}

static char *__dynsec_build_path_greedy(struct path *path,
                               struct dynsec_file *file, gfp_t mode)
{
    size_t alloc_size = DEFAULT_PATH_ALLOC_SZ;
    char *buf = NULL;
    const char *p = NULL;
    size_t len = 0;

    if (!path) {
        return NULL;
    }
    buf = kzalloc(alloc_size, mode);
    if (!buf) {
        return NULL;
    }

    // Build path with local buffer
    if (!has_gfp_atomic(mode))
        path_get(path);
    p = dynsec_d_path(path, buf, alloc_size);
    if (!has_gfp_atomic(mode))
        path_put(path);

    // If no issues duplicate the string and return
    if (!IS_ERR_OR_NULL(p)) {
        len = strlen(p);
        strlcpy(buf, p, len + 1);
        if (file) {
            file->path_size = len + 1;
            file->attr_mask |= DYNSEC_FILE_ATTR_PATH_FULL;
        }
        return buf;

    } else if (!p || PTR_ERR(p) != -ENAMETOOLONG) {
        goto out_err;
    }

    // Local buffer was too small. Retry with a large buffer.
    alloc_size = DYNSEC_PATH_MAX;
    buf = krealloc(buf, alloc_size, mode);
    if (!buf) {
        return NULL;
    }
    // Retry path with dynamic buffer
    if (!has_gfp_atomic(mode))
        path_get(path);
    p = dynsec_d_path(path, buf, alloc_size);
    if (!has_gfp_atomic(mode))
        path_put(path);
    if (IS_ERR_OR_NULL(p)) {
        // Handle the case of real truncation
        if (p && PTR_ERR(p) == -ENAMETOOLONG) {
            p = find_trunc_path(buf, alloc_size);
            if (p) {
                if (file) {
                    file->attr_mask |= DYNSEC_FILE_ATTR_PATH_TRUNC;
                }
                goto found;
            }
        }
        goto out_err;
    } else {
        if (file) {
            file->attr_mask |= DYNSEC_FILE_ATTR_PATH_FULL;
        }
    }

found:
    // Fix up path to be at start of buffer
    len = strlen(p);
    if (likely(p > buf)) {
        memmove(buf, p, len);
    }
    buf[len] = 0;
    if (file) {
        file->path_size = len + 1;
    }
    return buf;

out_err:
    kfree(buf);
    return NULL;
}

char *dynsec_build_path(struct path *path, struct dynsec_file *file, gfp_t mode)
{
    return __dynsec_build_path_greedy(path, file, mode);
}

char *dynsec_build_dentry(struct dentry *dentry, struct dynsec_file *file, gfp_t mode)
{
    size_t alloc_size = DEFAULT_PATH_ALLOC_SZ;
    char *buf = NULL;
    const char *p = NULL;
    size_t len = 0;

    if (!dentry) {
        return NULL;
    }
    buf = kzalloc(alloc_size, mode);
    if (!buf) {
        return NULL;
    }

    // Build path with local buffer
    if (!has_gfp_atomic(mode))
        dget(dentry);
    p = dynsec_dentry_path(dentry, buf, alloc_size);
    if (!has_gfp_atomic(mode))
        dput(dentry);

    // If no issues duplicate the string and return
    if (!IS_ERR_OR_NULL(p)) {
        len = strlen(p);
        strlcpy(buf, p, len + 1);
        if (file) {
            file->path_size = len + 1;
            file->attr_mask |= DYNSEC_FILE_ATTR_PATH_DENTRY;
        }
        return buf;

    } else if (!p || PTR_ERR(p) != -ENAMETOOLONG) {
        goto out_err;
    }

    // Local buffer was too small. Retry with a large buffer.
    alloc_size = DYNSEC_PATH_MAX;
    buf = krealloc(buf, alloc_size, mode);
    if (!buf) {
        return NULL;
    }
    // Retry path with dynamic buffer
    if (!has_gfp_atomic(mode))
        dget(dentry);
    p = dynsec_dentry_path(dentry, buf, alloc_size);
    if (!has_gfp_atomic(mode))
        dput(dentry);
    if (IS_ERR_OR_NULL(p)) {
        // Handle the case of real truncation
        if (p && PTR_ERR(p) == -ENAMETOOLONG) {
            p = find_trunc_path(buf, alloc_size);
            if (p) {
                if (file) {
                    file->attr_mask |= DYNSEC_FILE_ATTR_PATH_TRUNC;
                }
                goto found;
            }
        }
        goto out_err;
    } else {
        if (file) {
            file->attr_mask |= DYNSEC_FILE_ATTR_PATH_DENTRY;
        }
    }

found:
    // Fix up path to be at start of buffer
    len = strlen(p);
    if (likely(p > buf)) {
        memmove(buf, p, len);
    }
    buf[len] = 0;
    if (file) {
        file->path_size = len + 1;
    }
    return buf;

out_err:
    kfree(buf);
    return NULL;
}

static char *dynsec_prepend_dfd(int dfd, char *pathbuf, int buflen,
                                int *err)
{
    char *dfd_path = NULL;
    struct file *dfd_file = NULL;

    if (dfd < 0 || buflen <= 0) {
        return NULL;
    }
    if (err) {
        *err = 0;
    }

    dfd_file = fget(dfd);
    if (IS_ERR_OR_NULL(dfd_file)) {
        return NULL;
    }

    // Must be a directory
    if (!dfd_file->f_path.dentry ||
        !dfd_file->f_path.dentry->d_inode ||
        !S_ISDIR(dfd_file->f_path.dentry->d_inode->i_mode)) {
        if (err) {
            *err = -ENOTDIR;
        }
        fput(dfd_file);
        return NULL;
    }

    dfd_path = dynsec_d_path(&dfd_file->f_path, pathbuf, buflen);
    fput(dfd_file);

    if (IS_ERR_OR_NULL(dfd_path)) {
        if (dfd_path && PTR_ERR(dfd_path) == -ENAMETOOLONG) {
            if (err) {
                *err = -ENAMETOOLONG;
            }
            dfd_path = (char *)find_trunc_path(pathbuf, buflen);
        } else {
            dfd_path = NULL;
        }
    }
    if (dfd_path && !*dfd_path) {
        dfd_path = NULL;
    }

    return dfd_path;
}

// Copies the last component from a raw path to a name buffer.
// Returns -ENAMETOOLONG if last component is too long.
// Assumes raw path has had `/` chopped off.
static char *parse_last_component(char *namebuf, size_t namebuf_sz,
                                  char *pathbuf, int input_len)
{
    char *p;
    char *comp;
    const char *name_start;
    const char *name_end;
    int component_len = 0;

    if (!namebuf || !pathbuf ||
        input_len <= 0 || namebuf_sz <= 2) {
        return NULL;
    }

    name_start = namebuf;
    name_end = name_start + namebuf_sz - 2;

    // Likely last non-nul character from raw input buffer
    p = pathbuf + input_len - 1;
    // Last non-nul position in component/name buffer
    comp = (char *)name_end;

    memset(namebuf, 0, namebuf_sz);

    while (1) {
        if (p < pathbuf || *p == '/') {
            // Don't remove component if `.` or `..`
            if (component_len == 1 && *name_end == '.') {
                break;
            } else if (component_len == 2 &&
                       *name_end == '.' && *(name_end - 1) == '.') {
                break;
            }
            // Handle the normal case relative path input
            else {
                // Might as well just clear out the input buffer
                if (p < pathbuf) {
                    memset(pathbuf, 0, input_len);
                }
                // nul terminate just the `/` should be okay
                else {
                    *p = '\0';
                }
                // Adjust over decrement
                comp++;
                return comp;
            }
        }
        // Find first non-null character
        if (!*p) {
            p--;
            continue;
        }

        // Name too long
        if (comp < name_start) {
            return ERR_PTR(-ENAMETOOLONG);
        }

        // Copy character over
        *comp-- = *p--;
        component_len += 1;
    }

    return NULL;
}

//
// Returns 0 if no truncation
// Returns negative if error
// Return positive value if trunation
//
static int append_component(const char *bufhead, size_t bufsize,
                            char *pos, const char *component)
{
    char *buftail;
    size_t component_len;
    size_t len;
    int ret = 0;

    if (!bufhead || !pos) {
        return -EINVAL;
    }
    if (pos < bufhead || pos >= bufhead + bufsize) {
        return -EINVAL;
    }
    buftail = (char *)bufhead + bufsize -1;

    len = strlen(pos);
    // If we went passed the end of the buffer
    // truncate since already violated boundaries
    if (unlikely(len >= bufsize)) {
        len = bufsize -1;
        ret = 1;
    }

    // move the string to the start/head of buffer
    if (likely(pos > bufhead)) {
        if (unlikely(pos + len > buftail)) {
            // If we went passed the end of the buffer
            // truncate since already violated boundaries
            *buftail = 0;
            len = strlen(pos);
            ret = 1;
        }
        // Setting nul just in-case
        else {
            pos[len] = 0;
        }
        // Should be moving path contents AND nul terminator
        memmove((char *)bufhead, pos, len + 1);
        len = strlen(bufhead);
    }

    if (component && *component) {
        component_len = strlen(component);
        if (likely(component_len) < bufsize) {
            if (component_len + len + 2 > bufsize) {
                size_t offset = len + component_len + 2 - bufsize;
                size_t mv_len = bufsize - offset + 1;
                size_t og_len = len;

                ret = 1;
                memmove((char *)bufhead, bufhead + offset, mv_len);
                *buftail = 0;
                len = strlen(bufhead);

                // Double check our memmove logic is correct
                if (component_len + len + 2 <= bufsize) {
                    strcat((char *)bufhead, "/");
                    strcat((char *)bufhead, component);
                    *buftail = 0;
                    return 1;
                }

                pr_info("%s:%d bufsize:%lu og_len:%lu newlen:%lu "
                        "offset:%lu comp_len:%lu mv_len:%lu\n",
                        __func__, __LINE__, bufsize, og_len,
                        len, offset, component_len, mv_len);
                return -EINVAL;
            }
            else {
                strcat((char *)bufhead, "/");
                strcat((char *)bufhead, component);
                *buftail = 0;
                return ret;
            }
        } else {
            *buftail = 0;
            // strncpy is slow but the path should not be hit.
            strncpy((char *)bufhead, component, bufsize -1);
            return 1;
        }
    }

    return ret;
}

extern void fill_in_preaction_data(struct dynsec_file *dynsec_file,
                                   const struct path *parent_path);

char *build_preaction_path(int dfd, const char __user *filename,
                           int lookup_flags,
                           struct dynsec_file *file)
{
    struct path parent_path;
    char namebuf[NAME_MAX + 1];
    int input_len;
    char *p;
    int component_len = 0;
    char *pathbuf = NULL;
    char *input_start = NULL;
    const char *norm_path = NULL;
    const char *component = NULL;
    int err_ret = -EINVAL;
    int ret;

    // TODO: Handle AT_EMPTY_PATH ?

    if (dfd < 0 && dfd != AT_FDCWD) {
        return ERR_PTR(-EINVAL);
    }

    pathbuf = kmalloc(DYNSEC_PATH_MAX, GFP_KERNEL);
    if (!pathbuf) {
        return ERR_PTR(-ENOMEM);
    }

    memset(pathbuf, 0, DYNSEC_PATH_MAX);
    input_len = strncpy_from_user(pathbuf, filename, DYNSEC_PATH_MAX);

    if (input_len < 0) {
        err_ret = input_len;
        goto out_err;
    }
    if (input_len == 0) {
        // Just return dfd file?
        err_ret = -EINVAL;
        goto out_err;
    }

    // Chomp trailing '/'
    p = pathbuf + input_len - 1;
    while (p >= pathbuf && *p == '/') {
        *p = '\0';
        p--;
        input_len--;
    }
    if (input_len <= 0) {
        goto do_raw;
    }

    component = parse_last_component(namebuf, sizeof(namebuf),
                                     pathbuf, input_len);
    if (component) {
        if (IS_ERR(component)) {
            err_ret = PTR_ERR(component);
            goto out_err;
        }
        component_len = (int)strlen(component);
    } else {
        component_len = 0;
    }
    input_len = strlen(pathbuf);
    input_start = pathbuf;

    if (dfd >= 0) {
        int err = 0;
        int max_dfd_path_len = DYNSEC_PATH_MAX;

        // Move raw input farthest right and prefix a `/`
        // if needed.
        if (input_len) {
            input_start = pathbuf + DYNSEC_PATH_MAX - input_len;
            max_dfd_path_len -= input_len;
            // pr_info("%s:%d input:%s\n", __func__, __LINE__, pathbuf);
            memmove(input_start, pathbuf, input_len);

            if (*input_start != '/') {
                *(input_start - 1) = '/';
                max_dfd_path_len -= 1;
            }
        }
        norm_path = dynsec_prepend_dfd(dfd, pathbuf, max_dfd_path_len, &err);
        if (err == -ENOTDIR) {
            err_ret = err;
            goto out_err;
        } else if (err == -ENAMETOOLONG && norm_path) {
            if (file) {
                file->attr_mask |= DYNSEC_FILE_ATTR_PATH_TRUNC;
            }
            ret = append_component(pathbuf, DYNSEC_PATH_MAX,
                                    (char *)norm_path, component);
            if (ret < 0) {
                goto do_raw;
            }
            if (file) {
                file->path_size = strlen(pathbuf) + 1;
                file->attr_mask |= DYNSEC_FILE_ATTR_PATH_FULL;
            }
            return pathbuf;
        }
        if (!norm_path) {
            goto do_raw;
        }
    } else {
        if (!input_len && !component_len) {
            err_ret = -EINVAL;
            goto out_err;
        }
        norm_path = pathbuf;
    }

    if (dfd == AT_FDCWD && (!input_len || !norm_path || !*norm_path)) {
        err_ret = kern_path(".", lookup_flags, &parent_path);
    } else {
        err_ret = kern_path(norm_path, lookup_flags, &parent_path);
    }
    if (err_ret) {
        goto out_err;
    }

    // check if connected client is interested in this
    // file system type
    if (!__is_client_concerned_filesystem(parent_path.dentry->d_sb)) {
        err_ret = -EINVAL;
        goto out_err;
    }

    if (file) {
        fill_in_preaction_data(file, &parent_path);
    }
    memset(pathbuf, 0, DYNSEC_PATH_MAX);
    norm_path = dynsec_d_path(&parent_path, pathbuf, DYNSEC_PATH_MAX);
    path_put(&parent_path);

    if (IS_ERR_OR_NULL(norm_path)) {
        if (!norm_path || PTR_ERR(norm_path) != -ENAMETOOLONG) {
            goto do_raw;
        }
        if (file) {
            file->attr_mask |= DYNSEC_FILE_ATTR_PATH_TRUNC;
        }
        // Fixup normalized by finding the starting point of normalized entry
        norm_path = find_trunc_path(pathbuf, DYNSEC_PATH_MAX);
    }

    ret = append_component(pathbuf, DYNSEC_PATH_MAX,
                           (char *)norm_path, component);
    if (ret > 0) {
        // set truncation bits
        if (file) {
            file->attr_mask |= DYNSEC_FILE_ATTR_PATH_TRUNC;
        }
    } else if (ret < 0) {
        goto do_raw;
    }

    if (file) {
        file->path_size = strlen(pathbuf) + 1;
        file->attr_mask |= DYNSEC_FILE_ATTR_PATH_FULL;
    }

    return pathbuf;

do_raw:
    if (file) {
        file->attr_mask &= ~(DYNSEC_FILE_ATTR_PATH_FULL);
        file->path_size = 0;
    }
    memset(pathbuf, 0, DYNSEC_PATH_MAX);
    input_len = strncpy_from_user(pathbuf, filename, DYNSEC_PATH_MAX);
    if (input_len < 0) {
        err_ret = input_len;
        goto out_err;
    }
    if (!input_len) {
        err_ret = -EINVAL;
        goto out_err;
    }

    if (file) {
        file->attr_mask |= DYNSEC_FILE_ATTR_PATH_RAW;
        file->path_size = strlen(pathbuf) + 1;
    }
    return pathbuf;

out_err:
    if (pathbuf) {
        kfree(pathbuf);
        pathbuf = NULL;
    }
    return ERR_PTR(err_ret);
}

#ifdef DEBUG_PATH
struct parse_test_case {
    const char *input;
    char *exp_ret;
    char *exp_input;
};
struct parse_test_case test_cases[] = {
    [0] = {
        .input = "..",
        .exp_ret = NULL,
        .exp_input = "..",
    },
    [1] = {
        .input = ".",
        .exp_ret = NULL,
        .exp_input = ".",
    },
    [2] = {
        .input = "...",
        .exp_ret = "...",
        .exp_input = "",
    },
    [3] = {
        .input = "../.",
        .exp_ret = NULL,
        .exp_input = "../.",
    },
    [4] = {
        .input = "/..",
        .exp_ret = NULL,
        .exp_input = "/..",
    },
    [5] = {
        .input = "",
        .exp_ret = NULL,
        .exp_input = "",
    },
    [6] = {
        .input = "filewith.",
        .exp_ret = "filewith.",
        .exp_input = "",
    },
};

bool test_parse_last_component(void)
{
    char namebuf[NAME_MAX + 1];
    char tmp_inputbuf[256];
    char *result;
    int i;
    int total_failed = 0;

    for (i = 0; i < ARRAY_SIZE(test_cases); i++) {
        bool passed = true;
        memset(tmp_inputbuf, 0, sizeof(tmp_inputbuf));

        if (!test_cases[i].input) {
            continue;
        }
        strcpy(tmp_inputbuf, test_cases[i].input);
        result = parse_last_component(namebuf, sizeof(namebuf),
                                      tmp_inputbuf, strlen(tmp_inputbuf));

        if ((!test_cases[i].exp_ret && result) ||
            (test_cases[i].exp_ret && !result) ||
            (test_cases[i].exp_ret && result && strcmp(test_cases[i].exp_ret, result) != 0)) {
            pr_info("FAIL: Case: %d %s exp_ret:'%s' actual ret:'%s'\n", i,
                    test_cases[i].input, test_cases[i].exp_ret, result);
            passed = false;
        }
        if (strcmp(test_cases[i].exp_input, tmp_inputbuf) != 0) {
            pr_info("FAIL: Case: %d %s exp_input_ret:'%s' actual input_ret:'%s'\n", i,
                    test_cases[i].input, test_cases[i].exp_input, tmp_inputbuf);
            passed = false;
        }
        if (passed) {
            pr_info("PASS: Case %d %s exp_ret:'%s' ret:'%s', exp_input_ret:'%s' input_ret:'%s'\n",
                    i, test_cases[i].input,  test_cases[i].exp_ret,
                    result, test_cases[i].exp_input, tmp_inputbuf);
        } else {
            total_failed += 1;
        }
    }

    return total_failed == 0;
}
#endif /* DEBUG_PATH */
