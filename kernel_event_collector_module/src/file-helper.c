// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include "priv.h"
#include "cb-banning.h"
#include "mem-alloc.h"
#include "path-cache.h"
#include "path-buffers.h"

#include <linux/err.h>
#include <linux/magic.h>
#include <linux/namei.h>
#include <linux/string.h>    // memset()

typedef PathData *(*path_find_fn)(
    uint64_t            ns_id,
    uint64_t            device,
    uint64_t            inode,
    ProcessContext     *context);

bool ec_file_helper_init(ProcessContext *context)
{
    return true;
}

bool ec_path_get_path(struct path const *path, char *buffer, unsigned int buflen, char **pathname)
{
    bool xcode = true;
    int bufindex;

    CANCEL(pathname, false);
    CANCEL(buffer, false);
    CANCEL(path && path->mnt && path->dentry, false);
    (*pathname) = NULL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)  //{
    path_get(path);
#else  //}{ v2.6.32 forgot 'const'
    path_get((struct path *)path);
#endif  //}

    // Problem here is that dentry_path, which solves pathing issues in chroot/namespace cases is not adequate
    // for the normal use case that d_path satisfies. These two function differ in the way in which they determine
    // the root dentry (d_path by get_fs_root and dentry_path by explicitly walking the dentry table). In the
    // dentry_path case, we consistently miss the root node. So each solution is the right solution for that
    // specific case, we just need to know when to use each.

    // If we failed to resolve the symbol, i.e. we're on a 2.6.32 kernel or it just doesn't resolve,
    // default to the d_path option
    if (current->nsproxy && CB_CHECK_RESOLVED(current_chrooted) && CB_RESOLVED(current_chrooted)())
    {
        (*pathname) = ec_dentry_to_path(path->dentry, buffer, buflen);
    } else if (current->fs)
    {
        (*pathname) = d_path(path, buffer, buflen);
    }

    if (IS_ERR(*pathname) && -ENAMETOOLONG == PTR_ERR(*pathname))
    {
        // An ENAMETOOLONG results when last fetched component name length exceeds remaining space avail
        // at beginning of buffer, so the partial path we want begins some offset beyond buffer[0] but
        // less than buffer[0] + max component len + separator len

        // Having arrived here by detection of ENAMETOOLONG we need to try and recover the partial path BUT the original
        // invocation operated on an uncleared buffer for performance reasons and the random garbage leaves sought data
        // indiscernible.  Here we explicitly set a reference buffer and reattempt to resolve the path.  This will allow
        // us to walk the buffer and recover the partial data up to the exceeding path element.
        memset(buffer, '.', buflen);
        if (current->nsproxy && CB_CHECK_RESOLVED(current_chrooted) && CB_RESOLVED(current_chrooted)())
        {
            (*pathname) = ec_dentry_to_path(path->dentry, buffer, buflen);
        } else if (current->fs)
        {
            (*pathname) = d_path(path, buffer, buflen);
        }

        // a non-error bail here such as  'if (!IS_ERR(*pathname)) break;' is pointless -- nothing has changed
        // so press on resolving ENAMETOOLONG
        xcode = false;
        for (bufindex = 0; bufindex < buflen; bufindex++)
        {
            // path constructed R-to-L in buffer, first non '.' encountered is start of partial path return
            if ('.' != buffer[bufindex])
            {
                // We want ellipsis as visual cue that returned data is truncated path not actual.
                if (bufindex > 2)
                {
                    // normal -- '.../partial/path/<rest>'
                    bufindex -= 3;
                } else
                {
                    // edge case -- '...artial/path/<rest>'
                    memset(buffer, '.', 3);
                    bufindex = 0;
                }

                *pathname = &buffer[bufindex];
                xcode = true;
                break;
            }
        }

        buffer[buflen - 1] = 0;       // ensure termination as a valid strz

    } else if (IS_ERR_OR_NULL(*pathname))
    {
        (*pathname) = buffer;
        buffer[0] = 0;
        xcode = false;
        strncat(buffer, path->dentry->d_name.name, buflen-1);

        // report such info as we have for other error cases
        if (IS_ERR(*pathname))
        {
            TRACE(DL_FILE, "Error %ld resolving path for |%s|", PTR_ERR(*pathname), path->dentry->d_name.name);
        } else
        {
            TRACE(DL_FILE, "Null path resolved for |%s|", buffer);
        }
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)  //{
    path_put(path);
#else  //}{ v2.6.32 forgot 'const'
    path_put((struct path *)path);
#endif  //}

    return xcode;
}

bool ec_file_get_path(struct file const *file, char *buffer, unsigned int buflen, char **pathname)
{
    CANCEL(file, false);
    return ec_path_get_path(&file->f_path, buffer, buflen, pathname);
}

PathData *ec_file_get_path_data(
    struct path_lookup *path_lookup,
    ProcessContext     *context)
{
    PathQuery query = {
        .key = { 0, 0, 0 },
    };
    uint64_t fs_magic = 0;
    PathData *path_data = NULL;
    char *owned_path_buffer = NULL;
    char *path_str = NULL;

    TRY(likely(path_lookup));

    TRY(path_lookup->file || path_lookup->path);    // We need at least one of file or path
    TRY(!(path_lookup->file && path_lookup->path)); // But not both

    query.ignore_special = path_lookup->ignore_spcial;

    // Get the device info
    // TODO: Get the namespace
    if (path_lookup->file)
    {
        ec_get_devinfo_fs_magic_from_file(path_lookup->file, &query.key.device, &query.key.inode, &fs_magic);
    } else
    {
        ec_get_devinfo_from_path(path_lookup->path, &query.key.device, &query.key.inode, &fs_magic);
    }

    path_data = ec_path_cache_find(&query, context);

    TRY(!path_data);

    if (!path_lookup->path_buffer)
    {
        // If caller does not provide path_lookup->path_buffer we need to allocate one for use in this function.
        owned_path_buffer = path_lookup->path_buffer = ec_get_path_buffer(context);
    }

    // PSCLNX-5220
    //  If we are in the clone hook it is possible for the ec_task_get_path functon
    //  to schedule. (Softlock!)  Do not lookup the path in this case.
    if (ALLOW_WAKE_UP(context) && !query.path_ignored && path_lookup->path_buffer)
    {
        bool path_found = false;

        if (path_lookup->file)
        {
            // We have a file, so use the path from that
            path_lookup->path = &path_lookup->file->f_path;
        }
        // ec_file_get_path() uses dpath which builds the path efficiently
        //  by walking back to the root. It starts with a string terminator
        //  in the last byte of the target buffer.
        //
        // The `path` variable will point to the start of the string, so we will
        //  use that directly later to copy into the tracking entry and event.
        path_found = ec_path_get_path(path_lookup->path, path_lookup->path_buffer, PATH_MAX, &path_str);
        path_lookup->path_buffer[PATH_MAX] = 0;

        if (!path_found)
        {
            TRACE(DL_INFO, "Failed to retrieve path for pid: %d", ec_getpid(current));
        }
    }

    if (path_str)
    {
        path_str = ec_mem_strdup(path_str, context);
    } else if (path_lookup->filename)
    {
        int input_len;

        input_len = strncpy_from_user(path_lookup->path_buffer, path_lookup->filename, PATH_MAX);

        TRY_MSG(input_len <= 0, DL_ERROR, "strncpy_from_user: %d", input_len);

        path_lookup->path_buffer[PATH_MAX - 1] = 0;

        path_str = ec_mem_strdup(path_lookup->path_buffer, context);
    }

    path_data = ec_path_cache_add(query.key.ns_id, query.key.device, query.key.inode, path_str, fs_magic, context);
    if (path_lookup->ignore_spcial && path_data && path_data->is_special_file)
    {
        ec_path_cache_put(path_data, context);
        path_data = NULL;
    }

CATCH_DEFAULT:
    ec_mem_put(path_str);
    ec_put_path_buffer(owned_path_buffer);

    if (!path_data)
    {
        // No path was created so return a "not found" path_data
        path_data = ec_path_cache_add(0, 0, 0, NULL, 0, context);
    }

    return path_data;
}

char *ec_dentry_to_path(struct dentry const *dentry, char *buf, int buflen)
{
    CANCEL_CB_RESOLVED(dentry_path, NULL);
    return CB_RESOLVED(dentry_path)((struct dentry *)dentry, buf, buflen);
}

struct inode const *ec_get_inode_from_dentry(struct dentry const *dentry)
{
    // Skip if dentry is null
    if (!dentry) return NULL;
    if (!dentry->d_inode) return NULL;

    // dig out inode
    return dentry->d_inode;
}

struct inode const *ec_get_inode_from_file(struct file const *file)
{
    if (!file) return NULL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)  //{
    // The cached inode may be NULL, but the calling code will handle that
    return file->f_inode;
#else  //}{
    return ec_get_inode_from_dentry(file->f_path.dentry);
#endif  //}
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
    #define VFS_GETATTR(PATH, KS)   vfs_getattr_nosec((PATH), (KS), STATX_BASIC_STATS, AT_STATX_SYNC_AS_STAT)
#else
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
        #define _VFS_GETATTR(PATH, KS)   vfs_getattr((PATH), (KS))
    #else
        #define _VFS_GETATTR(PATH, KS)   vfs_getattr((PATH)->mnt, (PATH)->dentry, (KS))

        // This "simulates" the behavior of vfs_getattr_nosec found in later kernels
        //  by adding S_PRIVATE to the inode flags.  With this flag set, the kernel
        //  will not call check the security on getattr.
        // The nosec version is needed because SELinux was rejecting our access to some files.
        //  (You would see messages like this in the log.)
        //  SELinux is preventing /usr/bin/dbus-daemon from getattr access on the fifo_file /run/systemd/sessions/1.ref.
        int ec_getattr(struct path const *path, struct kstat *stat)
        {
            int ret = 0;
            bool should_remove_private = false;

            if (!IS_PRIVATE(path->dentry->d_inode))
            {
                should_remove_private = true;
                path->dentry->d_inode->i_flags = path->dentry->d_inode->i_flags | S_PRIVATE;
            }

            ret = _VFS_GETATTR(path, stat);

            if (should_remove_private)
            {
                path->dentry->d_inode->i_flags = path->dentry->d_inode->i_flags & ~S_PRIVATE;
            }
            return ret;
        }
        #define VFS_GETATTR(PATH, KS)   ec_getattr((PATH), (KS))
    #endif
#endif

struct super_block const *ec_get_sb_from_dentry(struct dentry const *dentry);  // forward

// Why doesn't this return bool?
void ec_get_devinfo_from_path(struct path const *path, uint64_t *device, uint64_t *inode, uint64_t *fs_magic)
{
    const struct super_block *sb = NULL;

    sb = ec_get_sb_from_dentry(path->dentry);
    if (sb)
    {
        *device   = new_encode_dev(sb->s_dev);
        *inode    = path->dentry->d_inode->i_ino;
        *fs_magic = sb->s_magic;
    }
}

void ec_get_devinfo_from_file(struct file const *file, uint64_t *device, uint64_t *inode)
{
    uint64_t fs_magic;

    ec_get_devinfo_fs_magic_from_file(file, device, inode, &fs_magic);
}

void ec_get_devinfo_fs_magic_from_file(struct file const *file, uint64_t *device, uint64_t *inode, uint64_t *fs_magic)
{
    struct super_block const *sb = NULL;

    CANCEL_VOID(file && device && inode && fs_magic);

    *device = 0;
    *inode  = 0;
    *fs_magic = 0;

    if (file->f_inode)
    {
        *inode = file->f_inode->i_ino;
    }

    sb = ec_get_sb_from_file(file);
    if (sb)
    {
        *device = new_encode_dev(sb->s_dev);
        *fs_magic = sb->s_magic;
    }
}

umode_t ec_get_mode_from_file(struct file const *file)
{
    umode_t mode = 0;

    if (file)
    {
        struct inode const *inode = ec_get_inode_from_file(file);

        if (inode)
        {
            mode = inode->i_mode;
        }
    }

    return mode;
}

struct super_block const *ec_get_sb_from_dentry(struct dentry const *dentry)
{
    struct super_block const *sb = NULL;

    if (dentry)
    {
        // Get super_block from inode first
        struct inode const *inode = ec_get_inode_from_dentry(dentry);

        if (inode)
        {
            sb = inode->i_sb;
        }

        // Get super_block from dentry last.
        if (!sb)
        {
            sb = dentry->d_sb;
        }
    }
    return sb;
}

struct super_block const *ec_get_sb_from_file(struct file const *file)
{
    struct super_block const *sb = NULL;

    if (file)
    {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
        struct inode const *inode = ec_get_inode_from_file(file);

        if (inode)
        {
            sb = inode->i_sb;
        }
#endif
        if (!sb)
        {
            sb = ec_get_sb_from_dentry(file->f_path.dentry);
        }
    }
    return sb;
}

bool ec_is_ignored_filesystem(uint64_t fs_magic)
{
    // Check magic numbers
    switch (fs_magic)
    {
    case NFS_SUPER_MAGIC:
        return true;

    case SMB_SUPER_MAGIC:
        return true;

    case SYSFS_MAGIC:
        return true;

    case CGROUP_SUPER_MAGIC:
        return true;

#ifdef CGROUP2_SUPER_MAGIC
    case CGROUP2_SUPER_MAGIC:
        return true;
#endif

    case PROC_SUPER_MAGIC:
        return true;

    default:
        return false;
    }

    return false;
}

#define ENABLE_SPECIAL_FILE_SETUP(x)   {x, sizeof(x)-1, 1}
#define DISABLE_SPECIAL_FILE_SETUP(x)  {x, sizeof(x)-1, 0}
#define N_ELEM(x) (sizeof(x) / sizeof(*x))

typedef struct special_file_t_ {
    char *name;
    int   len;
    int   enabled;

} special_file_t;

//
// be sure to keep this value set to the smallest 'len' value in the
// special_files[] array below
//
#define MIN_SPECIAL_FILE_LEN 4
static const special_file_t special_files[] = {

    ENABLE_SPECIAL_FILE_SETUP("/var/lib/rsyslog"),
    ENABLE_SPECIAL_FILE_SETUP("/var/log/messages"),
    ENABLE_SPECIAL_FILE_SETUP("/var/lib/cb"),
    ENABLE_SPECIAL_FILE_SETUP("/var/log"),
    ENABLE_SPECIAL_FILE_SETUP("/srv/bit9/data"),
    ENABLE_SPECIAL_FILE_SETUP("/sys"),
    ENABLE_SPECIAL_FILE_SETUP("/proc"),
    ENABLE_SPECIAL_FILE_SETUP("/var/opt/carbonblack"),
    DISABLE_SPECIAL_FILE_SETUP(""),
};

//
// FUNCTION:
//   ec_is_special_file()
//
// DESCRIPTION:
//   we'll skip any file that lives below any of the directories listed in
//   in the special_files[] array.
//
// PARAMS:
//   char *pathname - full path + filename to test
//   int len - length of the full path and filename
//
// RETURNS:
//   0 == no match
//
//
int ec_is_special_file(char *pathname, int len)
{
    int i;

    CANCEL(pathname, 0);

    //
    // bail out if we've got no chance of a match
    //
    if (len < MIN_SPECIAL_FILE_LEN)
    {
        return 0;
    }

    for (i = 0; i < N_ELEM(special_files); i++)
    {
        //
        // Skip disabled elements
        //
        if (!special_files[i].enabled)
        {
            continue;
        }

        //
        // if the length of the path we're testing is shorter than this special
        // file, it can't possibly be a match
        //
        if (special_files[i].len > len)
        {
            continue;
        }

        //
        // still here, do the compare. We know that the path passed in is >=
        // this special_file[].len so we'll just compare up the length of the
        // special file itself. If we match up to that point, the path being
        // tested is or is below this special_file[].name
        //
        if (strncmp(pathname, special_files[i].name, special_files[i].len) == 0)
        {
            return -1;
        }
    }

    return 0;
}

bool ec_file_exists(int dfd, const char __user *filename)
{
    bool         exists     = false;
    struct path path;

    TRY(filename);

    exists = user_path_at(dfd, filename, LOOKUP_FOLLOW, &path) == 0;

CATCH_DEFAULT:
    if (exists)
    {
        path_put(&path);
    }

    return exists;
}

bool ec_is_interesting_file(struct file *file)
{
    umode_t mode = ec_get_mode_from_file(file);

    return (S_ISREG(mode) && (!S_ISDIR(mode)) && (!S_ISLNK(mode)));
}
