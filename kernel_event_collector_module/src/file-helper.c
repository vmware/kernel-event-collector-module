// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include "priv.h"
#include "cb-banning.h"
#include "mem-alloc.h"
#include "path-cache.h"
#include "path-buffers.h"

#include <linux/magic.h>
#include <linux/namei.h>

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
    bool         xcode = true;

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
    } else
    {
        (*pathname) = d_path(path, buffer, buflen);
    }

    if (IS_ERR_OR_NULL((*pathname)))
    {
        (*pathname) = buffer;
        xcode   = false;

        buffer[0] = 0;
        strncat(buffer, path->dentry->d_name.name, buflen-1);

        TRACE(DL_WARNING, "Path lookup failed, using |%s| as file name", buffer);
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

    CANCEL(likely(path_lookup), NULL);

    CANCEL(path_lookup->file || path_lookup->path, NULL);    // We need at least one of file or path
    CANCEL(!(path_lookup->file && path_lookup->path), NULL); // But not both

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

    // PSCLNX-5220
    //  If we are in the clone hook it is possible for the ec_task_get_path functon
    //  to schedule. (Softlock!)  Do not lookup the path in this case.
    if (!path_data && !query.path_ignored && ALLOW_WAKE_UP(context))
    {
        char *owned_path_buffer = NULL;
        char *path_str = NULL;
        bool path_found = false;

        if (!path_lookup->path_buffer)
        {
            owned_path_buffer = path_lookup->path_buffer = ec_get_path_buffer(context);
        }

        if (path_lookup->path_buffer)
        {
            if (path_lookup->file)
            {
                // We have a file, so use the path from that
                path_lookup->path = &path_lookup->file->f_path;
            }
            // ec_file_get_path() uses dpath which builds the path efficently
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
            // Fallback to a supplied filename
            struct filename *file_s = CB_RESOLVED(getname)(path_lookup->filename);

            path_str = ec_mem_strdup(file_s->name, context);
        }

        path_data = ec_path_cache_add(query.key.ns_id, query.key.device, query.key.inode, path_str, fs_magic, context);
        if (path_lookup->ignore_spcial && path_data && path_data->is_special_file)
        {
            ec_path_cache_put(path_data, context);
            path_data = NULL;
        }

        ec_mem_put(path_str);
        ec_put_path_buffer(owned_path_buffer);
    }

    return path_data;
}

char *ec_dentry_to_path(struct dentry const *dentry, char *buf, int buflen)
{
    CANCEL_CB_RESOLVED(dentry_path, NULL);
    return CB_RESOLVED(dentry_path)((struct dentry *)dentry, buf, buflen);
}

bool ec_dentry_get_path(struct dentry const *dentry, char *buffer, unsigned int buflen, char **pathname)
{
    bool xcode = true;

    CANCEL(dentry, false);
    CANCEL(buffer, false);
    CANCEL(pathname, false);

    (*pathname) = ec_dentry_to_path(dentry, buffer, buflen);

    if (IS_ERR_OR_NULL((*pathname)))
    {
        (*pathname) = buffer;
        xcode   = false;

        buffer[0] = 0;
        strncat(buffer, dentry->d_name.name, buflen-1);

        TRACE(DL_WARNING, "Path lookup failed, using |%s| as file name", buffer);
    }

    return xcode;
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

bool ec_is_network_filesystem(struct super_block const *sb)
{
    if (!sb)
    {
        return false;
    }

    // Check magic numbers
    switch (sb->s_magic)
    {
    case NFS_SUPER_MAGIC:
        return true;

    case SMB_SUPER_MAGIC:
        return true;

    default:
        return false;
    }

    return false;
}

bool ec_may_skip_unsafe_vfs_calls(struct file const *file)
{
    struct super_block const *sb = ec_get_sb_from_file(file);

    // Since we still don't know the file system type
    // it's safer to not perform any VFS ops on the file.
    if (!sb)
    {
        return true;
    }

    // We may want to check if a file's inode lock is held
    // before trying to do a vfs operation.

    // Eventually expand to stacked file systems
    return ec_is_network_filesystem(sb);
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
