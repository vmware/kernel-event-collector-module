// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2022 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include "priv.h"
#include "process-tracking.h"
#include "file-process-tracking.h"
#include "cb-spinlock.h"
#include "path-buffers.h"
#include "cb-banning.h"
#include "event-factory.h"
#include "mem-alloc.h"

#include <linux/file.h>
#include <linux/namei.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
#define DENTRY(a)    (a)
#else
// checkpatch-ignore: COMPLEX_MACRO
#define DENTRY(a)    (a)->dentry, (a)->mnt
// checkpatch-no-ignore: COMPLEX_MACRO
#endif

char *ec_event_type_to_str(CB_EVENT_TYPE event_type)
{
    char *str = "UNKNOWN";

    switch (event_type)
    {
    case CB_EVENT_TYPE_FILE_CREATE:
        str = "FILE-CREATE";
        break;
    case CB_EVENT_TYPE_FILE_DELETE:
        str = "FILE-DELETE";
        break;
    case CB_EVENT_TYPE_FILE_WRITE:
        str = "FILE-WRITE";
        break;
    case CB_EVENT_TYPE_FILE_CLOSE:
        str = "FILE-CLOSE";
        break;
    default:
        break;
    }

    return str;
}

PathData *__ec_get_path_data(
    int                dfd,
    const char __user *filename,
    ProcessContext    *context)
{
    PathData *path_data;
    struct path path = {};
    struct path_lookup path_lookup = {
        .path = &path,
        .filename = filename,
        .ignore_spcial = false,
    };

    CANCEL(!user_path_at(dfd, filename, LOOKUP_FOLLOW, &path), NULL);

    path_data = ec_file_get_path_data(&path_lookup, context);

    path_put(&path);
    return path_data;
}

void __ec_do_generic_file_event(
    PathData       *path_data,
    CB_EVENT_TYPE   eventType,
    ProcessContext *context)
{
    pid_t pid = ec_getpid(current);
    ProcessHandle *process_handle = NULL;

    TRY(path_data);

    TRY(!ec_banning_IgnoreProcess(context, pid));

    TRY(ec_logger_should_log(eventType));

    if (eventType == CB_EVENT_TYPE_FILE_DELETE)
    {
        TRACE(DL_VERBOSE, "Checking if deleted inode [%llu:%llu] was banned.",
            path_data->key.device,
            path_data->key.inode);
        if (ec_banning_ClearBannedProcessInode(context, path_data->key.device, path_data->key.inode))
        {
            TRACE(DL_FILE, "[%llu:%llu] was removed from banned inode table.",
                path_data->key.device,
                path_data->key.inode);
        }
    }

    process_handle = ec_get_procinfo_and_create_process_start_if_needed(pid, "Fileop", context);

    TRY(eventType != CB_EVENT_TYPE_FILE_OPEN ||
        (process_handle &&
         ec_process_exec_identity(process_handle)->is_interpreter));

    ec_event_send_file(
        process_handle,
        eventType,
        path_data,
        context);

CATCH_DEFAULT:
    ec_process_tracking_put_handle(process_handle, context);
}

void __ec_do_file_event(ProcessContext *context, struct file *file, CB_EVENT_TYPE eventType)
{
    FILE_PROCESS_VALUE *fileProcess = NULL;
    pid_t              pid          = ec_getpid(current);
    bool               doClose      = false;
    PathData           *path_data   = NULL;

    CANCEL_VOID(file);
    CANCEL_VOID(!ec_banning_IgnoreProcess(context, pid));

    CANCEL_VOID(ec_logger_should_log(eventType));

    // Skip if not interesting
    CANCEL_VOID(ec_is_interesting_file(file));

    fileProcess = ec_file_process_get(file, context);

    if (fileProcess)
    {
        TRY_MSG(eventType != CB_EVENT_TYPE_FILE_WRITE,
                DL_FILE, "%s [%llu:%llu] process:%u written before",
                SANE_PATH(fileProcess->path_data->path),
                fileProcess->path_data->key.device,
                fileProcess->path_data->key.inode,
                pid);

        if (eventType == CB_EVENT_TYPE_FILE_CLOSE || eventType == CB_EVENT_TYPE_FILE_DELETE)
        {
            TRACE(DL_FILE, "%s [%llu:%llu] process:%u closed or deleted",
                SANE_PATH(fileProcess->path_data->path),
                fileProcess->path_data->key.device,
                fileProcess->path_data->key.inode,
                pid);
            // I still need to use the path buffer from fileProcess, so don't call
            //  ec_file_process_status_close until later.
            doClose = true;
        }

        path_data = ec_path_cache_get(fileProcess->path_data, context);
    } else //status == CLOSED
    {
        struct path_lookup path_lookup = {
            .file = file,
            .ignore_spcial = true,
        };

        TRY(eventType == CB_EVENT_TYPE_FILE_WRITE
            || eventType == CB_EVENT_TYPE_FILE_CREATE
            || eventType == CB_EVENT_TYPE_FILE_OPEN);

        // If this file is deleted already, then just skip it
        TRY(!d_unlinked(file->f_path.dentry));

        path_data = ec_file_get_path_data(&path_lookup, context);
        TRY(path_data);

        // Do not track if this is an open/read, otherwise a last-write will be issued when we see the close event
        if (eventType != CB_EVENT_TYPE_FILE_OPEN)
        {
            fileProcess = ec_file_process_status_open(
                file,
                pid,
                path_data,
                context);
        }

        if (fileProcess)
        {
            char *path = SANE_PATH(fileProcess->path_data->path);

            TRACE(DL_FILE, "%s [%llu:%llu:%p] process:%u first write",
                path,
                fileProcess->path_data->key.device,
                fileProcess->path_data->key.inode,
                file,
                pid);

            // If this file has been written to AND that files inode is in the banned list
            // we need to remove it on the assumption that the md5 will have changed. It is
            // entirely possible that the exact bits are written back, but in that case we
            // will catch it in user space, by md5, and notify kernel to kill and ban if necessary.
            //
            // This should be a fairly lightweight call as it is inlined and the hashtable is usually
            // empty and if not is VERY small.
            if (ec_banning_ClearBannedProcessInode(context, fileProcess->path_data->key.device, fileProcess->path_data->key.inode))
            {
                TRACE(DL_FILE, "%s [%llu:%llu] was removed from banned inode table.",
                      path,
                      fileProcess->path_data->key.device,
                      fileProcess->path_data->key.inode);
            }
        }
    }

    TRY(path_data);
    if (path_data->path)
    {
        // Check to see if the process is tracked already
        ProcessHandle *process_handle = ec_process_tracking_get_handle(pid, context);

        TRY(process_handle);

        if (path_data->path[0] == '/')
        {
            //
            // Log it
            //
            if (!path_data->is_special_file
                && (eventType != CB_EVENT_TYPE_FILE_OPEN || ec_process_exec_identity(process_handle)->is_interpreter))
            {
                ec_event_send_file(
                    process_handle,
                    eventType,
                    path_data,
                    context);
            }
        } else if (path_data->path[0] == '[' && eventType == CB_EVENT_TYPE_FILE_WRITE)
        {
            // CEL This is a noop as we can see [eventfd] on a write and we don't care about it
        } else if (eventType == CB_EVENT_TYPE_FILE_CLOSE)
        {
            ec_event_send_file(
                process_handle,
                eventType,
                path_data,
                context);
        } else
        {
            TRACE(DL_FILE, "invalid full path %s event %d", fileProcess->path_data->path, eventType);
        }
        ec_process_tracking_put_handle(process_handle, context);
    }

CATCH_DEFAULT:
    ec_path_cache_put(path_data, context);
    ec_file_process_put_ref(fileProcess, context);
    if (doClose)
    {
        ec_file_process_status_close(file, context);
    }

    return;
}

long (*ec_orig_sys_write)(unsigned int fd, const char __user *buf, size_t count);
long (*ec_orig_sys_close)(unsigned int fd);

long (*ec_orig_sys_open)(const char __user *filename, int flags, umode_t mode);
long (*ec_orig_sys_openat)(int dfd, const char __user *filename, int flags, umode_t mode);
long (*ec_orig_sys_creat)(const char __user *filename, umode_t mode);
long (*ec_orig_sys_unlink)(const char __user *filename);
long (*ec_orig_sys_unlinkat)(int dfd, const char __user *pathname, int flag);
long (*ec_orig_sys_rename)(const char __user *oldname, const char __user *newname);
long (*ec_orig_sys_renameat)(int old_dfd, const char __user *oldname, int new_dfd, const char __user *newname);
long (*ec_orig_sys_renameat2)(int old_dfd, const char __user *oldname, int new_dfd, const char __user *newname, unsigned int flags);

asmlinkage void ec_lsm_file_free_security(struct file *file)
{
    DECLARE_ATOMIC_CONTEXT(context, ec_getpid(current));

    MODULE_GET_AND_BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(&context, CATCH_DEFAULT);

    __ec_do_file_event(&context, file, CB_EVENT_TYPE_FILE_CLOSE);

CATCH_DEFAULT:

    g_original_ops_ptr->file_free_security(file);

    MODULE_PUT_AND_FINISH_MODULE_DISABLE_CHECK(&context);
}

struct open_argblock {
    int dfd;
    const char __user *filename;
    int flags;
    umode_t mode;
};

long __ec_sys_open(
    long (*call_open_func)(struct open_argblock *args),
    struct open_argblock   *args,
    ProcessContext         *context)
{
    long                fd;
    CB_EVENT_TYPE       eventType = 0;

    IF_MODULE_DISABLED_GOTO(context, CATCH_DISABLED);

    if ((args->flags & O_CREAT) && !ec_file_exists(args->dfd, args->filename))
    {
        // If this is opened with create mode AND it does not already exist we will report a create event
        eventType = CB_EVENT_TYPE_FILE_CREATE;
    } else if (args->flags & (O_RDWR | O_WRONLY))
    {
        eventType = CB_EVENT_TYPE_FILE_WRITE;
    } else if (!(args->flags & (O_RDWR | O_WRONLY)))
    {
        // If the file is opened with read-only mode we will report an open event
        eventType = CB_EVENT_TYPE_FILE_OPEN;
    }

CATCH_DISABLED:
    fd = call_open_func(args);

    BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(context, CATCH_DEFAULT);

    if (!IS_ERR_VALUE(fd) && eventType)
    {
        struct file *file = fget(fd);

        TRY(!IS_ERR_OR_NULL(file));
        __ec_do_file_event(context, file, eventType);
        fput(file);
    }

CATCH_DEFAULT:
    return fd;
}

asmlinkage long ec_sys_creat(const char __user *filename, umode_t mode)
{
    long fd;
    CB_EVENT_TYPE       eventType = 0;

    DECLARE_NON_ATOMIC_CONTEXT(context, ec_getpid(current));

    MODULE_GET_AND_IF_MODULE_DISABLED_GOTO(&context, CATCH_DISABLED);

    // If this is opened with create mode AND it does not already exist we
    //  will report an event
    if (!ec_file_exists(AT_FDCWD, filename))
    {
        eventType = CB_EVENT_TYPE_FILE_CREATE;
    } else
    {
        eventType = CB_EVENT_TYPE_FILE_WRITE;
    }

CATCH_DISABLED:
    fd = ec_orig_sys_creat(filename, mode);

    BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(&context, CATCH_DEFAULT);

    if (!IS_ERR_VALUE(fd) && eventType)
    {
        struct file *file = fget(fd);

        TRY(!IS_ERR_OR_NULL(file));
        __ec_do_file_event(&context, file, eventType);
        fput(file);
    }

CATCH_DEFAULT:
    MODULE_PUT_AND_FINISH_MODULE_DISABLE_CHECK(&context);
    return fd;
}

struct unlink_argblock {
    int dfd;
    const char __user *filename;
    int flags;
};

long __ec_sys_unlink(
    long (*call_unlink_func)(struct unlink_argblock *args),
    struct unlink_argblock *args,
    ProcessContext         *context)
{
    long ret;
    PathData *path_data = NULL;

    // __ec_get_path_data can block if the device is unavailable (e.g. network timeout)
    // so do not begin hook tracking yet, since that can block module disable
    IF_MODULE_DISABLED_GOTO(context, CATCH_DISABLED);

    // Collect data about the file before it is modified.  The event will be sent
    // after a successful operation
    path_data = __ec_get_path_data(args->dfd, args->filename, context);

CATCH_DISABLED:
    ret = call_unlink_func(args);

    BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(context, CATCH_DEFAULT);
    // Now the active count is incremented and the hook is being tracked

    if (!IS_ERR_VALUE(ret) && path_data)
    {
        __ec_do_generic_file_event(path_data, CB_EVENT_TYPE_FILE_DELETE, context);
    }

    ec_path_cache_delete(path_data, context);

CATCH_DEFAULT:
    // We still need to release the reference after deleting it
    ec_path_cache_put(path_data, context);

    return ret;
}

struct rename_argblock {
    int olddirfd;
    char __user const *oldname;
    int newdirfd;
    char __user const *newname;
    unsigned int flags;
};

long __ec_sys_rename(
    long (*call_rename_func)(struct rename_argblock *args),
    struct rename_argblock *args,
    ProcessContext         *context)
{
    long         ret;
    PathData *old_path_data = NULL;
    PathData *new_path_data_pre_rename = NULL;
    PathData *new_path_data_post_rename = NULL;

    // __ec_get_path_data can block if the device is unavailable (e.g. network timeout)
    // so do not begin hook tracking yet, since that can block module disable
    IF_MODULE_DISABLED_GOTO(context, CATCH_DISABLED);

    // Collect data about the file before it is modified.  The event will be sent
    // after a successful operation
    old_path_data = __ec_get_path_data(args->olddirfd, args->oldname, context);

    // Only lookup new path when old path was found
    if (old_path_data)
    {
        new_path_data_pre_rename = __ec_get_path_data(args->newdirfd, args->newname, context);
    }
    // Old path must exist but still execute syscall

CATCH_DISABLED:
    ret = call_rename_func(args);

    BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(context, CATCH_DEFAULT);
    // Now the active count is incremented and the hook is being tracked

    if (!IS_ERR_VALUE(ret) && old_path_data)
    {
        __ec_do_generic_file_event(old_path_data, CB_EVENT_TYPE_FILE_DELETE, context);

        // Delete the old path from the cache
        ec_path_cache_delete(old_path_data, context);

        // Send a delete for the destination if the rename will overwrite an existing file
        if (new_path_data_pre_rename)
        {
            __ec_do_generic_file_event(new_path_data_pre_rename, CB_EVENT_TYPE_FILE_DELETE, context);

            // Delete the old path from the cache
            ec_path_cache_delete(new_path_data_pre_rename, context);
        }

        FINISH_MODULE_DISABLE_CHECK(context);

        // This could block so call it outside the disable tracking
        new_path_data_post_rename = __ec_get_path_data(args->newdirfd, args->newname, context);

        BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(context, CATCH_DEFAULT);

        __ec_do_generic_file_event(new_path_data_post_rename, CB_EVENT_TYPE_FILE_CREATE, context);
        __ec_do_generic_file_event(new_path_data_post_rename, CB_EVENT_TYPE_FILE_CLOSE, context);
    }

CATCH_DEFAULT:
    ec_path_cache_put(old_path_data, context);
    ec_path_cache_put(new_path_data_pre_rename, context);
    ec_path_cache_put(new_path_data_post_rename, context);

    return ret;
}

long __ec_call_orig_sys_renameat(struct rename_argblock *args)
{
    return ec_orig_sys_renameat(args->olddirfd, args->oldname, args->newdirfd, args->newname);
}

long __ec_call_orig_sys_renameat2(struct rename_argblock *args)
{
    return ec_orig_sys_renameat2(args->olddirfd, args->oldname, args->newdirfd, args->newname, args->flags);
}

long __ec_call_orig_sys_rename(struct rename_argblock *args)
{
    return ec_orig_sys_rename(args->oldname, args->newname);
}

long __ec_call_orig_sys_open(struct open_argblock *args)
{
    return ec_orig_sys_open(args->filename, args->flags, args->mode);
}

long __ec_call_orig_sys_openat(struct open_argblock *args)
{
    return ec_orig_sys_openat(args->dfd, args->filename, args->flags, args->mode);
}

long __ec_call_orig_sys_unlink(struct unlink_argblock *args)
{
    return ec_orig_sys_unlink(args->filename);
}

long __ec_call_orig_sys_unlinkat(struct unlink_argblock *args)
{
    return ec_orig_sys_unlinkat(args->dfd, args->filename, args->flags);
}

asmlinkage long ec_sys_renameat(int olddirfd, char __user const *oldname, int newdirfd, char __user const *newname)
{
    long ret = 0;
    struct rename_argblock ab = {olddirfd, oldname, newdirfd, newname, 0};

    DECLARE_NON_ATOMIC_CONTEXT(context, ec_getpid(current));

    MODULE_GET(&context);

    ret = __ec_sys_rename(__ec_call_orig_sys_renameat, &ab, &context);

    MODULE_PUT_AND_FINISH_MODULE_DISABLE_CHECK(&context);
    return ret;
}

asmlinkage long ec_sys_renameat2(int olddirfd, char __user const *oldname, int newdirfd, char __user const *newname, unsigned int flags)
{
    long ret = 0;
    struct rename_argblock ab = {olddirfd, oldname, newdirfd, newname, flags};

    DECLARE_NON_ATOMIC_CONTEXT(context, ec_getpid(current));

    MODULE_GET(&context);

    ret = __ec_sys_rename(__ec_call_orig_sys_renameat2, &ab, &context);

    MODULE_PUT_AND_FINISH_MODULE_DISABLE_CHECK(&context);
    return ret;
}

asmlinkage long ec_sys_rename(const char __user *oldname, const char __user *newname)
{
    long ret = 0;
    struct rename_argblock ab = {AT_FDCWD, oldname, AT_FDCWD, newname, 0};

    DECLARE_NON_ATOMIC_CONTEXT(context, ec_getpid(current));

    MODULE_GET(&context);

    ret = __ec_sys_rename(__ec_call_orig_sys_rename, &ab, &context);

    MODULE_PUT_AND_FINISH_MODULE_DISABLE_CHECK(&context);
    return ret;
}

asmlinkage long ec_sys_open(const char __user *filename, int flags, umode_t mode)
{
    long ret = 0;
    struct open_argblock ab = {AT_FDCWD, filename, flags, mode};

    DECLARE_NON_ATOMIC_CONTEXT(context, ec_getpid(current));

    MODULE_GET(&context);

    ret = __ec_sys_open(__ec_call_orig_sys_open, &ab, &context);

    MODULE_PUT_AND_FINISH_MODULE_DISABLE_CHECK(&context);
    return ret;
}

asmlinkage long ec_sys_openat(int dfd, const char __user *filename, int flags, umode_t mode)
{
    long ret = 0;
    struct open_argblock ab = {dfd, filename, flags, mode};

    DECLARE_NON_ATOMIC_CONTEXT(context, ec_getpid(current));

    MODULE_GET(&context);

    ret = __ec_sys_open(__ec_call_orig_sys_openat, &ab, &context);

    MODULE_PUT_AND_FINISH_MODULE_DISABLE_CHECK(&context);
    return ret;
}

asmlinkage long ec_sys_unlink(const char __user *filename)
{
    long ret = 0;
    struct unlink_argblock ab = {AT_FDCWD, filename, 0};

    DECLARE_NON_ATOMIC_CONTEXT(context, ec_getpid(current));

    MODULE_GET(&context);

    ret = __ec_sys_unlink(__ec_call_orig_sys_unlink, &ab, &context);

    MODULE_PUT_AND_FINISH_MODULE_DISABLE_CHECK(&context);
    return ret;
}

asmlinkage long ec_sys_unlinkat(int dfd, const char __user *filename, int flag)
{
    long ret = 0;
    struct unlink_argblock ab = {dfd, filename, flag};

    DECLARE_NON_ATOMIC_CONTEXT(context, ec_getpid(current));

    MODULE_GET(&context);

    ret = __ec_sys_unlink(__ec_call_orig_sys_unlinkat, &ab, &context);

    MODULE_PUT_AND_FINISH_MODULE_DISABLE_CHECK(&context);
    return ret;
}

