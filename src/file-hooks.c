// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include "priv.h"
#include "file-types.h"
#include "process-tracking.h"
#include "file-process-tracking.h"
#include "cb-spinlock.h"
#include "path-buffers.h"
#include "cb-banning.h"
#include "event-factory.h"

#include <linux/file.h>
#include <linux/namei.h>

static FILE_PROCESS_KEY g_log_messages_file_id = {0, 0};

static bool file_exists(const char __user *filename);

#define N_ELEM(x) (sizeof(x) / sizeof(*x))

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
#define DENTRY(a)    (a)
#else
// checkpatch-ignore: COMPLEX_MACRO
#define DENTRY(a)    (a)->dentry, (a)->mnt
// checkpatch-no-ignore: COMPLEX_MACRO
#endif

typedef struct special_file_t_ {
    char *name;
    int   len;
    int   enabled;

} special_file_t;

// We collect data about a file in some of the syscall hooks.  We use this struct
//  so that we can collect data before modifying the file, but not actually use
//  it to send an event until the operation completes successfully
typedef struct file_data_t_ {
    struct filename *file_s;
    uint64_t         device;
    uint64_t         inode;
    const char      *name;
    char            *generic_path_buffer; // on the GENERIC cache
} file_data_t;

static file_data_t *get_file_data_from_name(ProcessContext *context, const char __user *filename);
static file_data_t *get_file_data_from_fd(ProcessContext *context, const char __user *filename, unsigned int fd);
static void put_file_data(ProcessContext *context, file_data_t *file_data);

#define ENABLE_SPECIAL_FILE_SETUP(x)   {x, sizeof(x)-1, 1}
#define DISABLE_SPECIAL_FILE_SETUP(x)  {x, sizeof(x)-1, 0}


//
// be sure to keep this value set to the smallest 'len' value in the
// special_files[] array below
//
#define MIN_SPECIAL_FILE_LEN 5
static const special_file_t special_files[] = {

    ENABLE_SPECIAL_FILE_SETUP("/var/lib/cb"),
    ENABLE_SPECIAL_FILE_SETUP("/var/log"),
    ENABLE_SPECIAL_FILE_SETUP("/srv/bit9/data"),
    ENABLE_SPECIAL_FILE_SETUP("/sys"),
    ENABLE_SPECIAL_FILE_SETUP("/proc"),
    DISABLE_SPECIAL_FILE_SETUP(""),
    DISABLE_SPECIAL_FILE_SETUP(""),
    DISABLE_SPECIAL_FILE_SETUP(""),
    DISABLE_SPECIAL_FILE_SETUP(""),
    DISABLE_SPECIAL_FILE_SETUP(""),
};

//
// FUNCTION:
//   is_special_file()
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
int is_special_file(char *pathname, int len)
{
    int i;

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

static void check_for_log_messages(uint64_t device, uint64_t inode, char *pathname, bool forcecheck)
{
    // If we don't know what the messages inode is then figure it out
    if (g_log_messages_file_id.inode == 0 || forcecheck)
    {
        if (strstr(pathname, "/var/log/messages") == pathname)
        {
            g_log_messages_file_id.device = device;
            g_log_messages_file_id.inode  = inode;
        }
    }
}

bool is_excluded_file(uint64_t device, uint64_t inode)
{
    // Ignore /var/log/messages
    return g_log_messages_file_id.device == device && g_log_messages_file_id.inode == inode;
}

bool is_interesting_file(struct file *file)
{
    umode_t mode = get_mode_from_file(file);

    return (S_ISREG(mode) && (!S_ISDIR(mode)) && (!S_ISLNK(mode)));
}

char *event_type_to_str(CB_EVENT_TYPE event_type)
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

//
// IMPORTANT: get_file_data_*/put_file_data MUST work regardless of whether the module is enabled
// or disabled. We call these functions from outside the active call hook tracking that prevents
// the module from disabling.
//

// Allocates a file_data_t and sets file_data->file_s to a kernelspace filename string
static file_data_t *file_data_alloc(ProcessContext *context, const char __user *filename)
{
    file_data_t *file_data           = NULL;

    TRY(filename);

    file_data = cb_mem_cache_alloc_generic(sizeof(file_data_t), context);
    TRY(file_data);

    file_data->generic_path_buffer = NULL;
    file_data->name                = NULL;

    file_data->file_s = CB_RESOLVED(getname)(filename);
    TRY(!IS_ERR_OR_NULL(file_data->file_s));
    return file_data;

CATCH_DEFAULT:
    put_file_data(context, file_data);
    return NULL;
}

// Initializes file_data members from a file struct
static void file_data_init(ProcessContext *context, file_data_t *file_data, struct file *file)
{
    char *pathname            = NULL;
    char *generic_path_buffer = NULL;

    // if the path begins with a / we know it is already absolute so we dont need to do a lookup
    // prepare to do a lookup by allocating a buffer
    if (file_data->file_s->name[0] != '/')
    {
        // need to use the generic cache because the module could disable before we are able to free
        generic_path_buffer = cb_mem_cache_alloc_generic(PATH_MAX, context);
    }

    // make sure the kmalloc succeeded
    if (generic_path_buffer)
    {
        file_get_path(file, generic_path_buffer, PATH_MAX, &pathname);
        file_data->generic_path_buffer = generic_path_buffer;
        file_data->name = pathname;
    } else
    {
        // if no path buffer that means we already have an absolute path because
        // it starts with a / or maybe the kmalloc failed. in either case just use the
        // file_s->name because it is either already absolute or if the buffer failed to
        // allocate, then we cant do the lookup anyways, so we just report the relative path
        // as a best effort.
        file_data->name = file_data->file_s->name;
    }

    get_devinfo_from_file(file, &file_data->device, &file_data->inode);
}

static file_data_t *get_file_data_from_name(ProcessContext *context, const char __user *filename)
{
    struct file *file      = NULL;
    file_data_t *file_data = file_data_alloc(context, filename);

    TRY(file_data);

    // O_NONBLOCK is needed here in case the file is a named pipe.  Otherwise we
    //   could deadlock waiting for a writer that may never come.
    file = filp_open(file_data->file_s->name, O_RDONLY|O_NONBLOCK, 0);
    TRY(!IS_ERR_OR_NULL(file));

    file_data_init(context, file_data, file);

    filp_close(file, NULL);

    return file_data;

CATCH_DEFAULT:
    put_file_data(context, file_data);
    return NULL;
}

static file_data_t *get_file_data_from_fd(ProcessContext *context, const char __user *filename, unsigned int fd)
{
    struct file *file      = NULL;
    file_data_t *file_data = file_data_alloc(context, filename);

    TRY(file_data);

    file = fget(fd);
    TRY(!IS_ERR_OR_NULL(file));

    file_data_init(context, file_data, file);

    fput(file);

    return file_data;

CATCH_DEFAULT:
    put_file_data(context, file_data);
    return NULL;
}

//
// **NOTE: put_file_data is not protected by active call hook disable tracking.
//
static void put_file_data(ProcessContext *context, file_data_t *file_data)
{
    CANCEL_VOID(file_data);

    if (!IS_ERR_OR_NULL(file_data->file_s))
    {
        CB_RESOLVED(putname)(file_data->file_s);
    }
    if (file_data->generic_path_buffer)
    {
        cb_mem_cache_free_generic(file_data->generic_path_buffer);
    }
    cb_mem_cache_free_generic(file_data);
}

static void do_generic_file_event(ProcessContext *context,
                                   file_data_t *file_data,
                                   CB_EVENT_TYPE   eventType)
{
    pid_t pid              = getpid(current);
    ProcessTracking *procp = NULL;

    TRY(file_data);

    TRY(!cbIgnoreProcess(context, pid));


    if (eventType == CB_EVENT_TYPE_FILE_DELETE)
    {
        TRACE(DL_VERBOSE, "Checking if deleted inode [%llu:%llu] was banned.", file_data->device, file_data->inode);
        if (cbClearBannedProcessInode(context, file_data->device, file_data->inode))
        {
            TRACE(DL_INFO, "[%llu:%llu] was removed from banned inode table.", file_data->device, file_data->inode);
        }
    }

    procp = get_procinfo_and_create_process_start_if_needed(pid, "Fileop", context);

    TRY(eventType != CB_EVENT_TYPE_FILE_OPEN ||
        (procp &&
         procp->shared_data && // this shouldnt ever be null but we got a segfault here so
                               // i added this check for safety
         procp->shared_data->is_interpreter));

    event_send_file(
        procp,
        eventType,
        file_data->device,
        file_data->inode,
        filetypeUnknown,
        file_data->name,
        context);

CATCH_DEFAULT:
    process_tracking_put_process(procp, context);
}

void do_file_event(ProcessContext *context, struct file *file, CB_EVENT_TYPE eventType)
{
    uint64_t            device        = 0;
    uint64_t            inode         = 0;
    FILE_PROCESS_VALUE *fileProcess   = NULL;
    char *pathname      = NULL;
    pid_t               pid           = getpid(current);
    bool                doClose       = false;
    ProcessTracking *procp         = NULL;

    CANCEL_VOID(!cbIgnoreProcess(context, pid));

    CANCEL_VOID(should_log(eventType));

    get_devinfo_from_file(file, &device, &inode);

    // Skip if not interesting
    CANCEL_VOID(is_interesting_file(file));

    // Skip if excluded
    CANCEL_VOID(!is_excluded_file(device, inode));

    // Check to see if the process is tracked already
    procp = get_procinfo_and_create_process_start_if_needed(pid, "Fileop", context);
    CANCEL_VOID(procp);

    fileProcess = file_process_status(device, inode, pid, context);
    if (fileProcess && fileProcess->status == OPENED)
    {
        pathname = fileProcess->path;
        TRY_MSG(eventType != CB_EVENT_TYPE_FILE_WRITE,
                DL_INFO, "[%llu:%llu] process:%u written before", device, inode, pid);

        if (eventType == CB_EVENT_TYPE_FILE_CLOSE || eventType == CB_EVENT_TYPE_FILE_DELETE)
        {
            TRACE(DL_INFO, "[%llu:%llu] process:%u closed or deleted", device, inode, pid);
            // I still need to use the path buffer from fileProcess, so don't call
            //  file_process_status_close until later.
            doClose = true;
        }
    } else //status == CLOSED
    {
        // If this file is deleted already, then just skip it
        TRY(!d_unlinked(file->f_path.dentry));

        if (eventType == CB_EVENT_TYPE_FILE_WRITE)
        {
            bool  isSpecialFile = false;
            char *string_buffer = get_path_buffer(context);

            if (string_buffer)
            {
                // file_get_path() uses dpath which builds the path efficently
                //  by walking back to the root. It starts with a string terminator
                //  in the last byte of the target buffer and needs to be copied
                //  with memmove to adjust
                // Note for CB-6707: The 3.10 kernel occasionally crashed in d_path when the file was closed.
                //  The workaround used dentry->d_iname instead. But this only provided the short name and
                //  not the whole path.  The daemon could no longer match the lastWrite to the firstWrite.
                //  I am now only calling this with an open file now so we should be fine.
                file_get_path(file, string_buffer, PATH_MAX, &pathname);
                if (pathname)
                {
                    // Check to see if this is a special file that we will not send an event for.  It will save
                    //  us at least one check in the future.
                    isSpecialFile = is_special_file(pathname, strlen(pathname));
                }
            }

            TRACE(DL_INFO, "[%llu:%llu] process:%u first write", device, inode, pid);
            fileProcess = file_process_status_open(device,
                                                   inode,
                                                   pid,
                                                   pathname,
                                                   isSpecialFile,
                                                   context);
            put_path_buffer(string_buffer);

            TRY(fileProcess);
            pathname = fileProcess->path;

            // If this file has been written to AND that files inode is in the banned list
            // we need to remove it on the assumption that the md5 will have changed. It is
            // entirely possible that the exact bits are written back, but in that case we
            // will catch it in user space, by md5, and notify kernel to kill and ban if necessary.
            //
            // This should be a fairly lightweight call as it is inlined and the hashtable is usually
            // empty and if not is VERY small.
            if (cbClearBannedProcessInode(context, device, inode))
            {
                TRACE(DL_INFO, "[%llu:%llu] was removed from banned inode table.", device, inode);
            }
        } else if (eventType == CB_EVENT_TYPE_FILE_CLOSE)
        {
            TRACE(DL_VERBOSE, "[%llu:%llu] process:%u NOT written before", device, inode, pid);
            goto CATCH_DEFAULT;
        }
    }

    if (pathname && strlen(pathname) > 0)
    {
        if (pathname[0] == '/')
        {
            //
            // Log it
            //
            check_for_log_messages(device, inode, pathname, true);
            if (!fileProcess->isSpecialFile)
            {
                event_send_file(
                    procp,
                    eventType,
                    device,
                    inode,
                    fileProcess->fileType,
                    pathname,
                    context);
            }
        } else if (pathname[0] == '[' && eventType == CB_EVENT_TYPE_FILE_WRITE)
        {
            // CEL This is a noop as we can see [eventfd] on a write and we don't care about it
        }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
        else if (eventType == CB_EVENT_TYPE_FILE_CLOSE)
        {
            event_send_file(
                procp,
                eventType,
                device,
                inode,
                fileProcess->fileType,
                pathname,
                context);
        }
#endif
        else
        {
            TRACE(DL_INFO, "invalid full path %s event %d", pathname, eventType);
        }
    }

CATCH_DEFAULT:
    process_tracking_put_process(procp, context);
    if (doClose)
    {
        file_process_status_close(device, inode, pid, context);
    }

    return;
}

long (*cb_orig_sys_write)(unsigned int fd, const char __user *buf, size_t count);
long (*cb_orig_sys_close)(unsigned int fd);

long (*cb_orig_sys_open)(const char __user *filename, int flags, umode_t mode);
long (*cb_orig_sys_openat)(int dfd, const char __user *filename, int flags, umode_t mode);
long (*cb_orig_sys_creat)(const char __user *filename, umode_t mode);
long (*cb_orig_sys_unlink)(const char __user *filename);
long (*cb_orig_sys_unlinkat)(int dfd, const char __user *pathname, int flag);
long (*cb_orig_sys_rename)(const char __user *oldname, const char __user *newname);

// This detects the file type after the first write happens.  We still send the events
//  from the LSM hook because the kernel panics the second time a file is opened when we
//  attempt to read the path from this hook.
// Because we detect the type after the first write, I added logic that will redetect the
//  type  on a write to the beginning of the file.  (So if the file type changes we will
//  detect it.)
// NOTE: I have to read the file type here so I have access to the numer bytes written to
//  the file.  I need this to decide if we wrote into the area that will help us identify
//  the file type.
asmlinkage long cb_sys_write(unsigned int fd, const char __user *buf, size_t count)
{
    long                ret;
    uint64_t            device        = 0;
    uint64_t            inode         = 0;
    FILE_PROCESS_VALUE *fileProcess   = NULL;
    struct file *file          = NULL;

    DECLARE_NON_ATOMIC_CONTEXT(context, getpid(current));

    MODULE_GET();

    // Do the actual write first.  This way if the type is changed we will detect it later.
    ret = cb_orig_sys_write(fd, buf, count);
    TRY(ret > -1);

    BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(&context, CATCH_DEFAULT);

    // Get a local reference to the file
    file = fget(fd);
    TRY(file != NULL);

    TRY(!may_skip_unsafe_vfs_calls(file));

    do_file_event(&context, file, CB_EVENT_TYPE_FILE_WRITE);

    TRY(S_ISREG(get_mode_from_file(file)));

    get_devinfo_from_file(file, &device, &inode);

    fileProcess = file_process_status(device, inode, getpid(current), &context);

    // I did not bother to do all the checks we do in the other hook to see if this file
    //  should be ignored.  If this check passes we know this is a file we care about
    if (fileProcess && !fileProcess->isSpecialFile)
    {
        loff_t         pos_orig      = file->f_pos;

        // If we detect this is the first write or that a write happened near the start of the file attempt to detect the type.
        if (!fileProcess->didReadType || (pos_orig - ret) < MAX_FILE_BYTES_TO_DETERMINE_TYPE)
        {
            char           buffer[MAX_FILE_BYTES_TO_DETERMINE_TYPE];
            CB_FILE_TYPE   fileType = filetypeUnknown;
            loff_t         pos      = 0;
            ssize_t        size     = 0;
            mm_segment_t   oldfs    = get_fs();
            fmode_t        mode;

            // Seek to the beginning of the file so we can read the data we want.
            TRY(-1 < vfs_llseek(file, 0, SEEK_SET));

            // Save the real mode and force the ability to read in case the file was opened write only
            mode = file->f_mode;
            file->f_mode |= FMODE_READ;

            // Disable memory checks because we are passing in a kernel buffer instead of a user buffer
            set_fs(KERNEL_DS);
            size = vfs_read(file, buffer, MAX_FILE_BYTES_TO_DETERMINE_TYPE, &pos);
            set_fs(oldfs);

            // Restore the real file mode
            file->f_mode = mode;

            if (size > 0)
            {
                FILE_PROCESS_VALUE updateFileProcess;

                determine_file_type(buffer, size, &fileType, true);
                updateFileProcess.fileType    = fileType;
                updateFileProcess.didReadType = true;

                file_process_status_update(device, inode, getpid(current), &updateFileProcess, &context);
            }

            // Seek back to where the file was be so that the next write will work
            TRY(-1 < vfs_llseek(file, pos_orig, SEEK_SET));
        }
    }

CATCH_DEFAULT:
    if (file)
    {
        fput(file);
    }
    MODULE_PUT_AND_FINISH_MODULE_DISABLE_CHECK(&context);
    return ret;
}

asmlinkage long cb_sys_close(unsigned int fd)
{
    long                ret;
    struct file *file          = NULL;

    DECLARE_NON_ATOMIC_CONTEXT(context, getpid(current));

    MODULE_GET_AND_BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(&context, CATCH_DEFAULT);

    // Get a local reference to the file
    file = fget(fd);
    TRY(file != NULL);

    do_file_event(&context, file, CB_EVENT_TYPE_FILE_CLOSE);

CATCH_DEFAULT:
    if (file)
    {
        fput(file);
    }

    ret = cb_orig_sys_close(fd);

    MODULE_PUT_AND_FINISH_MODULE_DISABLE_CHECK(&context);
    return ret;
}

asmlinkage long cb_sys_open(const char __user *filename, int flags, umode_t mode)
{
    long                ret;
    CB_EVENT_TYPE       eventType = 0;

    DECLARE_NON_ATOMIC_CONTEXT(context, getpid(current));

    MODULE_GET_AND_IF_MODULE_DISABLED_GOTO(&context, CATCH_DISABLED);

    if ((flags & O_CREAT) && !file_exists(filename))
    {
        // If this is opened with create mode AND it does not already exist we will report a create event
        eventType = CB_EVENT_TYPE_FILE_CREATE;
    } else if (!(flags & (O_RDWR | O_WRONLY)))
    {
        // If the file is opened with read-only mode we will report an open event
        eventType = CB_EVENT_TYPE_FILE_OPEN;
    }

CATCH_DISABLED:
    ret = cb_orig_sys_open(filename, flags, mode);

    BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(&context, CATCH_DEFAULT);

    if (!IS_ERR_VALUE(ret) && eventType)
    {
        file_data_t *file_data = get_file_data_from_fd(&context, filename, ret);

        do_generic_file_event(&context, file_data, eventType);
        put_file_data(&context, file_data);
    }

CATCH_DEFAULT:
    MODULE_PUT_AND_FINISH_MODULE_DISABLE_CHECK(&context);
    return ret;
}

asmlinkage long cb_sys_openat(int dfd, const char __user *filename, int flags, umode_t mode)
{
    long ret;
    CB_EVENT_TYPE       eventType = 0;

    DECLARE_NON_ATOMIC_CONTEXT(context, getpid(current));

    MODULE_GET_AND_IF_MODULE_DISABLED_GOTO(&context, CATCH_DISABLED);

    if ((flags & O_CREAT) && !file_exists(filename))
    {
        // If this is opened with create mode AND it does not already exist we will report a create event
        eventType = CB_EVENT_TYPE_FILE_CREATE;
    } else if (!(flags & (O_RDWR | O_WRONLY)))
    {
        // If the file is opened with read-only mode we will report an open event
        eventType = CB_EVENT_TYPE_FILE_OPEN;
    }

CATCH_DISABLED:
    ret = cb_orig_sys_openat(dfd, filename, flags, mode);

    BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(&context, CATCH_DEFAULT);

    if (!IS_ERR_VALUE(ret) && eventType)
    {
        file_data_t *file_data = get_file_data_from_fd(&context, filename, ret);

        do_generic_file_event(&context, file_data, eventType);
        put_file_data(&context, file_data);
    }

CATCH_DEFAULT:
    MODULE_PUT_AND_FINISH_MODULE_DISABLE_CHECK(&context);
    return ret;
}

asmlinkage long cb_sys_creat(const char __user *filename, umode_t mode)
{
    long ret;
    bool report_create = false;

    DECLARE_NON_ATOMIC_CONTEXT(context, getpid(current));

    MODULE_GET_AND_IF_MODULE_DISABLED_GOTO(&context, CATCH_DISABLED);

    // If this is opened with create mode AND it does not already exist we
    //  will report an event
    report_create = (!file_exists(filename));

CATCH_DISABLED:
    ret = cb_orig_sys_creat(filename, mode);

    BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(&context, CATCH_DEFAULT);

    if (!IS_ERR_VALUE(ret) && report_create)
    {
        file_data_t *file_data = get_file_data_from_fd(&context, filename, ret);

        do_generic_file_event(&context, file_data, CB_EVENT_TYPE_FILE_CREATE);
        put_file_data(&context, file_data);
    }

CATCH_DEFAULT:
    MODULE_PUT_AND_FINISH_MODULE_DISABLE_CHECK(&context);
    return ret;
}

asmlinkage long cb_sys_unlink(const char __user *filename)
{
    long         ret;
    file_data_t *file_data = NULL;

    DECLARE_NON_ATOMIC_CONTEXT(context, getpid(current));

    // get_file_data_from_name can block if the device is unavailable (e.g. network timeout)
    // so do not begin hook tracking yet, to avoid blocking module disable
    MODULE_GET_AND_IF_MODULE_DISABLED_GOTO(&context, CATCH_DISABLED);

    // Collect data about the file before it is modified.  The event will be sent
    //  after a successful operation
    file_data = get_file_data_from_name(&context, filename);

CATCH_DISABLED:
    ret = cb_orig_sys_unlink(filename);

    BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(&context, CATCH_DEFAULT);

    // Now the active count is incremented and the hook is being tracked

    if (!IS_ERR_VALUE(ret) && file_data)
    {
        do_generic_file_event(&context, file_data, CB_EVENT_TYPE_FILE_DELETE);
    }

CATCH_DEFAULT:
    // Note: file_data is destroyed by do_generic_file_event
    put_file_data(&context, file_data);

    MODULE_PUT_AND_FINISH_MODULE_DISABLE_CHECK(&context);
    return ret;
}

asmlinkage long cb_sys_unlinkat(int dfd, const char __user *filename, int flag)
{
    long         ret;
    file_data_t *file_data = NULL;

    DECLARE_NON_ATOMIC_CONTEXT(context, getpid(current));

    // get_file_data_from_name can block if the device is unavailable (e.g. network timeout)
    // so do not begin hook tracking yet, since that can block module disable
    MODULE_GET_AND_IF_MODULE_DISABLED_GOTO(&context, CATCH_DISABLED);

    // Collect data about the file before it is modified.  The event will be sent
    //  after a successful operation
    file_data = get_file_data_from_name(&context, filename);

CATCH_DISABLED:
    ret = cb_orig_sys_unlinkat(dfd, filename, flag);

    BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(&context, CATCH_DEFAULT);

    // Now the active count is incremented and the hook is being tracked

    if (!IS_ERR_VALUE(ret) && file_data)
    {
        do_generic_file_event(&context, file_data, CB_EVENT_TYPE_FILE_DELETE);
    }

CATCH_DEFAULT:
    // Note: file_data is destroyed by do_generic_file_event
    put_file_data(&context, file_data);

    MODULE_PUT_AND_FINISH_MODULE_DISABLE_CHECK(&context);
    return ret;
}

asmlinkage long cb_sys_rename(const char __user *oldname, const char __user *newname)
{
    long         ret;
    file_data_t *old_file_data = NULL;
    file_data_t *new_file_data = NULL;

    DECLARE_NON_ATOMIC_CONTEXT(context, getpid(current));

    // get_file_data_from_name can block if the device is unavailable (e.g. network timeout)
    // so do not begin hook tracking yet, since that can block module disable
    MODULE_GET_AND_IF_MODULE_DISABLED_GOTO(&context, CATCH_DISABLED);

    // Collect data about the file before it is modified.  The event will be sent
    //  after a successful operation
    old_file_data = get_file_data_from_name(&context, oldname);

CATCH_DISABLED:
    ret = cb_orig_sys_rename(oldname, newname);

    BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(&context, CATCH_DEFAULT);

    // Now the active count is incremented and the hook is being tracked

    if (!IS_ERR_VALUE(ret) && old_file_data)
    {
        do_generic_file_event(&context, old_file_data, CB_EVENT_TYPE_FILE_DELETE);

        FINISH_MODULE_DISABLE_CHECK(&context);

        // This could block so call it outside the disable tracking
        new_file_data = get_file_data_from_name(&context, newname);

        BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(&context, CATCH_DEFAULT);

        do_generic_file_event(&context, new_file_data, CB_EVENT_TYPE_FILE_CREATE);
    }

CATCH_DEFAULT:
    put_file_data(&context, old_file_data);
    put_file_data(&context, new_file_data);

    MODULE_PUT_AND_FINISH_MODULE_DISABLE_CHECK(&context);
    return ret;
}

static bool file_exists(const char __user *filename)
{
    bool         exists     = false;
    struct path path;

    TRY(filename);

    exists = user_path(filename, &path) == 0;

CATCH_DEFAULT:
    if (exists)
    {
        path_put(&path);
    }

    return exists;
}
