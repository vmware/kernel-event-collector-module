// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include "priv.h"
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
#include <linux/binfmts.h>
#include <linux/cred.h>
#endif
#include <linux/signal.h>

#include "hash-table-generic.h"
#include "process-tracking.h"
#include "event-factory.h"
#include "mem-alloc.h"

typedef struct bl_table_key {
    uint64_t    device;
    uint64_t    inode;
} BL_TBL_KEY;

typedef struct banning_entry_s {
    HashTableNode link;
    BL_TBL_KEY    key;
    uint64_t hash;
    uint64_t    device;
    uint64_t    inode;
} BanningEntry;

#define CB_BANNING_CACHE_OBJ_SZ 64

static struct
{
    HashTbl    *banning_table;
    uint32_t    protectionModeEnabled;
    uint64_t    ignored_pid_count;
    pid_t       ignored_pids[CB_SENSOR_MAX_PIDS];
    int64_t     ignored_uid_count;
    uid_t       ignored_uids[CB_SENSOR_MAX_UIDS];
} s_banning;

void ec_banning_KillRunningBannedProcessByInode(ProcessContext *context, uint64_t device, uint64_t ino);

bool ec_banning_initialize(ProcessContext *context)
{
    s_banning.protectionModeEnabled = PROTECTION_ENABLED;
    memset(&s_banning.ignored_pids[0], 0, sizeof(pid_t)*CB_SENSOR_MAX_PIDS);
    memset(&s_banning.ignored_uids[0], 0xFF, sizeof(uid_t)*CB_SENSOR_MAX_PIDS);

    s_banning.banning_table = ec_hashtbl_init_generic(context,
                                           8192,
                                           sizeof(BanningEntry),
                                           CB_BANNING_CACHE_OBJ_SZ,
                                           "banning_cache",
                                           sizeof(BL_TBL_KEY),
                                           offsetof(BanningEntry, key),
                                           offsetof(BanningEntry, link),
                                           HASHTBL_DISABLE_REF_COUNT,
                                           HASHTBL_DISABLE_LRU,
                                           NULL,
                                           NULL);

    if (!s_banning.banning_table)
    {
        return false;
    }

    return true;
}

void ec_banning_shutdown(ProcessContext *context)
{
    if (s_banning.banning_table)
    {
        ec_hashtbl_shutdown_generic(s_banning.banning_table, context);
    }
}

void ec_banning_SetProtectionState(ProcessContext *context, uint32_t new_state)
{
    uint32_t current_state = s_banning.protectionModeEnabled;

    if (current_state == new_state)
    {
        return;
    }

    TRACE(DL_INFO, "Setting protection state to %u", new_state);
    s_banning.protectionModeEnabled = new_state;
}

bool ec_banning_SetBannedProcessInodeWithoutKillingProcs(ProcessContext *context, uint64_t device, uint64_t ino)
{
    BanningEntry *bep;

    TRACE(DL_INFO, "Recevied [%llu:%llu] inode", device, ino);

    bep = (BanningEntry *)ec_hashtbl_alloc_generic(s_banning.banning_table, context);
    if (bep == NULL)
    {
        return false;
    }

    bep->key.device = device;
    bep->key.inode = ino;
    bep->hash = 0;
    bep->device = device;
    bep->inode = ino;

    if (ec_hashtbl_add_generic_safe(s_banning.banning_table, bep, context) < 0)
    {
        ec_hashtbl_free_generic(s_banning.banning_table, bep, context);
        return false;
    }

    return true;
}

bool ec_banning_SetBannedProcessInode(ProcessContext *context, uint64_t device, uint64_t ino)
{
    bool retval;

    retval = ec_banning_SetBannedProcessInodeWithoutKillingProcs(context, device, ino);
    ec_banning_KillRunningBannedProcessByInode(context, device, ino);

    return retval;
}

inline bool ec_banning_ClearBannedProcessInode(ProcessContext *context, uint64_t device, uint64_t ino)
{
    BanningEntry *bep;
    BL_TBL_KEY key = { device, ino };

    if (ino == 0)
    {
        return false;
    }

    bep = (BanningEntry *) ec_hashtbl_del_by_key_generic(s_banning.banning_table, &key, context);
    if (!bep)
    {
        return false;
    }
    TRACE(DL_INFO, "Clearing banned file [%llu:%llu]", device, ino);

    ec_hashtbl_free_generic(s_banning.banning_table, bep, context);
    return true;
}

void ec_banning_ClearAllBans(ProcessContext *context)
{
    TRACE(DL_INFO, "Clearing all bans");
    ec_hashtbl_clear_generic(s_banning.banning_table, context);
}

bool ec_banning_KillBannedProcessByInode(ProcessContext *context, uint64_t device, uint64_t ino)
{
    BanningEntry *bep;
    BL_TBL_KEY key = { device, ino };

    if (s_banning.protectionModeEnabled == PROTECTION_DISABLED)
    {
        TRACE(DL_VERBOSE, "protection is disabled");
        goto kbpbi_exit;
    }

    TRACE(DL_VERBOSE, "Check for banned file [%llu:%llu]", device, ino);
    if (ino == 0)
    {
        goto kbpbi_exit;
    }

    bep = (BanningEntry *) ec_hashtbl_get_generic(s_banning.banning_table, &key, context);
    if (!bep)
    {
        TRACE(DL_INFO, "kill banned process failed to find [%llu:%llu]", device, ino);
        goto kbpbi_exit;
    }

    if (device == bep->device && ino == bep->inode)
    {
        TRACE(DL_INFO, "Banned [%llu:%llu]", device, ino);
        return true;
    }

kbpbi_exit:
    return false;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0) && RHEL_MINOR >= 1  //{
#define my_siginfo kernel_siginfo
#else  //}{
#define my_siginfo siginfo
#endif //}

void ec_banning_KillRunningBannedProcessByInode(ProcessContext *context, uint64_t device, uint64_t ino)
{
    pid_t pid = 0;
    struct my_siginfo info;
    int ret;
    struct list_head *pos, *safe_del;
    RUNNING_BANNED_INODE_S sRunningInodesToBan;
    RUNNING_PROCESSES_TO_BAN *temp = NULL;

    if (s_banning.protectionModeEnabled == PROTECTION_DISABLED)
    {
        TRACE(DL_VERBOSE, "protection is disabled");
        return;
    }

    TRACE(DL_ERROR, "Kill process with [%llu:%llu]", device, ino);

    memset(&info, 0, sizeof(info));
    info.si_signo = SIGKILL;
    info.si_code = 0;
    info.si_errno = 1234;

    memset(&sRunningInodesToBan, 0, sizeof(RUNNING_BANNED_INODE_S));
    sRunningInodesToBan.device = device;
    sRunningInodesToBan.inode  = ino;
    sRunningInodesToBan.count  = 0;
    INIT_LIST_HEAD(&sRunningInodesToBan.BanList.list);

    ec_is_process_tracked_get_state_by_inode(&sRunningInodesToBan, context);

    if (!sRunningInodesToBan.count)
    {
        TRACE(DL_INFO, "%s: failed to find process with [%llu:%llu]", __func__, device, ino);
        return;
    }

    list_for_each(pos, &sRunningInodesToBan.BanList.list)
    {
        struct task_struct const *task = NULL;
        ProcessHandle *process_handle = (ProcessHandle *)(list_entry(pos, RUNNING_PROCESSES_TO_BAN, list)->process_handle);

        if (process_handle)
        {
            pid = ec_process_posix_identity(process_handle)->pt_key.pid;

            task = ec_find_task(pid);
            if (task)
            {
                ret = send_sig_info(SIGKILL, &info, (struct task_struct *) task);
                if (!ret)
                {
                    TRACE(DL_ERROR, "%s: killed process with [%llu:%llu] pid=%d", __func__, device, ino, pid);

                    // Send the event
                    ec_event_send_block(process_handle,
                                        ProcessTerminatedAfterStartup,
                                        TerminateFailureReasonNone,
                                        0,
                                        ec_process_tracking_should_track_user() ? ec_process_posix_identity(process_handle)->uid : (uid_t) -1,
                                        NULL,
                                        context);
                    continue;
                }
            }
        }

        TRACE(DL_INFO, "%s: error sending kill to process with [%llu:%llu] pid=%d", __func__, device, ino, pid);
    }

    //Clean up the list
    list_for_each_safe(pos, safe_del, &sRunningInodesToBan.BanList.list)
    {
        temp = list_entry(pos, RUNNING_PROCESSES_TO_BAN, list);
        ec_process_tracking_put_handle(temp->process_handle, context);
        list_del(pos);
        ec_mem_free(temp);
    }

    memset(&sRunningInodesToBan, 0, sizeof(RUNNING_BANNED_INODE_S));
}

bool ec_banning_IgnoreProcess(ProcessContext *context, pid_t pid)
{
    int64_t i;
    int64_t max = s_banning.ignored_pid_count;

    TRACE(DL_TRACE, "Test if pid=%u should be ignored count=%lld", pid, max);

    if (max == 0)
    {
        goto ignore_process_exit;
    }

    for (i = 0; i < max; ++i)
    {
        if (s_banning.ignored_pids[i] == pid)
        {
            TRACE(DL_TRACE, "Ignore pid=%u", pid);
            return true;
        }
    }

ignore_process_exit:
    return false;
}

void ec_banning_SetIgnoredProcess(ProcessContext *context, pid_t pid)
{
    int64_t i;
    int64_t max = s_banning.ignored_pid_count;

    // Search for pid
    for (i = 0; i < max; ++i)
    {
        if (s_banning.ignored_pids[i] == pid)
        {
            TRACE(DL_VERBOSE, "already ignoring pid=%u", pid);
            return;
        }
    }

    if (max < CB_SENSOR_MAX_PIDS)
    {
        s_banning.ignored_pids[max] = pid;
        max += 1;
        s_banning.ignored_pid_count = max;
        TRACE(DL_INFO, "Adding pid=%u at %lld", pid, max);
    }
}

bool ec_banning_IgnoreUid(ProcessContext *context, pid_t uid)
{
    int64_t i;
    int64_t max = s_banning.ignored_uid_count;

    TRACE(DL_TRACE, "Test if uid=%u should be ignored", uid);

    if (max == 0)
    {
        goto ignore_uid_exit;
    }

    for (i = 0; i < max; ++i)
    {
        if (s_banning.ignored_uids[i] == uid)
        {
            TRACE(DL_TRACE, "Ignore uid=%u", uid);
            return true;
        }
    }

ignore_uid_exit:
    return false;
}

void ec_banning_SetIgnoredUid(ProcessContext *context, uid_t uid)
{
    int64_t i;
    int64_t max = s_banning.ignored_uid_count;

    // Search for uid
    for (i = 0; i < max; ++i)
    {
        if (s_banning.ignored_uids[i] == uid)
        {
            TRACE(DL_VERBOSE, "already ignoring uid=%u", uid);
            return;
        }
    }

    if (max < CB_SENSOR_MAX_UIDS)
    {
        s_banning.ignored_uids[max] = uid;
        max += 1;
        s_banning.ignored_uid_count = max;
        TRACE(DL_WARNING, "Adding uid=%u at %lld", uid, max);
    }
}
