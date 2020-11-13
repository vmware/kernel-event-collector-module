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
HashTbl * g_banning_table = NULL;
int64_t  g_banned_process_by_inode_count;
uint32_t g_protectionModeEnabled = PROTECTION_ENABLED; // Default to enabled

static void cbKillRunningBannedProcessByInode(ProcessContext *context, uint64_t device, uint64_t ino);

bool cbBanningInitialize(ProcessContext *context)
{
    g_protectionModeEnabled = PROTECTION_ENABLED;
    g_banned_process_by_inode_count = 0;
    g_banning_table = hashtbl_init_generic(context,
                                           8192,
                                           sizeof(BanningEntry),
                                           CB_BANNING_CACHE_OBJ_SZ,
                                           "banning_cache",
                                           sizeof(BL_TBL_KEY),
                                           offsetof(BanningEntry, key),
                                           offsetof(BanningEntry, link),
                                           HASHTBL_DISABLE_REF_COUNT,
                                           NULL);

    if (!g_banning_table)
    {
        return false;
    }

    return true;
}

void cbBanningShutdown(ProcessContext *context)
{
    if (g_banning_table)
    {
        hashtbl_shutdown_generic(g_banning_table, context);
    }
}

void cbSetProtectionState(ProcessContext *context, uint32_t new_state)
{
    uint32_t current_state = atomic_read((atomic_t *)&g_protectionModeEnabled);

    if (current_state == new_state)
    {
        return;
    }

    TRACE(DL_INFO, "Setting protection state to %u", new_state);
    atomic_set((atomic_t *)&g_protectionModeEnabled, new_state);
}

bool cbSetBannedProcessInodeWithoutKillingProcs(ProcessContext *context, uint64_t device, uint64_t ino)
{
    BanningEntry *bep;
    int64_t i = atomic64_read((atomic64_t *)&g_banned_process_by_inode_count);

    TRACE(DL_INFO, "Recevied [%llu:%llu] inode count=%lld", device, ino, i);

    bep = (BanningEntry *)hashtbl_alloc_generic(g_banning_table, context);
    if (bep == NULL)
    {
        return false;
    }

    bep->key.device = device;
    bep->key.inode = ino;
    bep->hash = 0;
    bep->device = device;
    bep->inode = ino;

    if (hashtbl_add_generic_safe(g_banning_table, bep, context) < 0)
    {
        hashtbl_free_generic(g_banning_table, bep, context);
        return false;
    }

    atomic64_inc((atomic64_t *)&g_banned_process_by_inode_count);
    return true;
}

bool cbSetBannedProcessInode(ProcessContext *context, uint64_t device, uint64_t ino)
{
    bool retval;

    retval = cbSetBannedProcessInodeWithoutKillingProcs(context, device, ino);
    cbKillRunningBannedProcessByInode(context, device, ino);

    return retval;
}

inline bool cbClearBannedProcessInode(ProcessContext *context, uint64_t device, uint64_t ino)
{
    int64_t count = atomic64_read((atomic64_t *)&g_banned_process_by_inode_count);
    BanningEntry *bep;
    BL_TBL_KEY key = { device, ino };

    if (count == 0 || ino == 0)
    {
        return false;
    }

    bep = (BanningEntry *) hashtbl_del_by_key_generic(g_banning_table, &key, context);
    if (!bep)
    {
        return false;
    }
    TRACE(DL_INFO, "Clearing banned file [%llu:%llu] count=%lld", device, ino, count);

    hashtbl_free_generic(g_banning_table, bep, context);
    atomic64_dec((atomic64_t *)&g_banned_process_by_inode_count);
    return true;
}

void cbClearAllBans(ProcessContext *context)
{
    int64_t count = atomic64_read((atomic64_t *)&g_banned_process_by_inode_count);

    if (count == 0)
    {
        return;
    }

    TRACE(DL_INFO, "Clearing all bans");
    atomic64_set((atomic64_t *)&g_banned_process_by_inode_count, 0);
    hashtbl_clear_generic(g_banning_table, context);
}

bool cbKillBannedProcessByInode(ProcessContext *context, uint64_t device, uint64_t ino)
{
    int64_t count;
    BanningEntry *bep;
    BL_TBL_KEY key = { device, ino };

    if (atomic_read((atomic_t *)&g_protectionModeEnabled) == PROTECTION_DISABLED)
    {
        TRACE(DL_VERBOSE, "protection is disabled");
        goto kbpbi_exit;
    }

    count = atomic64_read((atomic64_t *)&g_banned_process_by_inode_count);
    TRACE(DL_VERBOSE, "Check for banned file [%llu:%llu] count=%lld", device, ino, count);
    if (count == 0 || ino == 0)
    {
        goto kbpbi_exit;
    }

    bep = (BanningEntry *) hashtbl_get_generic(g_banning_table, &key, context);
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

static void cbKillRunningBannedProcessByInode(ProcessContext *context, uint64_t device, uint64_t ino)
{
    pid_t pid;
    struct siginfo info;
    int ret;
    struct list_head *pos, *safe_del;
    ProcessTracking *procp = NULL;
    RUNNING_BANNED_INODE_S sRunningInodesToBan;
    RUNNING_PROCESSES_TO_BAN *temp = NULL;

    if (atomic_read((atomic_t *)&g_protectionModeEnabled) == PROTECTION_DISABLED)
    {
        TRACE(DL_VERBOSE, "protection is disabled");
        return;
    }

    TRACE(DL_ERROR, "Kill process with [%llu:%llu]", device, ino);

    memset(&info, 0, sizeof(struct siginfo));
    info.si_signo = SIGKILL;
    info.si_code = 0;
    info.si_errno = 1234;

    memset(&sRunningInodesToBan, 0, sizeof(RUNNING_BANNED_INODE_S));
    sRunningInodesToBan.device = device;
    sRunningInodesToBan.inode  = ino;
    sRunningInodesToBan.count  = 0;
    INIT_LIST_HEAD(&sRunningInodesToBan.BanList.list);

    is_process_tracked_get_state_by_inode(&sRunningInodesToBan, context);

    if (!sRunningInodesToBan.count)
    {
        TRACE(DL_INFO, "%s: failed to find process with [%llu:%llu]", __func__, device, ino);
        return;
    }

    list_for_each(pos, &sRunningInodesToBan.BanList.list)
    {
        struct task_struct *task = NULL;

        procp = (ProcessTracking *)(list_entry(pos, RUNNING_PROCESSES_TO_BAN, list)->procp);
        pid = procp->pt_key.pid;

        task = cb_find_task(pid);
        if (task)
        {
            ret = send_sig_info(SIGKILL, &info, task);
            if (!ret)
            {
                TRACE(DL_ERROR, "%s: killed process with [%llu:%llu] pid=%d", __func__, device, ino, pid);

                // Send the event
                event_send_block(procp,
                                 ProcessTerminatedAfterStartup,
                                 TerminateFailureReasonNone,
                                 0,
                                 process_tracking_should_track_user() ? procp->uid : (uid_t)-1,
                                 NULL,
                                 context);
                continue;
            }
        }

        TRACE(DL_INFO, "%s: error sending kill to process with [%llu:%llu] pid=%d", __func__, device, ino, pid);
    }

    //Clean up the list
    list_for_each_safe(pos, safe_del, &sRunningInodesToBan.BanList.list)
    {
        temp = list_entry(pos, RUNNING_PROCESSES_TO_BAN, list);
        list_del(pos);
        cb_mem_cache_free_generic(temp);
    }

    memset(&sRunningInodesToBan, 0, sizeof(RUNNING_BANNED_INODE_S));
}

bool cbIgnoreProcess(ProcessContext *context, pid_t pid)
{
    int64_t i;
    int64_t max = atomic64_read((atomic64_t *)&g_cb_ignored_pid_count);

    TRACE(DL_TRACE, "Test if pid=%u should be ignored count=%lld", pid, max);

    if (max == 0)
    {
        goto ignore_process_exit;
    }

    for (i = 0; i < max; ++i)
    {
        if (g_cb_ignored_pids[i] == pid)
        {
            TRACE(DL_TRACE, "Ignore pid=%u", pid);
            return true;
        }
    }

ignore_process_exit:
    return false;
}

void cbSetIgnoredProcess(ProcessContext *context, pid_t pid)
{
    int64_t i;
    int64_t max = atomic64_read((atomic64_t *)&g_cb_ignored_pid_count);

    // Search for pid
    for (i = 0; i < max; ++i)
    {
        if (g_cb_ignored_pids[i] == pid)
        {
            TRACE(DL_VERBOSE, "already ignoring pid=%u", pid);
            return;
        }
    }

    if (max < CB_SENSOR_MAX_PIDS)
    {
        g_cb_ignored_pids[max] = pid;
        max += 1;
        atomic64_set((atomic64_t *)&g_cb_ignored_pid_count, max);
        TRACE(DL_WARNING, "Adding pid=%u at %lld", pid, max);
    }
}

bool cbIngoreUid(ProcessContext *context, pid_t uid)
{
    int64_t i;
    int64_t max = atomic64_read((atomic64_t *)&g_cb_ignored_uid_count);

    TRACE(DL_TRACE, "Test if uid=%u should be ignored", uid);

    if (max == 0)
    {
        goto ignore_uid_exit;
    }

    for (i = 0; i < max; ++i)
    {
        if (g_cb_ignored_uids[i] == uid)
        {
            TRACE(DL_TRACE, "Ignore uid=%u", uid);
            return true;
        }
    }

ignore_uid_exit:
    return false;
}

void cbSetIgnoredUid(ProcessContext *context, uid_t uid)
{
    int64_t i;
    int64_t max = atomic64_read((atomic64_t *)&g_cb_ignored_uid_count);

    // Search for uid
    for (i = 0; i < max; ++i)
    {
        if (g_cb_ignored_uids[i] == uid)
        {
            TRACE(DL_VERBOSE, "already ignoring uid=%u", uid);
            return;
        }
    }

    if (max < CB_SENSOR_MAX_UIDS)
    {
        g_cb_ignored_uids[max] = uid;
        max += 1;
        atomic64_set((atomic64_t *)&g_cb_ignored_uid_count, max);
        TRACE(DL_WARNING, "Adding uid=%u at %lld", uid, max);
    }
}
