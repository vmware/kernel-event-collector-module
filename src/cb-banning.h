/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#pragma once

extern bool cbBanningInitialize(ProcessContext *context);
extern void cbBanningShutdown(ProcessContext *context);
extern void cbSetProtectionState(ProcessContext *context, uint32_t new_mode);
extern bool cbSetBannedProcessInode(ProcessContext *context, uint64_t device, uint64_t ino);
extern bool cbSetBannedProcessInodeWithoutKillingProcs(ProcessContext *context, uint64_t device, uint64_t ino);
extern inline bool cbClearBannedProcessInode(ProcessContext *context, uint64_t device, uint64_t ino);
extern bool cbKillBannedProcessByInode(ProcessContext *context, uint64_t device, uint64_t ino);
extern bool cbIgnoreProcess(ProcessContext *context, pid_t pid);
extern void cbSetIgnoredProcess(ProcessContext *context, pid_t pid);
extern bool cbIngoreUid(ProcessContext *context, pid_t uid);
extern void cbSetIgnoredUid(ProcessContext *context, uid_t uid);
extern void cbClearAllBans(ProcessContext *context);
extern bool cbKillBannedProcessByPid(ProcessContext *context, pid_t pid);
