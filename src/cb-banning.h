#ifndef __CB_BANNING__
#define __CB_BANNING__

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

#endif
