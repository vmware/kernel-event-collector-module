// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include "priv.h"
// checkpatch-ignore: AVOID_EXTERNS

static bool g_lsmRegistered;

struct        security_operations  *g_original_ops_ptr;   // Any LSM which we are layered on top of
static struct security_operations   g_combined_ops;       // Original LSM plus our hooks combined

extern int cb_bprm_check_security(struct linux_binprm *bprm);
extern void cb_bprm_committed_creds(struct linux_binprm *bprm);
extern int task_create(unsigned long clone_flags);
extern int cb_task_wait(struct task_struct *p);
extern void cb_task_free(struct task_struct *task);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
extern int on_file_mmap(struct file *file,
                         unsigned long reqprot, unsigned long prot,
                         unsigned long flags);
#else
extern int on_file_mmap(struct file *file,
                         unsigned long reqprot, unsigned long prot,
                         unsigned long flags, unsigned long addr,
                         unsigned long addr_only);
#endif

extern void cb_inet_conn_established(struct sock *sk, struct sk_buff *skb);
extern int cb_socket_connect_hook(struct socket *sock, struct sockaddr *addr, int addrlen);
extern int cb_inet_conn_request(struct sock *sk, struct sk_buff *skb, struct request_sock *req);
extern int on_socket_recvmsg(struct socket *sock, struct msghdr *msg, int size, int flags);
extern int socket_sendmsg(struct socket *sock,
struct msghdr *msg, int size);
extern int socket_recvmsg(struct socket *sock,
struct msghdr *msg, int size, int flags);

extern int socket_post_create(struct socket *sock, int family, int type, int protocol, int kern);
extern int socket_bind(struct socket *sock, struct sockaddr *address, int addrlen);

bool lsm_initialize(ProcessContext *context, uint64_t enableHooks)
{
    TRY_CB_RESOLVED(security_ops);

    //
    // Save off the old LSM pointers
    //
    g_original_ops_ptr = *CB_RESOLVED(security_ops);
    if (g_original_ops_ptr != NULL)
    {
        g_combined_ops     = *g_original_ops_ptr;
    }
    TRACE(DL_INFO, "Other LSM named %s", g_original_ops_ptr->name);

    //
    // Now add our hooks
    //
    if (enableHooks & CB__LSM_bprm_check_security) g_combined_ops.bprm_check_security  = cb_bprm_check_security;     // process banning  (exec)
    if (enableHooks & CB__LSM_bprm_committed_creds) g_combined_ops.bprm_committed_creds = cb_bprm_committed_creds;    // process launched (exec)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
    if (enableHooks & CB__LSM_mmap_file) g_combined_ops.mmap_file = on_file_mmap;                          // shared library load
    if (enableHooks & CB__LSM_task_free) g_combined_ops.task_free = cb_task_free;                          // process exit
#else
    if (enableHooks & CB__LSM_file_mmap) g_combined_ops.file_mmap = on_file_mmap;                          // shared library load
    if (enableHooks & CB__LSM_task_wait) g_combined_ops.task_wait = cb_task_wait;                          // process exit
#endif
    if (enableHooks & CB__LSM_socket_connect) g_combined_ops.socket_connect = cb_socket_connect_hook;            // outgoing connects (pre)
    if (enableHooks & CB__LSM_inet_conn_request) g_combined_ops.inet_conn_request = cb_inet_conn_request;           // incoming accept (pre)
    if (enableHooks & CB__LSM_socket_post_create) g_combined_ops.socket_post_create = socket_post_create;
    if (enableHooks & CB__LSM_socket_sendmsg) g_combined_ops.socket_sendmsg = socket_sendmsg;
    if (enableHooks & CB__LSM_socket_recvmsg) g_combined_ops.socket_recvmsg = socket_recvmsg;                    // incoming UDP/DNS - where we get the
    // process context

    *CB_RESOLVED(security_ops) = &g_combined_ops;

    g_lsmRegistered = true;
    return true;

CATCH_DEFAULT:
    TRACE(DL_ERROR, "LSM: Failed to find security_ops\n");
    return false;
}

bool lsm_hooks_changed(ProcessContext *context, uint64_t enableHooks)
{
    bool changed = false;
    struct security_operations *secops = *CB_RESOLVED(security_ops);

    if (enableHooks & CB__LSM_bprm_check_security) changed |= secops->bprm_check_security  != cb_bprm_check_security;
    if (enableHooks & CB__LSM_bprm_committed_creds) changed |= secops->bprm_committed_creds != cb_bprm_committed_creds;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
    if (enableHooks & CB__LSM_mmap_file) changed |= secops->mmap_file != on_file_mmap;
    if (enableHooks & CB__LSM_task_free) changed |= secops->task_free != cb_task_free;
#else
    if (enableHooks & CB__LSM_file_mmap) changed |= secops->file_mmap != on_file_mmap;
    if (enableHooks & CB__LSM_task_wait) changed |= secops->task_wait != cb_task_wait;
#endif
    if (enableHooks & CB__LSM_socket_connect) changed |= secops->socket_connect != cb_socket_connect_hook;
    if (enableHooks & CB__LSM_inet_conn_request) changed |= secops->inet_conn_request != cb_inet_conn_request;
    if (enableHooks & CB__LSM_socket_post_create) changed |= secops->socket_post_create != socket_post_create;
    if (enableHooks & CB__LSM_socket_sendmsg) changed |= secops->socket_sendmsg != socket_sendmsg;
    if (enableHooks & CB__LSM_socket_recvmsg) changed |= secops->socket_recvmsg != socket_recvmsg;

    return changed;
}

void lsm_shutdown(ProcessContext *context)
{
    if (g_lsmRegistered && CB_CHECK_RESOLVED(security_ops))
    {
        TRACE(DL_SHUTDOWN, "Unregistering LSM...");
        *CB_RESOLVED(security_ops) = g_original_ops_ptr;
    } else
    {
        TRACE(DL_WARNING, "LSM not registered so not unregistering");
    }
}

#ifdef HOOK_SELECTOR
static void setHook(const char *buf, const char *name, uint32_t call, void **addr, void *cb_hook, void *kern_hook)
{
    if (0 == strncmp("1", buf, sizeof(char)))
    {
        pr_info("Adding %s: 0x%p\n", name, addr);
        g_enableHooks |= call;
        *addr = cb_hook;
    } else if (0 == strncmp("0", buf, sizeof(char)))
    {
        pr_info("Removing %s\n", name);
        g_enableHooks &= ~call;
        *addr = kern_hook;
    } else
    {
        pr_err("Error adding %s to %s\n", buf, name);
        return;
    }
}

static int getHook(uint32_t hook, struct seq_file *m)
{
    seq_printf(m, (g_enableHooks & hook ? "1\n" : "0\n"));
    return 0;
}

int cb_lsm_bprm_check_security_get(struct seq_file *m, void *v) { return getHook(CB__LSM_bprm_check_security, m); }
int cb_lsm_bprm_committed_creds_get(struct seq_file *m, void *v) { return getHook(CB__LSM_bprm_committed_creds, m); }
int cb_lsm_task_wait_get(struct seq_file *m, void *v) { return getHook(CB__LSM_task_wait, m); }
int cb_lsm_task_free_get(struct seq_file *m, void *v) { return getHook(CB__LSM_task_free, m); }
int cb_lsm_file_permission_get(struct seq_file *m, void *v) { return getHook(CB__LSM_file_permission, m); }
int cb_lsm_socket_connect_get(struct seq_file *m, void *v) { return getHook(CB__LSM_socket_connect, m); }
int cb_lsm_inet_conn_request_get(struct seq_file *m, void *v) { return getHook(CB__LSM_inet_conn_request, m); }
int cb_lsm_socket_post_create_get(struct seq_file *m, void *v) { return getHook(CB__LSM_socket_post_create, m); }
int cb_lsm_socket_sendmsg_get(struct seq_file *m, void *v) { return getHook(CB__LSM_socket_sendmsg, m); }
int cb_lsm_socket_recvmsg_get(struct seq_file *m, void *v) { return getHook(CB__LSM_socket_recvmsg, m); }


#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
int cb_lsm_mmap_file_get(struct seq_file *m, void *v) { return getHook(CB__LSM_mmap_file, m); }
#else
int cb_lsm_file_mmap_get(struct seq_file *m, void *v) { return getHook(CB__LSM_file_mmap, m); }
#endif

#define LSM_HOOK(HOOK, NAME, FUNC) \
ssize_t cb_lsm_##HOOK##_set(struct file *file, const char *buf, size_t size, loff_t *ppos) \
{ \
    TRY_CB_RESOLVED(security_ops); \
    setHook(buf, NAME, CB__LSM_##HOOK, (void **)&(*CB_RESOLVED(security_ops))->HOOK, FUNC, g_original_ops_ptr->HOOK); \
CATCH_DEFAULT: \
    return size; \
}

LSM_HOOK(bprm_check_security, "bprm_check_security",  cb_bprm_check_security)
LSM_HOOK(bprm_committed_creds, "bprm_committed_creds", cb_bprm_committed_creds)
LSM_HOOK(task_wait, "task_wait",            cb_task_wait)
LSM_HOOK(task_free, "task_free",            cb_task_free)
LSM_HOOK(socket_connect, "socket_connect",       cb_socket_connect_hook)
LSM_HOOK(inet_conn_request, "inet_conn_request",    cb_inet_conn_request)
LSM_HOOK(socket_post_create, "socket_post_create",   socket_post_create)
LSM_HOOK(socket_sendmsg, "socket_sendmsg",       socket_sendmsg)
LSM_HOOK(socket_recvmsg, "socket_recvmsg",       socket_recvmsg)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
LSM_HOOK(mmap_file, "mmap_file",            on_file_mmap)
#else
LSM_HOOK(file_mmap, "file_mmap",            on_file_mmap)
#endif

#endif
