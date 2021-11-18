// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include "priv.h"
#include "module_state.h"
#include "net-hooks.h"
#include "net-helper.h"
#include "net-tracking.h"
#include "process-tracking.h"
#include "event-factory.h"
#include "cb-spinlock.h"
#include "cb-banning.h"
#include <linux/kprobes.h>


#define PT_REGS_ARG_1(REGS)  REGS->di
#define PT_REGS_ARG_2(REGS)  REGS->si
#define PT_REGS_ARG_3(REGS)  REGS->dx
#define PT_REGS_ARG_4(REGS)  REGS->cx

struct probe_sock_data {
    struct sock *sk;
};

void __ec_handle_net_event(char *msg, CB_EVENT_TYPE net_event_type, struct sock *sk, CB_SOCK_ADDR *localAddr, CB_SOCK_ADDR *remoteAddr, ProcessContext *context);

int ec_sock_arg_2_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct probe_sock_data *data = (struct probe_sock_data *)ri->data;

    data->sk = (struct sock *) PT_REGS_ARG_2(regs);

    return 0;
}

int ec_sock_arg_1_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct probe_sock_data *data = (struct probe_sock_data *)ri->data;

    data->sk = (struct sock *) PT_REGS_ARG_1(regs);

    return 0;
}

int ec_sendmsg_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    int                    retval = regs_return_value(regs);
    struct probe_sock_data *data  = (struct probe_sock_data *)ri->data;
    CB_SOCK_ADDR           localAddr;
    CB_SOCK_ADDR           remoteAddr;

    DECLARE_ATOMIC_CONTEXT(context, ec_getpid(current));

    MODULE_GET_AND_BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(&context, CATCH_DEFAULT);

    TRY(retval >= 0);
    TRY(data);
    TRY(CHECK_SK_FAMILY(data->sk) && CHECK_SK_PROTO_UDP(data->sk));

    ec_getsockname(data->sk, &localAddr);
    ec_getpeername(data->sk, &remoteAddr);

    __ec_handle_net_event("SEND", CB_EVENT_TYPE_NET_CONNECT_PRE, data->sk, &localAddr, &remoteAddr, &context);

CATCH_DEFAULT:
    MODULE_PUT_AND_FINISH_MODULE_DISABLE_CHECK(&context);
    return 0;
}

int ec_recvmsg_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct sk_buff         *skb  = (struct sk_buff *)regs_return_value(regs);
    struct probe_sock_data *data = (struct probe_sock_data *)ri->data;
    CB_SOCK_ADDR           localAddr;
    CB_SOCK_ADDR           remoteAddr;

    DECLARE_ATOMIC_CONTEXT(context, ec_getpid(current));

    MODULE_GET_AND_BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(&context, CATCH_DEFAULT);

    TRY(skb);
    TRY(data);
    TRY(CHECK_SK_FAMILY(data->sk) && CHECK_SK_PROTO_UDP(data->sk));

    TRY(ec_get_addrs_from_skb(data->sk, skb, &remoteAddr, &localAddr));

    __ec_handle_net_event("RECV", CB_EVENT_TYPE_NET_ACCEPT, data->sk, &localAddr, &remoteAddr, &context);

CATCH_DEFAULT:
    MODULE_PUT_AND_FINISH_MODULE_DISABLE_CHECK(&context);
    return 0;
}

int ec_accept_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct sock            *newsk = (struct sock *)regs_return_value(regs);
    struct probe_sock_data *data  = (struct probe_sock_data *)ri->data;
    CB_SOCK_ADDR           localAddr;
    CB_SOCK_ADDR           remoteAddr;

    DECLARE_ATOMIC_CONTEXT(context, ec_getpid(current));

    MODULE_GET_AND_BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(&context, CATCH_DEFAULT);

    TRY(data->sk && newsk);

    ec_getsockname(newsk, &localAddr);

    // we can't use kernel_getpeername here because newsk->sk_socket has not been set yet
    ec_getpeername(newsk, &remoteAddr);

    __ec_handle_net_event("ACCEPT", CB_EVENT_TYPE_NET_ACCEPT, data->sk, &localAddr, &remoteAddr, &context);

CATCH_DEFAULT:
    MODULE_PUT_AND_FINISH_MODULE_DISABLE_CHECK(&context);
    return 0;
}

int ec_connect_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    int ret  = (int) regs_return_value(regs);
    struct probe_sock_data *data = (struct probe_sock_data *) ri->data;
    CB_SOCK_ADDR      localAddr;
    CB_SOCK_ADDR      remoteAddr;

    DECLARE_ATOMIC_CONTEXT(context, ec_getpid(current));

    MODULE_GET_AND_BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(&context, CATCH_DEFAULT);

    TRY(ret >= 0);
    TRY(data->sk);

    ec_getsockname(data->sk, &localAddr);
    ec_getpeername(data->sk, &remoteAddr);

    __ec_handle_net_event("CONNECT", CB_EVENT_TYPE_NET_CONNECT_PRE, data->sk, &localAddr, &remoteAddr, &context);

CATCH_DEFAULT:
    MODULE_PUT_AND_FINISH_MODULE_DISABLE_CHECK(&context);
    return 0;
}

static struct kretprobe udp_sendmsg_probe = {
    .kp.symbol_name = "udp_sendmsg",
    .entry_handler	= ec_sock_arg_2_entry_handler,
    .handler		= ec_sendmsg_ret_handler,
    .data_size		= sizeof(struct probe_sock_data),
    .maxactive		= -1,
};

static struct kretprobe udpv6_sendmsg_probe = {
    .kp.symbol_name = "udpv6_sendmsg",
    .entry_handler	= ec_sock_arg_2_entry_handler,
    .handler		= ec_sendmsg_ret_handler,
    .data_size		= sizeof(struct probe_sock_data),
    .maxactive		= -1,
};

static struct kretprobe recvdatagram_probe = {
    .kp.symbol_name = "__skb_recv_datagram",
    .entry_handler	= ec_sock_arg_1_entry_handler,
    .handler		= ec_recvmsg_ret_handler,
    .data_size		= sizeof(struct probe_sock_data),
    .maxactive		= -1,
};

static struct kretprobe accept_probe = {
    .kp.symbol_name = "inet_csk_accept",
    .entry_handler	= ec_sock_arg_1_entry_handler,
    .handler		= ec_accept_ret_handler,
    .data_size		= sizeof(struct probe_sock_data),
    .maxactive		= -1,
};

static struct kretprobe tcp_v4_connect_probe = {
    .kp.symbol_name = "tcp_v4_connect",
    .entry_handler	= ec_sock_arg_1_entry_handler,
    .handler		= ec_connect_ret_handler,
    .data_size		= sizeof(struct probe_sock_data),
    .maxactive		= -1,
};

static struct kretprobe tcp_v6_connect_probe = {
    .kp.symbol_name = "tcp_v6_connect",
    .entry_handler	= ec_sock_arg_1_entry_handler,
    .handler		= ec_connect_ret_handler,
    .data_size		= sizeof(struct probe_sock_data),
    .maxactive		= -1,
};

bool __ec_register_kprobe(struct kretprobe *probe, uint64_t enableHooks, uint64_t flag)
{
    int ret;

    if (!(enableHooks & flag))
    {
        TRACE(DL_INIT, "Not registering kprobe for: %s", probe->kp.symbol_name);
        return true;
    }

    ret = register_kretprobe(probe);

    if (ret < 0) {
        TRACE(DL_ERROR, "%s: register_kretprobe failed, returned %d", probe->kp.symbol_name, ret);
        return false;
    }

    return true;
}

void __ec_unregister_kprobe(struct kretprobe *probe, uint64_t enableHooks, uint64_t flag)
{
    CANCEL_VOID(enableHooks & flag);

    unregister_kretprobe(probe);

    // flags and addr must be reset for reuse, otherwise register_kretprobe will fail
    probe->kp.flags = 0;
    probe->kp.addr = NULL;
}

bool ec_network_hooks_initialize(ProcessContext *context, uint64_t enableHooks)
{
    TRY(__ec_register_kprobe(&recvdatagram_probe, enableHooks, CB__KP_udp_recv));
    TRY(__ec_register_kprobe(&udp_sendmsg_probe, enableHooks, CB__KP_udp_sendmsg));
    TRY(__ec_register_kprobe(&udpv6_sendmsg_probe, enableHooks, CB__KP_udpv6_sendmsg));
    TRY(__ec_register_kprobe(&accept_probe, enableHooks, CB__KP_tcp_accept));
    TRY(__ec_register_kprobe(&tcp_v4_connect_probe, enableHooks, CB__KP_tcp_connect));
    TRY(__ec_register_kprobe(&tcp_v6_connect_probe, enableHooks, CB__KP_tcpv6_connect));

    return true;
CATCH_DEFAULT:
    ec_network_hooks_shutdown(context, enableHooks);
    return false;
}

void ec_network_hooks_shutdown(ProcessContext *context, uint64_t enableHooks)
{
    __ec_unregister_kprobe(&recvdatagram_probe, enableHooks, CB__KP_udp_recv);
    __ec_unregister_kprobe(&udp_sendmsg_probe, enableHooks, CB__KP_udp_sendmsg);
    __ec_unregister_kprobe(&udpv6_sendmsg_probe, enableHooks, CB__KP_udpv6_sendmsg);
    __ec_unregister_kprobe(&accept_probe, enableHooks, CB__KP_tcp_accept);
    __ec_unregister_kprobe(&tcp_v4_connect_probe, enableHooks, CB__KP_tcp_connect);
    __ec_unregister_kprobe(&tcp_v6_connect_probe, enableHooks, CB__KP_tcpv6_connect);
}

void __ec_handle_net_event(char *msg, CB_EVENT_TYPE net_event_type, struct sock *sk, CB_SOCK_ADDR *localAddr, CB_SOCK_ADDR *remoteAddr, ProcessContext *context)
{
    ProcessHandle    *process_handle = NULL;
    pid_t             pid;

    process_handle = ec_get_procinfo_and_create_process_start_if_needed(context->pid, "RECV", context);
    TRY(process_handle);

    pid = ec_process_tracking_exec_pid(process_handle, context);

    TRY(!ec_banning_IgnoreProcess(context, pid));

    TRY(ec_net_tracking_check_cache(context, pid, localAddr, remoteAddr, sk->sk_protocol, CONN_IN));

    ec_event_send_net(process_handle,
                      msg,
                      net_event_type,
                      localAddr,
                      remoteAddr,
                      sk->sk_protocol,
                      sk,
                      context);

CATCH_DEFAULT:
    ec_process_tracking_put_handle(process_handle, context);
}
