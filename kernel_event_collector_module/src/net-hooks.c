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
#include "dns-parser.h"
#include "path-buffers.h"

#include <linux/kprobes.h>
#include <linux/inet.h>
#include <net/ip.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
#define ec_ipv6_skip_exthdr(skb, ptr, pProtocol) (ptr = ipv6_skip_exthdr(skb, ptr, pProtocol))
#else
#define ec_ipv6_skip_exthdr(skb, ptr, pProtocol) do {     \
        __be16          frag_off;                               \
        ptr = ipv6_skip_exthdr(skb, ptr, pProtocol, &frag_off); \
    } while (0)
#endif

#define PT_REGS_ARG_1(REGS)  REGS->di
#define PT_REGS_ARG_2(REGS)  REGS->si
#define PT_REGS_ARG_3(REGS)  REGS->dx
#define PT_REGS_ARG_4(REGS)  REGS->cx

struct probe_sock_data {
    struct sock *sk;
};

void __ec_handle_net_event(char *msg,
                           CB_EVENT_TYPE net_event_type,
                           struct sock *sk,
                           CB_SOCK_ADDR *localAddr,
                           CB_SOCK_ADDR *remoteAddr,
                           CONN_DIRECTION conn_dir,
                           ProcessContext *context);

void __ec_process_dns_packet(
    struct sock    *sk,
    struct sk_buff *skb,
    ProcessContext *context);

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

    __ec_handle_net_event("SEND", CB_EVENT_TYPE_NET_CONNECT_PRE, data->sk, &localAddr, &remoteAddr, CONN_OUT, &context);

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

    // skb->sk will be NULL, it has not been attached yet

    __ec_process_dns_packet(data->sk, skb, &context);

    TRY(ec_get_addrs_from_skb(data->sk, skb, &remoteAddr, &localAddr));

    __ec_handle_net_event("RECV", CB_EVENT_TYPE_NET_ACCEPT, data->sk, &localAddr, &remoteAddr, CONN_IN, &context);

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

    __ec_handle_net_event("ACCEPT", CB_EVENT_TYPE_NET_ACCEPT, data->sk, &localAddr, &remoteAddr, CONN_IN, &context);

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

    __ec_handle_net_event("CONNECT", CB_EVENT_TYPE_NET_CONNECT_PRE, data->sk, &localAddr, &remoteAddr, CONN_OUT, &context);

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

bool ec_network_hooks_initialize(ProcessContext *context)
{
    TRY(__ec_register_kprobe(&recvdatagram_probe, g_enableHooks, CB__KP_udp_recv));
    TRY(__ec_register_kprobe(&udp_sendmsg_probe, g_enableHooks, CB__KP_udp_sendmsg));
    TRY(__ec_register_kprobe(&udpv6_sendmsg_probe, g_enableHooks, CB__KP_udpv6_sendmsg));
    TRY(__ec_register_kprobe(&accept_probe, g_enableHooks, CB__KP_tcp_accept));
    TRY(__ec_register_kprobe(&tcp_v4_connect_probe, g_enableHooks, CB__KP_tcp_connect));
    TRY(__ec_register_kprobe(&tcp_v6_connect_probe, g_enableHooks, CB__KP_tcpv6_connect));

    return true;
CATCH_DEFAULT:
    ec_network_hooks_shutdown(context);
    return false;
}

void ec_network_hooks_shutdown(ProcessContext *context)
{
    __ec_unregister_kprobe(&recvdatagram_probe, g_enableHooks, CB__KP_udp_recv);
    __ec_unregister_kprobe(&udp_sendmsg_probe, g_enableHooks, CB__KP_udp_sendmsg);
    __ec_unregister_kprobe(&udpv6_sendmsg_probe, g_enableHooks, CB__KP_udpv6_sendmsg);
    __ec_unregister_kprobe(&accept_probe, g_enableHooks, CB__KP_tcp_accept);
    __ec_unregister_kprobe(&tcp_v4_connect_probe, g_enableHooks, CB__KP_tcp_connect);
    __ec_unregister_kprobe(&tcp_v6_connect_probe, g_enableHooks, CB__KP_tcpv6_connect);
}

void __ec_handle_net_event(char *msg,
                           CB_EVENT_TYPE net_event_type,
                           struct sock *sk,
                           CB_SOCK_ADDR *localAddr,
                           CB_SOCK_ADDR *remoteAddr,
                           CONN_DIRECTION conn_dir,
                           ProcessContext *context)
{
    ProcessHandle    *process_handle = NULL;
    pid_t             pid;

    process_handle = ec_get_procinfo_and_create_process_start_if_needed(context->pid, "RECV", context);
    TRY(process_handle);

    pid = ec_process_tracking_exec_pid(process_handle, context);

    TRY(!ec_banning_IgnoreProcess(context, pid));

    TRY(ec_net_tracking_check_cache(context, pid, localAddr, remoteAddr, sk->sk_protocol, conn_dir));

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

int __ec_transport_offset(struct sk_buff *skb, struct iphdr *ip_header)
{
    int transport_offset = skb_transport_offset(skb);

    // In earlier kernels the transport header is not set up correctly, so we may need to calculate it.
    // https://stackoverflow.com/a/29663558/13177212
    if (skb_transport_header(skb) == (unsigned char *)ip_header)
    {
        transport_offset += (ip_header->ihl * 4);
    }

    return transport_offset;
}

// This hook only looks for DNS response packets.  If one is found, a message is sent to
//  user space for processing.  NOTE: Process ID and such will be added to the event but
//  it is not used by the daemon.  This is only used for internal caching.
void __ec_process_dns_packet(
    struct sock *sk,
    struct sk_buff *skb,
    ProcessContext *context)
{
    CB_EVENT_DNS_RESPONSE response  = { 0 };
    char                  *dns_data = NULL;
    uint8_t               protocol;
    int                   port      = 0;
    size_t                length    = 0;
    int                   payload_offset;
    struct iphdr          *ip_header;
    struct udphdr         *udphdr;

    TRY(skb && sk);
    protocol = sk->sk_protocol;

    // TODO: Add support for TCP
    //  DNS can use TCP, though it generally does not use TCP for the records we care about.
    //  I did spend some time attempting to get it working, but I had difficulty getting the payload
    //  for the TCP packet.  I seemed to multiple packets with no payload, and then one with 108 bytes.
    //  However I could never get any records when I parsed it.
    TRY(protocol == IPPROTO_UDP);

    ip_header = ip_hdr(skb);
    TRY(ip_header);
    udphdr = udp_hdr(skb);
    TRY(udphdr);

    if (sk->sk_family == AF_INET)
    {
        payload_offset = __ec_transport_offset(skb, ip_header);
    } else
    {
        payload_offset = skb_transport_offset(skb);

        // Use the ipv6_skip_exthdr function to skip past any extended headers that may be present.
        ec_ipv6_skip_exthdr(skb, payload_offset, &protocol);
    }

    port = ntohs(udphdr->source);
    length         = min((size_t)PATH_MAX, (size_t)(ntohs(udphdr->len) - sizeof(struct udphdr)));
    payload_offset = payload_offset + sizeof(udphdr);

    if (port == 53)
    {
        TRY_MSG(length > 0, DL_WARNING, "invalid length:%ld for UDP response", length);
        dns_data = ec_get_path_buffer(context);
        if (dns_data)
        {
            TRY_MSG(!skb_copy_bits(skb, payload_offset, dns_data, length),
                    DL_ERROR, "Error copying UDP DNS response data");

            TRY_MSG(!ec_dns_parse_data(dns_data, length, &response, context),
                    DL_INFO, "No DNS record found");

            ec_event_send_dns(
                CB_EVENT_TYPE_DNS_RESPONSE,
                &response,
                context);
        }
    }

CATCH_DEFAULT:
    ec_put_path_buffer(dns_data);
    ec_mem_cache_free_generic(response.records);
}
