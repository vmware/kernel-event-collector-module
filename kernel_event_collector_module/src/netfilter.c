// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include "priv.h"
#include "net-helper.h"
#include "mem-alloc.h"
#include "path-buffers.h"
#include "cb-isolation.h"
#include "cb-spinlock.h"
#include "event-factory.h"

#include "netfilter.h"

#include <linux/skbuff.h>
#undef __KERNEL__
#include <linux/netfilter.h>
#define __KERNEL__
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)  //{ RHEL8
#include <linux/net_namespace.h>
#endif  //}
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/string.h>
#include <net/ip.h>

bool g_webproxy_enabled;

#define NUM_HOOKS     4
static struct nf_hook_ops nfho_local_out[NUM_HOOKS];
static bool               s_netfilter_registered;
static uint64_t           s_netfilter_lock;

int __ec_find_char_offset(const struct sk_buff *skb, int offset, char target);
int __ec_web_proxy_request_check(ProcessContext *context, struct sk_buff *skb);

static unsigned int ec_hook_func_local_out(
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)  //{ RHEL8
    void *priv
    , struct sk_buff *skb
    , const struct nf_hook_state *state
#else  //}{ RHEL7, RHEL6:  start over!
  #if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)  //{ RHEL6
      unsigned int hooknum
  #else  //}{ RHEL7
      const struct nf_hook_ops *ops
  #endif  //}
    , struct sk_buff *skb
    , const struct net_device *in
    , const struct net_device *out
    #if RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7, 2)  //{
        , const struct nf_hook_state *state
    #else  //}{ RHEL7.0, RHEL7.1: truly ancient
          , int (*okfn)(struct sk_buff *)
    #endif  //}
#endif  //}
    )
{
    DECLARE_ATOMIC_CONTEXT(context, ec_getpid(current));

    TRY(skb);
    TRY(CHECK_SK_FAMILY(skb->sk) && CHECK_SK_PROTO(skb->sk));

    if (g_cbIsolationStats.isolationEnabled)
    {
        CB_SOCK_ADDR                  localAddr;
        CB_SOCK_ADDR                  remoteAddr;
        CB_ISOLATION_INTERCEPT_RESULT isolation_result;

        TRY(ec_get_addrs_from_skb(skb->sk, skb, &localAddr, &remoteAddr));

        ec_IsolationInterceptByAddrProtoPort(&context, skb->sk->sk_protocol, &remoteAddr, &isolation_result);
        if (isolation_result.isolationAction == IsolationActionBlock)
        {
            return NF_DROP;
        }
    }

    if (g_webproxy_enabled && skb->sk->sk_protocol == IPPROTO_TCP)
    {
        __ec_web_proxy_request_check(&context, skb);
    }

CATCH_DEFAULT:
    return NF_ACCEPT;
}


// This hook only looks for DNS response packets.  If one is found, a message is sent to
//  user space for processing.  NOTE: Process ID and such will be added to the event but
//  it is not used by the daemon.  This is only used for internal caching.
unsigned int ec_hook_func_local_in_v4(
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)  //{ RHEL8
    void *priv
    , struct sk_buff *skb
    , const struct nf_hook_state *state
#else  //}{ RHEL7, RHEL6:  start over!
  #if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)  //{ RHEL6
      unsigned int hooknum
  #else  //}{ RHEL7
      const struct nf_hook_ops *ops
  #endif  //}
    , struct sk_buff *skb
    , const struct net_device *in
    , const struct net_device *out
    #if RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7, 2)  //{
        , const struct nf_hook_state *state
    #else  //}{ RHEL7.0, RHEL7.1: truly ancient
          , int (*okfn)(struct sk_buff *)
    #endif  //}
#endif  //}
    )
{
    DECLARE_ATOMIC_CONTEXT(context, ec_getpid(current));

    TRY(skb);
    TRY(CHECK_SK_FAMILY(skb->sk) && CHECK_SK_PROTO(skb->sk));

    if (g_cbIsolationStats.isolationEnabled)
    {
        CB_SOCK_ADDR                  localAddr;
        CB_SOCK_ADDR                  remoteAddr;
        CB_ISOLATION_INTERCEPT_RESULT isolation_result;

        TRY(ec_get_addrs_from_skb(skb->sk, skb, &remoteAddr, &localAddr));

        ec_IsolationInterceptByAddrProtoPort(&context, skb->sk->sk_protocol, &remoteAddr, &isolation_result);
        if (isolation_result.isolationAction == IsolationActionBlock)
        {
            return NF_DROP;
        }
    }

CATCH_DEFAULT:
    return NF_ACCEPT;
}

unsigned int ec_hook_func_local_in_v6(
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)  //{ RHEL8
    void *priv
    , struct sk_buff *skb
    , const struct nf_hook_state *state
#else  //}{ RHEL7, RHEL6:  start over!
  #if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)  //{ RHEL6
      unsigned int hooknum
  #else  //}{ RHEL7
      const struct nf_hook_ops *ops
  #endif  //}
    , struct sk_buff *skb
    , const struct net_device *in
    , const struct net_device *out
    #if RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7, 2)  //{
        , const struct nf_hook_state *state
    #else  //}{ RHEL7.0, RHEL7.1: truly ancient
          , int (*okfn)(struct sk_buff *)
    #endif  //}
#endif  //}
    )
{
    DECLARE_ATOMIC_CONTEXT(context, ec_getpid(current));

    TRY(skb);
    TRY(CHECK_SK_FAMILY(skb->sk) && CHECK_SK_PROTO(skb->sk));

    if (g_cbIsolationStats.isolationEnabled)
    {
        CB_SOCK_ADDR                  localAddr;
        CB_SOCK_ADDR                  remoteAddr;
        CB_ISOLATION_INTERCEPT_RESULT isolation_result;

        TRY(ec_get_addrs_from_skb(skb->sk, skb, &remoteAddr, &localAddr));

        ec_IsolationInterceptByAddrProtoPort(&context, skb->sk->sk_protocol, &remoteAddr, &isolation_result);
        if (isolation_result.isolationAction == IsolationActionBlock)
        {
            return NF_DROP;
        }
    }

CATCH_DEFAULT:
    return NF_ACCEPT;
}

int __ec_web_proxy_request_check(ProcessContext *context, struct sk_buff *skb)
{
    char tmp[10];
    char url[PROXY_SERVER_MAX_LEN + 1];

    static const char * const HTTP_METHODS[] = {"GET", "PUT", "POST", "DELETE", "CONNECT"};
    static const int HTTP_METHODS_LEN[] = {3, 3, 4, 6, 7};
    static const int HTTP_METHOD_MAX_LEN = 7;
    static const char * const HTTP_VERSION[] = {"HTTP/1.1", "HTTP/1.0"};
    static const int HTTP_VERSION_LEN = 8;
    int family;

    int i;
    int space_offset;
    int url_len;
    int payload_offset;
    struct tcphdr *tcp_header;
    CB_SOCK_ADDR      localAddr;
    CB_SOCK_ADDR      remoteAddr;

    TRY(skb);
    TRY(skb->sk);

    family = skb->sk->sk_family;

    // The skb_transport_offset will give me offset of the transport header, skipping any IPv6 extended headers.
    payload_offset = skb_transport_offset(skb) + tcp_hdrlen(skb);

    if (skb_copy_bits(skb, payload_offset, tmp, HTTP_METHOD_MAX_LEN + 2) != 0)
    {
        goto CATCH_DEFAULT;
    }

    for (i = 0; i < 5; i++)
    {
        if (strncmp(HTTP_METHODS[i], tmp, HTTP_METHODS_LEN[i]) != 0)
        {
            continue;
        }

        if (tmp[HTTP_METHODS_LEN[i] + 1] == '/')
        {
            goto CATCH_DEFAULT;
        }

        space_offset = __ec_find_char_offset(skb, payload_offset + HTTP_METHODS_LEN[i] + 2, ' ');
        if (space_offset == -1)
        {
            goto CATCH_DEFAULT;
        }

        if (skb_copy_bits(skb, space_offset + 1,    tmp, HTTP_VERSION_LEN) != 0)
        {
            goto CATCH_DEFAULT;
        }

        if (strncmp(HTTP_VERSION[0], tmp, HTTP_VERSION_LEN) != 0 &&
            strncmp(HTTP_VERSION[1], tmp, HTTP_VERSION_LEN) != 0)
        {
            goto CATCH_DEFAULT;
        }

        url_len = space_offset - (payload_offset + HTTP_METHODS_LEN[i] + 1);
        if (url_len >= PROXY_SERVER_MAX_LEN)
        {
            url_len = PROXY_SERVER_MAX_LEN - 1;
        }

        if (skb_copy_bits(skb, payload_offset + HTTP_METHODS_LEN[i] + 1, url, url_len) != 0)
        {
            goto CATCH_DEFAULT;
        }

        url[url_len] = 0;

        TRACE(DL_INFO, "%s: will send proxy event for pid %lld to %s\n", __func__, (uint64_t)ec_getpid(current), url);

        localAddr. sa_addr.sa_family = family;
        remoteAddr.sa_addr.sa_family = family;
        tcp_header                   = (struct tcphdr *) skb_transport_header(skb);

        if (family == AF_INET)
        {
            struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);

            remoteAddr.as_in4.sin_addr.s_addr = ip_header->daddr;
            localAddr .as_in4.sin_addr.s_addr = ip_header->saddr;

            remoteAddr.as_in4.sin_port = tcp_header->dest;
            localAddr .as_in4.sin_port = tcp_header->source;
        } else {
            struct ipv6hdr *ip_header = (struct ipv6hdr *)skb_network_header(skb);

            memcpy(&remoteAddr.as_in6.sin6_addr, &ip_header->daddr, sizeof(struct in6_addr));
            memcpy(&localAddr.as_in6.sin6_addr, &ip_header->saddr, sizeof(struct in6_addr));

            remoteAddr.as_in6.sin6_port = tcp_header->dest;
            localAddr .as_in6.sin6_port = tcp_header->source;
        }

        // We don't track the DNS events
        ec_event_send_net_proxy(
            NULL,
            "PROXY",
            CB_EVENT_TYPE_WEB_PROXY,
            &localAddr,
            &remoteAddr,
            IPPROTO_TCP,
            url,
            0, //TODO: actual_port will be obtained at cbdaemon based on actual_server url.
            skb->sk,
            context);
    }

CATCH_DEFAULT:
    return 0;
}

int __ec_find_char_offset(const struct sk_buff *skb, int offset, char target)
{
    char *ptr;
    char *frag_addr;
    int frag_len;
    int current_offset;
    int i;

    //There is data inside skb, so search the remaining data before search fragments.
    if (skb->len - skb->data_len > offset)
    {
        current_offset = offset;
        for (ptr = (char *)skb->data + offset; ptr < (char *) skb_tail_pointer(skb); ptr++)
        {
            if (*ptr == target)
            {
                return current_offset;
            }
            current_offset++;
        }
    } else {
        current_offset = skb->len - skb->data_len;
    }

    for (i = skb_shinfo(skb)->nr_frags - 1; i >= 0; i--)
    {
        frag_addr = skb_frag_address_safe(&skb_shinfo(skb)->frags[i]);
        frag_len = skb_frag_size(&skb_shinfo(skb)->frags[i]);
        for (ptr = frag_addr; ptr <= frag_addr + frag_len; ptr++)
        {
            if (current_offset >= offset && *ptr == target)
            {
                return current_offset;
            }
            current_offset++;
        }
    }
    return -1;
}

bool ec_netfilter_enable(ProcessContext *context)
{
    bool result = true;
    int ret;

    ec_write_lock(&s_netfilter_lock, context);

    TRY(!s_netfilter_registered && (g_cbIsolationStats.isolationEnabled || g_webproxy_enabled));

    nfho_local_out[0].hook     = ec_hook_func_local_out;
    nfho_local_out[0].hooknum  = NF_INET_LOCAL_OUT;
    nfho_local_out[0].pf       = PF_INET;
    nfho_local_out[0].priority = NF_IP_PRI_FIRST;

    nfho_local_out[1].hook     = ec_hook_func_local_out;
    nfho_local_out[1].hooknum  = NF_INET_LOCAL_OUT;
    nfho_local_out[1].pf       = PF_INET6;
    nfho_local_out[1].priority = NF_IP_PRI_FIRST;

    nfho_local_out[2].hook     = ec_hook_func_local_in_v4;
    nfho_local_out[2].hooknum  = NF_INET_LOCAL_IN;
    nfho_local_out[2].pf       = PF_INET;
    nfho_local_out[2].priority = NF_IP_PRI_FIRST;

    nfho_local_out[3].hook     = ec_hook_func_local_in_v6;
    nfho_local_out[3].hooknum  = NF_INET_LOCAL_IN;
    nfho_local_out[3].pf       = PF_INET6;
    nfho_local_out[3].priority = NF_IP_PRI_FIRST;

    ret = nf_register_hooks(nfho_local_out, NUM_HOOKS);
    TRY_DO_MSG(ret == 0, { result = false; }, DL_ERROR, "Failed to register netfilter hooks %d", ret);

    s_netfilter_registered = true;
    TRACE(DL_INIT, "Netfilter hooks have been registered");

CATCH_DEFAULT:
    ec_write_unlock(&s_netfilter_lock, context);

    return result;
}

void __ec_netfilter_unregister(ProcessContext *context)
{
    ec_write_lock(&s_netfilter_lock, context);

    if (s_netfilter_registered)
    {
        nf_unregister_hooks(nfho_local_out, NUM_HOOKS);
        s_netfilter_registered = false;
        TRACE(DL_SHUTDOWN, "Netfilter hooks have been unregistered");
    }

    ec_write_unlock(&s_netfilter_lock, context);
}

void ec_netfilter_disable(ProcessContext *context)
{
    if (g_cbIsolationStats.isolationEnabled || g_webproxy_enabled)
    {
        return;
    }

    __ec_netfilter_unregister(context);
}

bool ec_netfilter_initialize(ProcessContext *context)
{
    ec_spinlock_init(&s_netfilter_lock, context);
    return s_netfilter_lock != 0;
}

void ec_netfilter_cleanup(ProcessContext *context)
{
    __ec_netfilter_unregister(context);
    ec_spinlock_destroy(&s_netfilter_lock, context);
}
