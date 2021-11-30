/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#pragma once

#include "priv.h"

#define CHECK_SK_FAMILY(sk)        ((sk) && \
                                     ((sk)->sk_family == PF_INET || (sk)->sk_family == PF_INET6) \
                                   )
#define CHECK_SK_FAMILY_INET(sk)   ((sk) && \
                                     (sk)->sk_family == PF_INET \
                                   )
#define CHECK_SK_FAMILY_INET6(sk)  ((sk) && \
                                     (sk)->sk_family == PF_INET6 \
                                   )
#define CHECK_SK_PROTO(sk)         ((sk) && \
                                     ((sk)->sk_protocol == IPPROTO_UDP || (sk)->sk_protocol == IPPROTO_TCP) \
                                   )
#define CHECK_SK_PROTO_UDP(sk)     ((sk) && \
                                     (sk)->sk_protocol == IPPROTO_UDP \
                                   )
#define CHECK_SK_PROTO_TCP(sk)     ((sk) && \
                                     (sk)->sk_protocol == IPPROTO_TCP \
                                   )
#define CHECK_SOCKET_TYPE(sock)    ((sock) && \
                                     ((sock)->type == SOCK_DGRAM || (sock)->type == SOCK_STREAM) \
                                   )
#define CHECK_SOCKET_FAMILY(sock)  ((sock) && CHECK_SK_FAMILY((sock)->sk))
#define CHECK_SOCKET_PROTO(sock)   ((sock) && CHECK_SK_PROTO((sock)->sk))
#define CHECK_SOCKET(sock)         (CHECK_SOCKET_FAMILY(sock) && CHECK_SOCKET_PROTO(sock) && CHECK_SOCKET_TYPE(sock))

#define PROTOCOL_STR(PROTOCOL) ((PROTOCOL) == IPPROTO_TCP ? "tcp" : (PROTOCOL) == IPPROTO_UDP ? "udp" : "??")
#define TYPE_STR(TYPE) ((TYPE) == SOCK_DGRAM ? "dgram" : (TYPE) == SOCK_STREAM ? "stream" : "??")

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
#  define IPV4_SOCKNAME(inet, a) ((inet)->inet_##a)
#  define IPV6_SOCKNAME(sk, a)   ((sk)->sk_v6_##a)
#else
#  define IPV4_SOCKNAME(inet, a) ((inet)->a)
#  define IPV6_SOCKNAME(sk, a)   (inet6_sk(sk)->a)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
#define ec_ipv6_skip_exthdr(skb, ptr, pProtocol) (ptr = ipv6_skip_exthdr(skb, ptr, pProtocol))
#else
#define ec_ipv6_skip_exthdr(skb, ptr, pProtocol) do {     \
        __be16          frag_off;                               \
        ptr = ipv6_skip_exthdr(skb, ptr, pProtocol, &frag_off); \
    } while (0)
#endif

// ------------------------------------------------
// Network Helpers
//
size_t ec_ntop(const struct sockaddr *sap, char *buf, const size_t buflen, uint16_t *port);
void ec_set_sockaddr_port(CB_SOCK_ADDR *addr, uint32_t port);
void ec_copy_sockaddr(CB_SOCK_ADDR *left, CB_SOCK_ADDR *right);
void ec_copy_sockaddr_in(struct sockaddr_in *left, struct sockaddr_in *right);
void ec_copy_sockaddr_in6(struct sockaddr_in6 *left, struct sockaddr_in6 *right);
void ec_getsockname(struct sock *sk, CB_SOCK_ADDR *localAddr);
bool ec_get_addrs_from_skb(struct sock *sk, struct sk_buff *skb, CB_SOCK_ADDR *srcAddr, CB_SOCK_ADDR *dstAddr);
void ec_getpeername(struct sock *sk, CB_SOCK_ADDR *remoteAddr);

void ec_print_address(
    char                  *msg,
    const struct sock     *sk,
    const struct sockaddr *localAddr,
    const struct sockaddr *remoteAddr);

#define PRINT_ADDRESS(msg, sk, localAddr, remoteAddr) do { if (MAY_TRACE_LEVEL(DL_NET)) ec_print_address(msg, sk, localAddr, remoteAddr); } while (0)
