/* Copyright 2021 VMware Inc.  All rights reserved. */
/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

#pragma once

#include <cstdint>




namespace cb_endpoint {
namespace bpf_probe {

    static const uint8_t DNS_SEGMENT_LEN = 40;
    static const uint8_t DNS_SEGMENT_FLAGS_START = 0x01;
    static const uint8_t DNS_SEGMENT_FLAGS_END = 0x02;

    enum PP
    {
        PP_NO_EXTRA_DATA,
        PP_ENTRY_POINT,
        PP_PATH_COMPONENT,
        PP_FINALIZED,
        PP_APPEND,
        PP_DEBUG,
    };

    enum event_type
    {
        EVENT_PROCESS_ARG,
        EVENT_PROCESS_EXEC,
        EVENT_PROCESS_EXIT,
        EVENT_PROCESS_CLONE,
        EVENT_FILE_READ,
        EVENT_FILE_WRITE,
        EVENT_FILE_CREATE,
        EVENT_FILE_PATH,
        EVENT_FILE_MMAP,
        EVENT_FILE_TEST,
        EVENT_NET_CONNECT_PRE,
        EVENT_NET_CONNECT_ACCEPT,
        EVENT_NET_CONNECT_DNS_RESPONSE,
        EVENT_NET_CONNECT_WEB_PROXY,
        EVENT_FILE_DELETE,
        EVENT_FILE_CLOSE,
        EVENT_FILE_OPEN
    };


    struct net_t
    {
        unsigned int local_addr;
        unsigned int remote_addr;
        unsigned short remote_port;
        unsigned short local_port;
        unsigned short ipver;
        unsigned short protocol;
        unsigned short dns_flag;
        unsigned int local_addr6[4];
        unsigned int remote_addr6[4];
        char dns[DNS_SEGMENT_LEN]; // shared by dns and web-proxy
        unsigned int name_len;
    };

    struct mmap_args
    {
        uint64_t flags;
        uint64_t prot;
    };

    struct data_t
    {
        uint64_t event_time;
        uint32_t tid;
        uint32_t pid;
        uint8_t type;
        uint8_t state;
        uint32_t uid;
        uint32_t ppid;
        uint64_t inode;
        uint32_t device;
        uint32_t mnt_ns;
        union
        {
            struct mmap_args mmap_args;
            char fname[255];
            struct net_t net;
        };
        int retval;
        uint64_t start_time;
        uint64_t event_submit_time;
    };

}}
