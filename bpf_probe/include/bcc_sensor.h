/* Copyright 2021 VMware Inc.  All rights reserved. */
/* SPDX-License-Identifier: GPL-2.0 */

#pragma once

#include <cstdint>

#define DNS_SEGMENT_LEN 40
#define DNS_SEGMENT_FLAGS_START 0x01
#define DNS_SEGMENT_FLAGS_END 0x02


#define PP_NO_EXTRA_DATA 0
#define PP_ENTRY_POINT 1
#define PP_PATH_COMPONENT 2
#define PP_FINALIZED 3
#define PP_APPEND 4
#define PP_DEBUG 5

namespace cb_endpoint {
namespace cb_ebpf {
    enum event_type
    {
        EVENT_PROCESS_ARG = 0,
        EVENT_PROCESS_EXEC = 1,
        EVENT_PROCESS_EXIT = 2,
        EVENT_PROCESS_CLONE = 3,
        EVENT_FILE_READ = 4,
        EVENT_FILE_WRITE = 5,
        EVENT_FILE_CREATE = 6,
        EVENT_FILE_PATH = 7,
        EVENT_FILE_MMAP = 8,
        EVENT_FILE_TEST = 9,
        EVENT_NET_CONNECT_PRE = 10,
        EVENT_NET_CONNECT_ACCEPT = 11,
        EVENT_NET_CONNECT_DNS_RESPONSE = 12,
        EVENT_NET_CONNECT_WEB_PROXY = 13,
        EVENT_FILE_DELETE = 14,
        EVENT_FILE_CLOSE = 15,
        EVENT_FILE_OPEN = 16
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
