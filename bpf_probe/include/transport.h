/* Copyright (c) 2022 VMWare, Inc. All rights reserved. */
/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

#ifdef BCC_SEC
// Used for prepending into embedded BCC source
#include <linux/types.h>
#endif

#ifdef __cplusplus
static const int MAX_FNAME = 255;
static const int CONTAINER_ID_LEN = 64;
#else
#define MAX_FNAME 255
#define CONTAINER_ID_LEN 64
#endif

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
    EVENT_PROCESS_EXEC_ARG,
    EVENT_PROCESS_EXEC_PATH,
    EVENT_PROCESS_EXEC_RESULT,
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
    EVENT_FILE_RENAME,
    EVENT_CONTAINER_CREATE,
};

struct data_header {
    uint64_t event_time; // Time the event collection started.  (Same across message parts.)
    uint8_t  type;
    uint8_t  state;

    uint32_t tid;
    uint32_t pid;
    uint32_t uid;
    uint32_t ppid;
    uint32_t mnt_ns;
};

struct data {
    struct data_header header;
};

struct exec_data
{
    struct data_header header;

    int retval;
};

struct file_data {
    struct data_header header;

    uint64_t inode;
    uint32_t device;
    uint64_t flags; // MMAP only
    uint64_t prot;  // MMAP only
    uint64_t fs_magic;
};

struct container_data {
    struct data_header header;

    char container_id[CONTAINER_ID_LEN + 1];
};

struct path_data {
    struct data_header header;

    uint8_t size;
#ifdef __cplusplus
    char fname[];
#else
    char fname[MAX_FNAME];
#endif
};

struct net_data
{
    struct data_header header;

    uint16_t ipver;
    uint16_t protocol;
    union {
        uint32_t local_addr;
        uint32_t local_addr6[4];
    };
    uint16_t local_port;
    union {
        uint32_t remote_addr;
        uint32_t remote_addr6[4];
    };
    uint16_t remote_port;
};

#ifdef __cplusplus
static const int DNS_SEGMENT_LEN = 40;
#else
#define DNS_SEGMENT_LEN 40
#endif
struct dns_data
{
    struct data_header header;

    char dns[DNS_SEGMENT_LEN];
    uint32_t name_len;
};

struct rename_data {
    struct data_header header;

    uint64_t old_inode;
    uint64_t new_inode;
    uint32_t device;
    uint64_t fs_magic;
};
