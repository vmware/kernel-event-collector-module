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
    EVENT_CGROUP_PATH,
};

#define REPORT_FLAGS_COMPAT     0x0000
// Signifies to use dynamic version of structs
#define REPORT_FLAGS_DYNAMIC    0x0001
#define REPORT_FLAGS_DENTRY     0x0002

struct data_header {
    uint64_t event_time; // Time the event collection started.  (Same across message parts.)
    uint8_t  type;
    uint8_t  state;
    uint16_t report_flags;
    uint32_t payload;

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

#define MAXARG 30
#define MAX_UCHAR_VAL 255
// So for now use the safe chunk read/write size.
#define MAX_ARG_CHUNK_SIZE MAX_UCHAR_VAL
#define MAX_PATH_COMPONENT_SIZE 256
#define MAX_CGROUP_PATH_ITER 8

// Alway ensure this a little bit larger than
// the MAX_PATH_ITER macros so the max blob size
// may increase appropriately.
#define HARD_MAX_PATH_ITER 42

// Blob sizes defines are to help with to computing the
// theoretical max sizes the BPF verifier wants to ensure
// there can be now overflow. The biggest factor for overflow
// then are max iteration amounts.

#define MAX_EXEC_ARG_BLOB_SIZE (MAXARG * MAX_ARG_CHUNK_SIZE)

#define MAX_CGROUP_BLOB_SIZE (MAX_PATH_COMPONENT_SIZE * MAX_CGROUP_PATH_ITER)

#define MAX_FILE_BLOB_SIZE (MAX_PATH_COMPONENT_SIZE * HARD_MAX_PATH_ITER)

#define MAX_FILE_PATH_BLOB_SIZE (MAX_FILE_BLOB_SIZE + MAX_CGROUP_BLOB_SIZE)

#define MAX_RENAME_BLOB_SIZE ((MAX_FILE_BLOB_SIZE * 2) + MAX_CGROUP_BLOB_SIZE)

#define MAX_DNS_BLOB_SIZE 4096

// Just let it use the largest blob
#define BLOB_OFFSET(data, blob_name) ((char *)data + data->blob_name.offset)

//
// This little struct tells us where a blob entry is located
// in the entire blob area of a message.
//
// Size and Offset must be nonzero.
// Size may exceed the static size of the char blob[...] member.
// Offset should be >= start of blob for event type.
// Offset likely won't exceed the static end position of the char blob[...]
//
struct blob_ctx {
    uint16_t size;
    uint16_t offset; // start_pos = ptr(event header) + offset
};

struct net_data {
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
struct dns_data {
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

struct data_x {
    struct data_header header;
    struct blob_ctx cgroup_blob;
    char blob[MAX_CGROUP_BLOB_SIZE];
};

struct file_path_data_x {
    struct data_header header;
    uint64_t inode;
    uint32_t device;
    uint64_t flags;
    uint64_t prot;
    uint64_t fs_magic;

    struct blob_ctx file_blob;
    struct blob_ctx cgroup_blob;
    char blob[MAX_FILE_PATH_BLOB_SIZE];
};

struct rename_data_x {
    struct data_header header;

    uint64_t old_inode;
    uint64_t new_inode;
    uint32_t device;
    uint64_t fs_magic;

    struct blob_ctx old_blob;
    struct blob_ctx new_blob;
    struct blob_ctx cgroup_blob;
    char blob[MAX_RENAME_BLOB_SIZE];
};

struct exec_arg_data {
    struct data_header header;

    struct blob_ctx exec_arg_blob;
    struct blob_ctx cgroup_blob; 
    char blob[MAX_EXEC_ARG_BLOB_SIZE];
};

struct dns_data_x {
    struct data_header header;
    struct blob_ctx dns_blob;
    char blob[MAX_DNS_BLOB_SIZE];
};

// Union for the base data payloads
#ifdef BCC_SEC
struct _file_event {
    union {
        struct file_data   _file_data;
        struct path_data   _path_data;
        struct rename_data _rename_data;
        struct data        _data;
    };
};
#else
struct _file_event {
    union {
        struct file_path_data_x _file_data_x;
        struct rename_data_x _rename_data_x;
        struct exec_arg_data _exec_data;
        struct file_data   _file_data;
        struct path_data   _path_data;
        struct rename_data _rename_data;
        struct data        _data;
        struct data_x      _data_x;
    };
};

// Used to keep the verifier happy on final payload checks
// and for sanity checks in userspace for max payloads.
#define MAX_BLOB_EVENT_SIZE (sizeof(struct _file_event))

#endif /* BCC_SEC */
