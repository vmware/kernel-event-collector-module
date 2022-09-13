/*
 * Copyright 2019-2021 VMware, Inc.
 * SPDX-License-Identifier: GPL-2.0
 */

#ifdef BCC_SEC
#define __BCC__
#endif

#ifdef __BCC__  /* BCC specific headers */
/* ---------------------------------------------------------------------*/

// Struct randomization causes issues on 4.13 and some early versions of 4.14
// These are redefined to work around this, per:
// https://lists.iovisor.org/g/iovisor-dev/topic/21386300#1239
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
#ifdef randomized_struct_fields_start
#undef randomized_struct_fields_start
#endif /* randomized_struct_fields_start */
#define randomized_struct_fields_start struct {
#ifdef randomized_struct_fields_end
#undef randomized_struct_fields_end
#endif /* randomized_struct_fields_end */
#define randomized_struct_fields_end \
    }                            \
    ;
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0) */

#ifndef KBUILD_MODNAME
#define KBUILD_MODNAME "vmw_bcc_bpfsensor"
#endif /* KBUILD_MODNAME */

#include <uapi/linux/limits.h>
#include <uapi/linux/in.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/ptrace.h>
#include <uapi/linux/stat.h>
#include <uapi/linux/udp.h>

#include <linux/binfmts.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/kdev_t.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/mount.h>
#include <linux/nsproxy.h>
#include <linux/ns_common.h>
#include <linux/path.h>
#include <linux/pid_namespace.h>
#include <linux/sched.h>
#include <linux/skbuff.h>

#include <net/sock.h>
#include <net/inet_sock.h>

// Create BPF_LRU if it does not exist.
// Support for lru hashes begins with 4.10, so a regular hash table must be used on earlier
// kernels (https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md#tables-aka-maps)
// This follows the form for other BPF_XXXX macros, so should work if it is ever added
#ifndef BPF_LRU
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
#define BPF_LRU1(_name) BPF_TABLE("lru_hash", u64, u64, _name, 10240)
#define BPF_LRU2(_name, _key_type) \
    BPF_TABLE("lru_hash", _key_type, u64, _name, 10240)
#define BPF_LRU3(_name, _key_type, _leaf_type) \
    BPF_TABLE("lru_hash", _key_type, _leaf_type, _name, 10240)
// helper for default-variable macro function
#define BPF_LRUX(_1, _2, _3, NAME, ...) NAME

// Define a hash function, some arguments optional
// BPF_LRU(name, key_type=u64, leaf_type=u64, size=10240)
#define BPF_LRU(...) \
    BPF_LRUX(__VA_ARGS__, BPF_LRU3, BPF_LRU2, BPF_LRU1)(__VA_ARGS__)
#else /* LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0) */
#define BPF_LRU BPF_HASH
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0) */
#endif /* BPF_LRU */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
// Existence of map tells userspace if kernel is LRU map capable
BPF_ARRAY(has_lru, uint32_t, 1);
#define FALLBACK_FIELD_TYPE(A, B) A
#else /* LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0) */
#define FALLBACK_FIELD_TYPE(A, B) B
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0) */

// is this struct really needed here?
struct mnt_namespace {
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
    atomic_t count;
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0) */
    struct ns_common ns;
};

struct mount {
    struct hlist_node mnt_hash;
    struct mount *mnt_parent;
    struct dentry *mnt_mountpoint;
    struct vfsmount mnt;
    void *cb_args;
} __randomize_layout;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
#define MAXARG 30
#else /* LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0) */
#define MAXARG 20
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)
#define __BCC_UNDER_4_10__
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0)
#define __BCC_UNDER_4_8__
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0) */


#else /* __BCC__ : non-BCC (libbpf specific) headers */
/* ---------------------------------------------------------------------*/

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
// TODO: Fix our kprobe syscall names so arm64 works too
_Bool LINUX_HAS_SYSCALL_WRAPPER = 0;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

//////////// Missing imports ///////////
#define BPF_F_CURRENT_CPU 0xffffffffULL
#define AF_INET     2       /* internetwork: UDP, TCP, etc. */
#define AF_INET6    28      /* IPv6 */
#define BPF_ANY     0 /* create new element or update existing */
#define BPF_NOEXIST 1 /* create new element if it didn't exist */
#define BPF_EXIST   2 /* update existing element */

// magic
#define DEBUGFS_MAGIC           0x64626720
#define SELINUX_MAGIC           0xf97cff8c
#define SMACK_MAGIC             0x43415d53  /* "SMAC" */
#define BPF_FS_MAGIC            0xcafe4a11
#define BINDERFS_SUPER_MAGIC    0x6c6f6f70
#define CGROUP_SUPER_MAGIC      0x27e0eb
#define CGROUP2_SUPER_MAGIC     0x63677270
#define TRACEFS_MAGIC           0x74726163
#define DEVPTS_SUPER_MAGIC      0x1cd1
#define FUTEXFS_SUPER_MAGIC     0xBAD1DEA
#define PROC_SUPER_MAGIC        0x9fa0
#define SOCKFS_MAGIC            0x534F434B
#define SYSFS_MAGIC             0x62656572
#define ANON_INODE_FS_MAGIC     0x09041934

#define PROT_EXEC               0x4                /* Page can be executed.  */

# define MAP_DENYWRITE          0x00800                /* ETXTBSY */
# define MAP_EXECUTABLE         0x01000                /* Mark it as an executable.  */

#define     S_IFMT              00170000
#define     S_IFREG             0100000
#define     S_ISREG(m)   (((m) & S_IFMT) == S_IFREG)

/* File is opened for execution with sys_execve / sys_uselib */
#define FMODE_EXEC      ((fmode_t)0x20)

//#define O_ACCMODE       00000003
//#define O_RDONLY        00000000
#define O_WRONLY        00000001
#define O_RDWR          00000002

#define PF_KTHREAD      0x00200000  /* I am a kernel thread */

#define MSG_PEEK    2

#define MINORBITS   20
#define MINORMASK   ((1U << MINORBITS) - 1)

#define MAJOR(dev)  ((unsigned int) ((dev) >> MINORBITS))
#define MINOR(dev)  ((unsigned int) ((dev) & MINORMASK))

static __always_inline u32 new_encode_dev(dev_t dev)
{
unsigned major = MAJOR(dev);
unsigned minor = MINOR(dev);
return (minor & 0xff) | (major << 8) | ((minor & ~0xff) << 12);
}

static inline uid_t __kuid_val(kuid_t uid)
{
return uid.val;
}

extern int LINUX_KERNEL_VERSION __kconfig;

#define MAXARG 30

#define s6_addr32       in6_u.u6_addr32

#endif /* __BCC__ : end of specific BCC/libbpf headers */
/* ---------------------------------------------------------------------*/

struct file_data_cache {
    u64 pid;
    u64 device;
    u64 inode;
};

#define CACHE_UDP

#ifdef CACHE_UDP
struct ip_key {
        uint32_t pid;
        uint16_t remote_port;
        uint16_t local_port;
        uint32_t remote_addr;
        uint32_t local_addr;
    };
    struct ip6_key {
        uint32_t pid;
        uint16_t remote_port;
        uint16_t local_port;
        uint32_t remote_addr6[4];
        uint32_t local_addr6[4];
    };
#define FLOW_TX 0x01
#define FLOW_RX 0x02
    struct ip_entry {
        u8 flow;
    };
#endif /* CACHE_UDP */

#ifdef __BCC__  /* BCC specific maps */
/* ---------------------------------------------------------------------*/

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0)
BPF_HASH(last_parent, u32, u32, 8192);
BPF_HASH(root_fs, u32, void *, 3); // stores last known root fs
#endif

BPF_PERF_OUTPUT(events);

// This hash tracks the "observed" file-create events.  This will not be 100% accurate because we will report a
//  file create for any file the first time it is opened with WRITE|TRUNCATE (even if it already exists).  It
//  will however serve to de-dup some events.  (Ie.. If a program does frequent open/write/close.)
BPF_LRU(file_map, struct file_data_cache, u32);

// Older kernels do not support the struct fields so allow for fallback
BPF_LRU(file_write_cache, u64, FALLBACK_FIELD_TYPE(struct file_data_cache, u32));

#ifdef CACHE_UDP
BPF_LRU(ip_cache, FALLBACK_FIELD_TYPE(struct ip_key, u32),
    FALLBACK_FIELD_TYPE(struct ip_entry, struct ip_key));
BPF_LRU(ip6_cache, FALLBACK_FIELD_TYPE(struct ip6_key, u32),
    FALLBACK_FIELD_TYPE(struct ip_entry, struct ip6_key));
#endif  /* CACHE_UDP */

BPF_LRU(currsock, u64, struct sock *);
BPF_LRU(currsock2, u64, struct msghdr *);
BPF_LRU(currsock3, u64, struct sock *);


#else /* __BCC__ : non-BCC (libbpf specific) maps */
/* ---------------------------------------------------------------------*/

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u32);
    __type(value, u32);
} last_parent SEC(".maps");

// dummy map for compilation
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 3);
    __type(key, u32);
    __type(value, void *);
} root_fs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

// This hash tracks the "observed" file-create events.  This will not be 100% accurate because we will report a
//  file create for any file the first time it is opened with WRITE|TRUNCATE (even if it already exists).  It
//  will however serve to de-dup some events.  (Ie.. If a program does frequent open/write/close.)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct file_data_cache);
    __type(value, u32);
    __uint(max_entries, 10240);
} file_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);
    __type(value, struct file_data_cache);
    __uint(max_entries, 10240);
} file_write_cache SEC(".maps");

#ifdef CACHE_UDP
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct ip_key);
    __type(value, struct ip_entry);
    __uint(max_entries, 10240);
} ip_cache SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct ip6_key);
    __type(value, struct ip_entry);
    __uint(max_entries, 10240);
} ip6_cache SEC(".maps");
#endif  /* CACHE_UDP */

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);
    __type(value, struct sock *);
    __uint(max_entries, 10240);
} currsock SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);
    __type(value, struct msghdr *);
    __uint(max_entries, 10240);
} currsock2 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);
    __type(value, struct sock *);
    __uint(max_entries, 10240);
} currsock3 SEC(".maps");

#endif /* __BCC__ : end of specific BCC/libbpf maps */
/* ---------------------------------------------------------------------*/

#ifdef __BCC__  /* BCC macro conversions */

#define ___concat(a, b) a ## b
#define ___apply(fn, n) ___concat(fn, n)
#define ___nth(_1, _2, _3, _4, _5, _6, _7, _8, _9, _10, __11, N, ...) N
#define ___narg(...) ___nth(_, ##__VA_ARGS__, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)

#define ___arrow1(a) a
#define ___arrow2(a, b) a->b
#define ___arrow3(a, b, c) a->b->c
#define ___arrow4(a, b, c, d) a->b->c->d
#define ___arrow5(a, b, c, d, e) a->b->c->d->e
#define ___arrow6(a, b, c, d, e, f) a->b->c->d->e->f
#define ___arrow7(a, b, c, d, e, f, g) a->b->c->d->e->f->g
#define ___arrow8(a, b, c, d, e, f, g, h) a->b->c->d->e->f->g->h
#define ___arrow9(a, b, c, d, e, f, g, h, i) a->b->c->d->e->f->g->h->i
#define ___arrow10(a, b, c, d, e, f, g, h, i, j) a->b->c->d->e->f->g->h->i->j
#define ___arrow(...) ___apply(___arrow, ___narg(__VA_ARGS__))(__VA_ARGS__)

#define BPF_CORE_READ(...) ___arrow(__VA_ARGS__)

# define bpf_core_read bpf_probe_read

#define bpf_perf_event_output(ctx, map_addr, _, data, data_size) \
    (*(map_addr).perf_submit(ctx, data, data_size))

#define bpf_map_lookup_elem(map, key) \
    (*(map).lookup(key))

#define bpf_map_delete_elem(map, key) \
    (*(map).delete(key))

#define bpf_map_update_elem(map, key, value, type) \
    { if (type == BPF_NOEXIST) {                   \
          *(map).insert(key, value);               \
      } else {                                     \
          *(map).update(key, value);               \
      }                                            \
    }

#define LINUX_KERNEL_VERSION LINUX_VERSION_CODE

#define SEC(...)

#define BPF_KPROBE_SYSCALL(name, ...) name(struct pt_regs *ctx, ##__VA_ARGS__)
#define BPF_KPROBE(name, args...) name(struct pt_regs *ctx, ##__VA_ARGS__)
#define BPF_KRETPROBE(name, args...) name(struct pt_regs *ctx, ##__VA_ARGS__)

#else /* __BCC__ : non-BCC (libbpf specific) macro covversions */

# define __user

#endif /* __BCC__ : end of  BCC macro conversions */

#ifndef PT_REGS_RC
#define PT_REGS_RC(x) ((x)->ax)
#endif

#define MAX_FNAME 255L
#define CONTAINER_ID_LEN 64

enum event_type {
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
    EVENT_CONTAINER_CREATE
};

#define DNS_RESP_PORT_NUM 53
#define DNS_RESP_MAXSIZE 512
#define PROXY_SERVER_MAX_LEN 100
#define DNS_SEGMENT_LEN 40
#define DNS_SEGMENT_FLAGS_START 0x01
#define DNS_SEGMENT_FLAGS_END 0x02

// Tells us the state for a probe point's data message
enum PP {
    PP_NO_EXTRA_DATA,
    PP_ENTRY_POINT,
    PP_PATH_COMPONENT,
    PP_FINALIZED,
    PP_APPEND,
    PP_DEBUG,
};

struct data_header {
    u64 event_time; // Time the event collection started.  (Same across message parts.)
    u8 type;
    u8 state;

    u32 tid;
    u32 pid;
    u32 uid;
    u32 ppid;
    u32 mnt_ns;
};

struct data {
    struct data_header header;
};

struct exec_data {
    struct data_header header;

    int retval;
};

struct file_data {
    struct data_header header;

    u64 inode;
    u32 device;
    u64 flags; // MMAP only
    u64 prot;  // MMAP only
    u64 fs_magic;
};

struct container_data {
    struct data_header header;

    char container_id[CONTAINER_ID_LEN + 1];
};

struct path_data {
    struct data_header header;

    u8 size;
    char fname[MAX_FNAME];
};

struct net_data {
    struct data_header header;

    u16 ipver;
    u16 protocol;
    union {
        u32 local_addr;
        u32 local_addr6[4];
    };
    u16 local_port;
    union {
        u32 remote_addr;
        u32 remote_addr6[4];
    };
    u16 remote_port;
};

struct dns_data {
    struct data_header header;

    char dns[DNS_SEGMENT_LEN];
    u32 name_len;
};

struct rename_data {
    struct data_header header;

    u64 old_inode, new_inode;
    u32 device;
    u64 fs_magic;
};

// THis is a helper struct for the "file like" events.  These follow a pattern where 3+n events are sent.
//  The first event sends the device/inode.  Each path element is sent as a separate event.  Finally an event is sent
//  to say the operation is complete.
// The macros below help to access the correct object in the struct.
struct _file_event
{
    union
    {
        struct file_data   _file_data;
        struct path_data   _path_data;
        struct rename_data _rename_data;
        struct data        _data;
    };
};

#define DECLARE_FILE_EVENT(DATA) struct _file_event DATA = {}
#define GENERIC_DATA(DATA)  ((struct data*)&((struct _file_event*)(DATA))->_data)
#define FILE_DATA(DATA)  ((struct file_data*)&((struct _file_event*)(DATA))->_file_data)
#define PATH_DATA(DATA)  ((struct path_data*)&((struct _file_event*)(DATA))->_path_data)
#define RENAME_DATA(DATA)  ((struct rename_data*)&((struct _file_event*)(DATA))->_rename_data)

static inline long cb_bpf_probe_read_str(void *dst, u32 size, const void *unsafe_ptr) {
    // Note that these functions are not 100% compatible.  The read_str function returns the number of bytes read,
    //   while the old version returns 0 on success.  Some of the logic we use does depend on the non-zero result
    //   (described later).
    if (LINUX_KERNEL_VERSION < KERNEL_VERSION(4, 11, 0)) {
        bpf_probe_read(dst, size, unsafe_ptr);
        return size;
    } else {
        return bpf_probe_read_str(dst, size, unsafe_ptr);
    }
}


static void send_event(
    struct pt_regs *ctx,
    void           *data,
    size_t          data_size)
{
    ((struct data*)data)->header.event_time = bpf_ktime_get_ns();
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, data, data_size);
}

static inline struct super_block *_sb_from_dentry(struct dentry *dentry)
{
    struct super_block *sb = NULL;
    // Can't get dentry info return NULL
    if (!dentry) {
        goto out;
    }
    // Try dentry inode before dentry's sb
    if (BPF_CORE_READ(dentry, d_inode)) {
        sb = BPF_CORE_READ(dentry, d_inode, i_sb);
    }
    if (sb) {
        goto out;
    }
    // This might not exactly be the sb we are looking for
    sb = BPF_CORE_READ(dentry, d_sb);

out:
    return sb;
}

static inline struct super_block *_sb_from_file(struct file *file)
{
    struct super_block *sb = NULL;

    if (!file) {
        goto out;
    }

    if (BPF_CORE_READ(file, f_inode)) {
        struct inode *pinode = NULL;

        bpf_core_read(&pinode, sizeof(pinode), &(file->f_inode));
        if (!pinode) {
            goto out;
        }
        bpf_core_read(&sb, sizeof(sb), &(pinode->i_sb));
    }
    if (sb) {
        goto out;
    }
    sb = _sb_from_dentry(BPF_CORE_READ(file, f_path.dentry));

out:
    return sb;
}

static inline bool __is_special_filesystem(struct super_block *sb)
{
    if (!sb) {
        return false;
    }

    switch (BPF_CORE_READ(sb, s_magic)) {
    // Special Kernel File Systems
    case CGROUP_SUPER_MAGIC:
#ifdef CGROUP2_SUPER_MAGIC
    case CGROUP2_SUPER_MAGIC:
#endif /* CGROUP2_SUPER_MAGIC */
    case SELINUX_MAGIC:
#ifdef SMACK_MAGIC
    case SMACK_MAGIC:
#endif /* SMACK_MAGIC */
    case SYSFS_MAGIC:
    case PROC_SUPER_MAGIC:
    case SOCKFS_MAGIC:
    case DEVPTS_SUPER_MAGIC:
    case FUTEXFS_SUPER_MAGIC:
    case ANON_INODE_FS_MAGIC:
    case DEBUGFS_MAGIC:
    case TRACEFS_MAGIC:
#ifdef BINDERFS_SUPER_MAGIC
    case BINDERFS_SUPER_MAGIC:
#endif /* BINDERFS_SUPER_MAGIC */
#ifdef BPF_FS_MAGIC
    case BPF_FS_MAGIC:
#endif /* BPF_FS_MAGIC */

        return true;

    default:
        return false;
    }

    return false;
}

static inline unsigned int __get_mnt_ns_id(struct task_struct *task)
{
    if (task && BPF_CORE_READ(task, nsproxy)) { // TODO: use bpf_core_field_exists()?
        return BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
    }
    return 0;
}

static inline u32 __get_device_from_sb(struct super_block *sb)
{
    dev_t device = 0;
    if (sb) {
        bpf_core_read(&device, sizeof(device), &sb->s_dev);
    }
    return new_encode_dev(device);
}

static inline u32 __get_device_from_dentry(struct dentry *dentry)
{
    return __get_device_from_sb(_sb_from_dentry(dentry));
}

static inline u32 __get_device_from_file(struct file *file)
{
    return __get_device_from_sb(_sb_from_file(file));
}

static inline u64 __get_inode_from_pinode(struct inode *pinode)
{
    u64 inode = 0;

    if (pinode) {
        bpf_core_read(&inode, sizeof(inode), &pinode->i_ino);
    }

    return inode;
}

static inline u64 __get_inode_from_file(struct file *file)
{
    if (file) {
        struct inode *pinode = NULL;

        bpf_core_read(&pinode, sizeof(pinode), &(file->f_inode));
        return __get_inode_from_pinode(pinode);
    }

    return 0;
}

static inline u64 __get_inode_from_dentry(struct dentry *dentry)
{
    if (dentry) {
        struct inode *pinode = NULL;

        bpf_core_read(&pinode, sizeof(pinode), &(dentry->d_inode));
        return __get_inode_from_pinode(pinode);
    }

    return 0;
}

static inline void __init_header_with_task(u8 type, u8 state, struct data_header *header, struct task_struct *task)
{
    header->type = type;
    header->state = state;

#ifdef __BCC_UNDER_4_8__
    u64 id = bpf_get_current_pid_tgid();
        header->tid = id & 0xffffffff;
        header->pid = id >> 32;

        u32 * ppid = bpf_map_lookup_elem(&last_parent, &header->pid);
        if (ppid) {
            header->ppid = *ppid;
        }
#else
    if (task) {
        header->tid = BPF_CORE_READ(task, pid);
        header->pid = BPF_CORE_READ(task, tgid);
        if (BPF_CORE_READ(task, cred)) { // TODO: use bpf_core_field_exists()?
            header->uid = BPF_CORE_READ(task, cred, uid.val);
        }
        if (BPF_CORE_READ(task, real_parent)) {
            header->ppid = BPF_CORE_READ(task, real_parent, tgid);
        }
        header->mnt_ns = __get_mnt_ns_id(task);
    }
#endif /* __BCC_UNDER_4_8__ */

}

// Assumed current context is what is valid!
static inline void __init_header(u8 type, u8 state, struct data_header *header)
{
    __init_header_with_task(type, state, header, (struct task_struct *)bpf_get_current_task());
}

static inline size_t PATH_MSG_SIZE(struct path_data *data) {
    if (LINUX_KERNEL_VERSION < KERNEL_VERSION(4, 18, 0)) {
        return sizeof(struct path_data);
    } else {
        return (size_t)(sizeof(struct path_data) - MAX_FNAME + data->size);
    }
}

static u8 __write_fname(struct path_data *data, const void *ptr)
{
    if (!ptr)
    {
        data->fname[0] = '\0';
        data->size = 1;
        return 0;
    }

    // Note: On some kernels bpf_probe_read_str does not exist.  In this case it is
    //  substituted by bpf_probe_read.
    // The bpf_probe_read_str will return the actual bytes written
    // The bpf_probe_read case will return MAX_FNAME
    data->size = cb_bpf_probe_read_str(&data->fname, MAX_FNAME, ptr);

    return data->size;
}

static u8 __submit_arg(struct pt_regs *ctx, void *ptr, struct path_data *data)
{
    // Note: On older kernel this may read past the actual arg list into the env.
    u8 result = __write_fname(data, ptr);

    // Don't copy the buffer which we did not actually write to.
    send_event(ctx, data, PATH_MSG_SIZE(data));
    return result;
}

// All arguments will be capped at MAX_FNAME bytes per argument
// (This is deliberately defined as a separate version of the function to cut down on the number
// of instructions needed, as older kernels have stricter limitations on the max count of the probe insns)

// PSCLNX-6764 - Improve EXEC event performance
//  This logic should be refactored to write the multiple args into a single
//  event buffer instead of one event per arg.
static void submit_all_args(struct pt_regs *ctx,
                            const char *const  *_argv,
                            struct path_data *data)
{
    void *argp = NULL;
    void *next_argp = NULL;
    int index = 0;

#pragma unroll
    for (int i = 0; i < MAXARG; i++) {
        if (LINUX_KERNEL_VERSION < KERNEL_VERSION(4, 11, 0)) {
            data->header.state = PP_ENTRY_POINT;
            bpf_probe_read(&argp, sizeof(argp), &_argv[index++]);
            if (!argp) {
                // We have reached the last arg so bail out
                goto out;
            }

            __submit_arg(ctx, argp, data);
        } else {
            if (next_argp) {
                // If there is more data to read in this arg, we tell the collector
                //  to continue with the previous arg (and not add a ' ').
                data->header.state = PP_APPEND;
                argp = next_argp;
                next_argp = NULL;
            } else {
                // This is a new arg
                data->header.state = PP_ENTRY_POINT;
                bpf_probe_read(&argp, sizeof(argp), &_argv[index++]);
            }
            if (!argp) {
                // We have reached the last arg so bail out
                goto out;
            }

            // Read the arg data and send an event.  We expect the result to be the bytes sent
            //  in the event.  On older kernels, this may be 0 which is OK.  It just means that
            //  we will always truncate the arg.
            u8 bytes_written = __submit_arg(ctx, argp, data);
            next_argp = NULL;

            if (bytes_written == MAX_FNAME) {
                // If we have filled the buffer exactly, it means that there is additional
                //  data for this arg.
                // Advance the read pointer by the bytes written (minus the null terminator)
                next_argp = argp + bytes_written - 1;
            }
        }
    }

    // handle truncated argument list
    char ellipsis[] = "...";
    __submit_arg(ctx, (void *)ellipsis, data);

out:
    data->header.state = PP_FINALIZED;
    send_event(ctx, (struct data*)data, sizeof(struct data));

    return;
}

#ifndef MAX_PATH_ITER
#define MAX_PATH_ITER 24
#endif

static inline int __do_file_path(struct pt_regs *ctx, struct dentry *dentry,
                 struct vfsmount *mnt, struct path_data *data)
{
    struct mount *real_mount = NULL;
    struct mount *mnt_parent = NULL;
    struct dentry *mnt_root = NULL;
    //struct dentry *new_mnt_root = NULL;
    struct dentry *parent_dentry = NULL;
    struct qstr sp = {};

    struct dentry *root_fs_dentry = NULL;
    struct vfsmount *root_fs_vfsmnt = NULL;

#ifdef __BCC_UNDER_4_8__
    u32 index = 0;
        struct dentry **t_dentry = (struct dentry **) bpf_map_lookup_elem(&root_fs, &index);
        if (t_dentry) {
            root_fs_dentry = *t_dentry;
        }
        index = 1;
        struct vfsmount **t_vfsmount = (struct vfsmount **) bpf_map_lookup_elem(&root_fs, &index);
        if (t_vfsmount) {
            root_fs_vfsmnt = *t_vfsmount;
        }
#else
    // We can ifdef this block to make this act more like either
    // d_absolute_path or __d_path
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (BPF_CORE_READ(task, fs)) { // TODO: use bpf_core_field_exists()?
        // We can get root fs path from mnt_ns or task
        root_fs_vfsmnt = BPF_CORE_READ(task, fs, root.mnt);
        root_fs_dentry = BPF_CORE_READ(task, fs, root.dentry);
    }
#endif /* __BCC_UNDER_4_8__ */
    mnt_root = BPF_CORE_READ(mnt, mnt_root);;

    // poorman's container_of
    real_mount = ((void *)mnt) - offsetof(struct mount, mnt);

    mnt_parent = BPF_CORE_READ(real_mount, mnt_parent);

    /*
     * File Path Walking. This may not be completely accurate but
     * should hold for most cases. Paths for private mount namespaces might work.
     */
    data->header.state = PP_PATH_COMPONENT;
#pragma clang loop unroll(full)
    for (int i = 1; i < MAX_PATH_ITER; ++i) {
        if (dentry == root_fs_dentry) {
            goto out;
        }

        bpf_core_read(&parent_dentry, sizeof(parent_dentry), &(dentry->d_parent));
        if (dentry == parent_dentry || dentry == mnt_root) {
            bpf_core_read(&dentry, sizeof(struct dentry *), &(real_mount->mnt_mountpoint));
            real_mount = mnt_parent;
            bpf_core_read(&mnt, sizeof(struct vfsmnt *), &(real_mount->mnt));
            mnt_root = BPF_CORE_READ(mnt, mnt_root);
            if (mnt == root_fs_vfsmnt) {
                goto out;
            }

            // prefetch next real mount parent.
            mnt_parent = BPF_CORE_READ(real_mount, mnt_parent);
            if (mnt_parent == real_mount) {
                goto out;
            }
        } else {
            bpf_core_read(&sp, sizeof(sp), (void *)&(dentry->d_name));
            __write_fname(data, sp.name);
            dentry = parent_dentry;
            send_event(ctx, data, PATH_MSG_SIZE(data));
        }
    }

out:
    data->header.state = PP_FINALIZED;
    return 0;
}

static inline int __do_dentry_path(struct pt_regs *ctx, struct dentry *dentry, struct path_data *data)
{
    struct dentry *parent_dentry = NULL;
    struct qstr sp = {};

    data->header.state = PP_PATH_COMPONENT;
#pragma unroll
    for (int i = 0; i < MAX_PATH_ITER; i++) {
        bpf_core_read(&parent_dentry, sizeof(parent_dentry), &(dentry->d_parent));

        if (parent_dentry == dentry || parent_dentry == NULL) {
            break;
        }

        bpf_core_read(&sp, sizeof(struct qstr), (void *)&(dentry->d_name));

        // Check that the name is valid
        //  We sometimes get a dentry of '/', so this logic will skip it
        if (__write_fname(data, sp.name) > 0 && data->size > 1) {
            send_event(ctx, data, PATH_MSG_SIZE(data));
        }

        dentry = parent_dentry;
    }

    // Trigger the agent to add the mount path
    data->header.state = PP_NO_EXTRA_DATA;
    send_event(ctx, GENERIC_DATA(data), sizeof(struct data));

    data->header.state = PP_FINALIZED;
    return 0;
}

SEC("kprobe/__x64_sys_execveat")
int BPF_KPROBE_SYSCALL(syscall__on_sys_execveat, int fd,
                 const char __user *filename,
                 const char __user *const __user *argv,
                 const char __user *const __user *envp, int flags)
{
    DECLARE_FILE_EVENT(data);

    __init_header(EVENT_PROCESS_EXEC_ARG, PP_ENTRY_POINT, &GENERIC_DATA(&data)->header);

    submit_all_args(ctx, argv, PATH_DATA(&data));

    return 0;
}

SEC("kprobe/__x64_sys_execve")
int BPF_KPROBE_SYSCALL(syscall__on_sys_execve, const char __user *filename,
               const char __user *const __user *argv,
               const char __user *const __user *envp)
{
    DECLARE_FILE_EVENT(data);

    __init_header(EVENT_PROCESS_EXEC_ARG, PP_ENTRY_POINT, &GENERIC_DATA(&data)->header);

    submit_all_args(ctx, argv, PATH_DATA(&data));

    return 0;
}

//Note that this can be called more than one from the same pid
SEC("kretprobe/__x64_sys_execve")
int BPF_KPROBE(after_sys_execve)
{
    struct exec_data data = {};

    __init_header(EVENT_PROCESS_EXEC_RESULT, PP_NO_EXTRA_DATA, &data.header);
    data.retval = PT_REGS_RC(ctx);

    send_event(ctx, &data, sizeof(struct exec_data));

    return 0;
}

static void __file_tracking_delete(u64 pid, u64 device, u64 inode)
{
    struct file_data_cache key = { .device = device, .inode = inode };
    bpf_map_delete_elem(&file_map, &key);
}

static inline void __track_write_entry(
    struct file      *file,
    struct file_data *data)
{
    if (!file || !data) {
        return;
    }

    u64 file_cache_key = (u64)file;

    void *cachep = bpf_map_lookup_elem(&file_write_cache, &file_cache_key);
    if (cachep) {
#ifdef __BCC_UNDER_4_10__
        u32 cache_data = *(u32 *)cachep;
        pid_t pid = cache_data;
        cache_data = data->header.pid;
#else
        struct file_data_cache cache_data = *((struct file_data_cache *) cachep);
        pid_t pid = cache_data.pid;
        cache_data.pid = data->header.pid;
#endif /* __BCC_UNDER_4_10__ */
        // if we really care about that multiple tasks
        // these are likely threads or less likely inherited from a fork
        if (pid == data->header.pid) {
            return;
        }

        bpf_map_update_elem(&file_write_cache, &file_cache_key, &cache_data, BPF_ANY);
    } else {
#ifdef __BCC_UNDER_4_10__
        u32 cache_data = data->header.pid;
#else
        struct file_data_cache cache_data = {
                .pid = data->header.pid,
                .device = data->device,
                .inode = data->inode
        };
#endif /* __BCC_UNDER_4_10__ */
        bpf_map_update_elem(&file_write_cache, &file_cache_key, &cache_data, BPF_NOEXIST);
    }
}

// Only need this hook for kernels without lru_hash
SEC("kprobe/security_file_free")
int BPF_KPROBE(on_security_file_free, struct file *file)
{
    if (!file) {
        return 0;
    }
    u64 file_cache_key = (u64)file;

    void *cachep = bpf_map_lookup_elem(&file_write_cache, &file_cache_key);
    if (cachep) {
        DECLARE_FILE_EVENT(data);
        __init_header(EVENT_FILE_CLOSE, PP_ENTRY_POINT, &GENERIC_DATA(&data)->header);

#ifdef __BCC_UNDER_4_10__
        FILE_DATA(&data)->device = __get_device_from_file(file);
            FILE_DATA(&data)->inode = __get_inode_from_file(file);
#else
        FILE_DATA(&data)->device = ((struct file_data_cache *) cachep)->device;
        FILE_DATA(&data)->inode = ((struct file_data_cache *) cachep)->inode;
#endif /* __BCC_UNDER_4_10__ */

        send_event(ctx, FILE_DATA(&data), sizeof(struct file_data));

        __do_file_path(ctx, BPF_CORE_READ(file, f_path.dentry), BPF_CORE_READ(file, f_path.mnt), PATH_DATA(&data));
        send_event(ctx, GENERIC_DATA(&data), sizeof(struct data));
    }

    bpf_map_delete_elem(&file_write_cache, &file_cache_key);
    return 0;
}

SEC("kprobe/security_mmap_file")
int BPF_KPROBE(on_security_mmap_file, struct file *file, unsigned long prot, unsigned long flags)
{
    unsigned long exec_flags;
    DECLARE_FILE_EVENT(data);

    if (!file) {
        goto out;
    }
    if (!(prot & PROT_EXEC)) {
        goto out;
    }

    exec_flags = flags & (MAP_DENYWRITE | MAP_EXECUTABLE);
    if (exec_flags == (MAP_DENYWRITE | MAP_EXECUTABLE)) {
        goto out;
    }

    __init_header(EVENT_FILE_MMAP, PP_ENTRY_POINT, &GENERIC_DATA(&data)->header);

    // event specific data
    FILE_DATA(&data)->device = __get_device_from_file(file);
    FILE_DATA(&data)->inode = __get_inode_from_file(file);
    FILE_DATA(&data)->flags = flags;
    FILE_DATA(&data)->prot = prot;
    // submit initial event data
    send_event(ctx, FILE_DATA(&data), sizeof(struct file_data));

    // submit file path event data
    __do_file_path(ctx, BPF_CORE_READ(file, f_path.dentry), BPF_CORE_READ(file, f_path.mnt), PATH_DATA(&data));
    send_event(ctx, GENERIC_DATA(&data), sizeof(struct data));
out:
    return 0;
}

// This is not available on older kernels.  So it will mean that we can not detect file creates
#ifndef FMODE_CREATED
#define FMODE_CREATED 0
#endif

// This hook may not be very accurate but at least tells us the intent
// to create the file if needed. So this will likely be written to next.
SEC("kprobe/security_file_open")
int BPF_KPROBE(on_security_file_open, struct file *file)
{
    DECLARE_FILE_EVENT(data);
    struct super_block *sb = NULL;
    struct inode *inode = NULL;
    int mode;

    if (!file) {
        goto out;
    }

    sb = _sb_from_file(file);
    if (!sb) {
        goto out;
    }

    if (__is_special_filesystem(sb)) {
        goto out;
    }

    bpf_core_read(&inode, sizeof(inode), &(file->f_inode));
    if (!inode) {
        goto out;
    }
#ifndef __BCC_UNDER_4_8__
    bpf_core_read(&mode, sizeof(mode), &(inode->i_mode));
    if (!S_ISREG(mode)) {
        goto out;
    }
#endif /* __BCC_UNDER_4_8__ ndef */

    u8 type;
    if (BPF_CORE_READ(file, f_flags) & FMODE_EXEC) {
        type = EVENT_PROCESS_EXEC_PATH;
    } else if ((BPF_CORE_READ(file, f_mode) & FMODE_CREATED)) {
        type = EVENT_FILE_CREATE;
    } else if (BPF_CORE_READ(file, f_flags) & (O_RDWR | O_WRONLY)) {
        type = EVENT_FILE_WRITE;
    } else {
        type = EVENT_FILE_READ;
    }

    __init_header(type, PP_ENTRY_POINT, &GENERIC_DATA(&data)->header);
    FILE_DATA(&data)->device = __get_device_from_file(file);
    FILE_DATA(&data)->inode = __get_inode_from_file(file);
    FILE_DATA(&data)->flags = BPF_CORE_READ(file, f_flags);
    FILE_DATA(&data)->prot = BPF_CORE_READ(file, f_mode);
    FILE_DATA(&data)->fs_magic = BPF_CORE_READ(sb, s_magic);

    if (type == EVENT_FILE_WRITE || type == EVENT_FILE_CREATE)
    {
        // This allows us to send the last-write event on file close
        __track_write_entry(file, FILE_DATA(&data));
    }

    send_event(ctx, FILE_DATA(&data), sizeof(struct file_data));

    __do_file_path(ctx, BPF_CORE_READ(file, f_path.dentry), BPF_CORE_READ(file, f_path.mnt), PATH_DATA(&data));

    send_event(ctx, GENERIC_DATA(&data), sizeof(struct data));

out:
    return 0;
}

static bool __send_dentry_delete(struct pt_regs *ctx, void *data, struct dentry *dentry)
{
    if (dentry)
    {
        struct super_block *sb = _sb_from_dentry(dentry);

        if (sb && !__is_special_filesystem(sb))
        {
            __init_header(EVENT_FILE_DELETE, PP_ENTRY_POINT, &GENERIC_DATA(data)->header);

            FILE_DATA(data)->device = __get_device_from_sb(sb);
            FILE_DATA(data)->inode = __get_inode_from_dentry(dentry);

            __file_tracking_delete(0, FILE_DATA(data)->device, FILE_DATA(data)->inode);

            send_event(ctx, FILE_DATA(data), sizeof(struct file_data));
            __do_dentry_path(ctx, dentry, PATH_DATA(data));
            send_event(ctx, GENERIC_DATA(data), sizeof(struct data));
            return true;
        }
    }

    return false;
}

SEC("kprobe/security_inode_unlink")
int BPF_KPROBE(on_security_inode_unlink, struct inode *dir, struct dentry *dentry)
{
    DECLARE_FILE_EVENT(data);
    // struct super_block *sb = NULL;
    // int mode;

    if (!dentry) {
        goto out;
    }

    __send_dentry_delete(ctx, &data, dentry);

out:
    return 0;
}

SEC("kprobe/security_inode_rename")
int BPF_KPROBE(on_security_inode_rename, struct inode *old_dir,
             struct dentry *old_dentry, struct inode *new_dir,
             struct dentry *new_dentry, unsigned int flags)
{
    DECLARE_FILE_EVENT(data);
    struct super_block *sb = NULL;

    // send event for delete of source file
    if (!__send_dentry_delete(ctx, &data, old_dentry)) {
        goto out;
    }

    __init_header(EVENT_FILE_RENAME, PP_ENTRY_POINT, &GENERIC_DATA(&data)->header);

    sb = _sb_from_dentry(old_dentry);

    RENAME_DATA(&data)->device = __get_device_from_dentry(old_dentry);
    RENAME_DATA(&data)->old_inode = __get_inode_from_dentry(old_dentry);
    RENAME_DATA(&data)->fs_magic = sb ? BPF_CORE_READ(sb, s_magic) : 0;

    __file_tracking_delete(0, RENAME_DATA(&data)->device, RENAME_DATA(&data)->old_inode);

    // If the target destination already exists
    if (new_dentry)
    {
        __file_tracking_delete(0, RENAME_DATA(&data)->device, RENAME_DATA(&data)->new_inode);

        RENAME_DATA(&data)->new_inode  = __get_inode_from_dentry(new_dentry);
    }
    else
    {
        RENAME_DATA(&data)->new_inode  = 0;
    }

    send_event(ctx, RENAME_DATA(&data), sizeof(struct rename_data));

    __do_dentry_path(ctx, new_dentry, PATH_DATA(&data));
    send_event(ctx, GENERIC_DATA(&data), sizeof(struct data));
out:
    return 0;
}

SEC("kprobe/wake_up_new_task")
int BPF_KPROBE(on_wake_up_new_task, struct task_struct *task)
{
    // struct inode *pinode = NULL;
    struct file_data data = {};
    if (!task) {
        goto out;
    }

    if (BPF_CORE_READ(task, tgid) != BPF_CORE_READ(task, pid)) {
        goto out;
    }

    __init_header_with_task(EVENT_PROCESS_CLONE, PP_NO_EXTRA_DATA, &data.header, task);

    data.header.uid = BPF_CORE_READ(task, real_parent, cred, uid.val);

#ifdef __BCC_UNDER_4_8__
    // Poorman's method for storing root fs path data->
    // This is to prevent us from iterating past '/'
    u32 index;
    struct dentry *root_fs_dentry = BPF_CORE_READ(task, fs, root.dentry);
    struct vfsmount *root_fs_vfsmount = BPF_CORE_READ(task, fs, root.mnt);
    index = 0;
    bpf_map_update_elem(&root_fs, &index, (void *)&root_fs_dentry, BPF_ANY);
    index += 1;
    bpf_map_update_elem(&root_fs, &index, (void *)&root_fs_vfsmount, BPF_ANY);
#endif /* __BCC_UNDER_4_8__ */

    if (!(BPF_CORE_READ(task, flags) & PF_KTHREAD) && BPF_CORE_READ(task,mm) && BPF_CORE_READ(task, mm, exe_file)) {
        data.device = __get_device_from_file(BPF_CORE_READ(task, mm, exe_file));
        data.inode = __get_inode_from_file(BPF_CORE_READ(task, mm, exe_file));
    }

    send_event(ctx, &data, sizeof(struct file_data));

out:
    return 0;
}

#ifdef CACHE_UDP
static inline bool has_ip_cache(struct ip_key *ip_key, u8 flow)
{
#ifdef __BCC_UNDER_4_10__
    struct ip_key *ip_entry = bpf_map_lookup_elem(&ip_cache, &ip_key->pid);
        if (ip_entry) {
            if (ip_entry->remote_port == ip_key->remote_port &&
                ip_entry->local_port == ip_key->local_port &&
                ip_entry->remote_addr == ip_key->remote_addr &&
                ip_entry->local_addr == ip_key->local_addr) {
                return true;
            } else {
                // Update entry
                bpf_map_update_elem(&ip_cache, &ip_key->pid, ip_key, BPF_ANY);
            }
        } else {
            bpf_map_update_elem(&ip_cache, &ip_key->pid, ip_key, BPF_NOEXIST); // insert
        }
#else
    struct ip_key ip_key_alternate = *ip_key;
    struct ip_entry *ip_entry = NULL;

    if (flow == FLOW_RX) {
        ip_key->remote_port = 0;
        ip_key_alternate.local_port = 0;
    } else {
        ip_key->local_port = 0;
        ip_key_alternate.remote_port = 0;
    }

    ip_entry = bpf_map_lookup_elem(&ip_cache, ip_key);
    if (!ip_entry) {
        struct ip_entry new_entry = {};
        new_entry.flow = flow;
        bpf_map_update_elem(&ip_cache, ip_key, &new_entry, BPF_NOEXIST); // insert

        ip_entry = bpf_map_lookup_elem(&ip_cache, &ip_key_alternate);
        if (!ip_entry) {
            bpf_map_update_elem(&ip_cache, &ip_key_alternate, &new_entry, BPF_NOEXIST); // insert
        } else {
            return true;
        }
    } else {
        return true;
    }
#endif /* __BCC_UNDER_4_10__ */
    return false;
}

static inline bool has_ip6_cache(struct ip6_key *ip6_key, u8 flow)
{
#ifdef __BCC_UNDER_4_10__
    struct ip6_key *ip_entry = bpf_map_lookup_elem(&ip6_cache, &ip6_key->pid);
        if (ip_entry) {
            if (ip_entry->remote_port == ip6_key->remote_port &&
                ip_entry->local_port == ip6_key->local_port &&
                ip_entry->remote_addr6[0] == ip6_key->remote_addr6[0] &&
                ip_entry->remote_addr6[1] == ip6_key->remote_addr6[1] &&
                ip_entry->remote_addr6[2] == ip6_key->remote_addr6[2] &&
                ip_entry->remote_addr6[3] == ip6_key->remote_addr6[3] &&
                ip_entry->local_addr6[0] == ip6_key->local_addr6[0] &&
                ip_entry->local_addr6[1] == ip6_key->local_addr6[1] &&
                ip_entry->local_addr6[2] == ip6_key->local_addr6[2] &&
                ip_entry->local_addr6[3] == ip6_key->local_addr6[3]) {
                return true;
            } else {
                // Update entry
                bpf_map_update_elem(&ip6_cache, &ip6_key->pid, ip6_key, BPF_ANY);
            }
        } else {
            bpf_map_update_elem(&ip6_cache, &ip6_key->pid, ip6_key, BPF_NOEXIST); // insert
        }
#else
    struct ip6_key ip6_key_alternate = *ip6_key;
    struct ip_entry *ip_entry = NULL;

    if (flow == FLOW_RX) {
        ip6_key->remote_port = 0;
        ip6_key_alternate.local_port = 0;
    } else {
        ip6_key->local_port = 0;
        ip6_key_alternate.remote_port = 0;
    }

    ip_entry = bpf_map_lookup_elem(&ip6_cache, ip6_key);
    if (!ip_entry) {
        struct ip_entry new_entry = {};
        new_entry.flow = flow;
        bpf_map_update_elem(&ip6_cache, ip6_key, &new_entry, BPF_NOEXIST); // insert

        ip_entry = bpf_map_lookup_elem(&ip6_cache, &ip6_key_alternate);
        if (!ip_entry) {
            bpf_map_update_elem(&ip6_cache, &ip6_key_alternate, &new_entry, BPF_NOEXIST); // insert
        } else {
            return true;
        }
    } else {
        return true;
    }
#endif /* __BCC_UNDER_4_10__ */
    return false;
}
#endif /* CACHE_UDP */

SEC("kprobe/do_exit")
int BPF_KPROBE(on_do_exit, long code)
{
    struct data data = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    if (!task) {
        goto out;
    }
    if (BPF_CORE_READ(task, tgid) != BPF_CORE_READ(task, pid)) {
        goto out;
    }

    __init_header(EVENT_PROCESS_EXIT, PP_NO_EXTRA_DATA, &data.header);

    send_event(ctx, &data, sizeof(struct data));

#ifdef __BCC_UNDER_4_8__
    bpf_map_delete_elem(&last_parent, &data.header.pid);
#endif /* __BCC_UNDER_4_8__ */

#ifdef __BCC_UNDER_4_10__
    #ifdef CACHE_UDP
        // Remove burst cache entries
        //  We only need to do this for older kernels that do not have an LRU
        bpf_map_delete_elem(&ip_cache, &data.header.pid);
        bpf_map_delete_elem(&ip6_cache, &data.header.pid);
    #endif /* CACHE_UDP */
#endif /* __BCC_UNDER_4_10__ */


out:
    return 0;
}


static inline int trace_connect_entry(struct sock *sk)
{
    u64 id = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&currsock, &id, &sk, BPF_ANY);
    return 0;
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(trace_connect_v4_entry, struct sock *sk)
{
    return trace_connect_entry(sk);
}

SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(trace_connect_v6_entry, struct sock *sk)
{
    return trace_connect_entry(sk);
}

static inline bool check_family(struct sock *sk, u16 expected_family)
{
    u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    return family == expected_family;
}

static inline int trace_connect_return(struct pt_regs *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    // u32 pid = id >> 32;
    int ret = PT_REGS_RC(ctx);
    if (ret != 0) {
        bpf_map_delete_elem(&currsock, &id);
        return 0;
    }

    struct sock **skpp;
    skpp = bpf_map_lookup_elem(&currsock, &id);
    if (skpp == 0) {
        return 0;
    }

    struct net_data data = {};
    struct sock *skp = *skpp;
    u16 dport = BPF_CORE_READ(skp, __sk_common.skc_dport);

    __init_header(EVENT_NET_CONNECT_PRE, PP_NO_EXTRA_DATA, &data.header);
    data.protocol = IPPROTO_TCP;
    data.remote_port = dport;

    struct inet_sock *sockp = (struct inet_sock *)skp;
    data.local_port = BPF_CORE_READ(sockp, inet_sport);

    if (check_family(skp, AF_INET)) {
        data.ipver = AF_INET;
        data.local_addr =
            BPF_CORE_READ(skp, __sk_common.skc_rcv_saddr);
        data.remote_addr =
            BPF_CORE_READ(skp, __sk_common.skc_daddr);

        send_event(ctx, &data, sizeof(data));
    } else if (check_family(skp, AF_INET6)) {
        data.ipver = AF_INET6;
        bpf_probe_read(
            &data.local_addr6, sizeof(data.local_addr6),
            BPF_CORE_READ(skp, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32));
        bpf_probe_read(&data.remote_addr6,
                   sizeof(data.remote_addr6),
                   BPF_CORE_READ(skp, __sk_common.skc_v6_daddr.in6_u.u6_addr32));

        send_event(ctx, &data, sizeof(data));
    }

    bpf_map_delete_elem(&currsock, &id);
    return 0;
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(trace_connect_v4_return)
{
    return trace_connect_return(ctx);
}

SEC("kretprobe/tcp_v6_connect")
int BPF_KRETPROBE(trace_connect_v6_return)
{
    return trace_connect_return(ctx);
}

SEC("kretprobe/__skb_recv_udp")
int BPF_KRETPROBE(trace_skb_recv_udp)
{
    // u64 id = bpf_get_current_pid_tgid();
    // u32 pid = id >> 32;

    struct sk_buff *skb = (struct sk_buff *)PT_REGS_RC(ctx);
    if (skb == NULL) {
        return 0;
    }

#ifdef __BCC_UNDER_4_8__
        // Older kernels we probe __skb_recv_datagram which can be used by
        // other protocols. We filter by sk_family or skb->protocol
        if (!BPF_CORE_READ(skb, sk)) {
            return 0;
        }

        if (!(BPF_CORE_READ(skb, sk, sk_family) == AF_INET ||
              BPF_CORE_READ(skb, sk, sk_family) == AF_INET6)) {
            return 0;
        }
#endif /* __BCC_UNDER_4_8__ */
    struct udphdr *udphdr = NULL;

    // Get a pointer to the network header and the header length.
    //  We use the header length to decide if this is IPv4 or IPv6
    void *hdr = (struct iphdr *)(BPF_CORE_READ(skb, head) + BPF_CORE_READ(skb, network_header));
    u32 hdr_len = BPF_CORE_READ(skb, transport_header) - BPF_CORE_READ(skb, network_header);

    struct net_data data = {};

    __init_header(EVENT_NET_CONNECT_ACCEPT, PP_NO_EXTRA_DATA, &data.header);

    data.protocol = IPPROTO_UDP;

    udphdr = (struct udphdr *)(BPF_CORE_READ(skb, head) + BPF_CORE_READ(skb, transport_header));
    data.remote_port = BPF_CORE_READ(udphdr, source);
    data.local_port = BPF_CORE_READ(udphdr, dest);

    if (hdr_len == sizeof(struct iphdr)) {
        struct iphdr *iphdr = (struct iphdr *)hdr;

        data.ipver = AF_INET;
        data.local_addr = BPF_CORE_READ(iphdr, daddr);
        data.remote_addr = BPF_CORE_READ(iphdr, saddr);

#ifdef CACHE_UDP
        struct ip_key ip_key = {};
        ip_key.pid = data.header.pid;
        bpf_probe_read(&ip_key.remote_port, sizeof(data.remote_port),
                   &data.remote_port);
        bpf_probe_read(&ip_key.local_port, sizeof(data.local_port),
                   &data.local_port);
        bpf_probe_read(&ip_key.remote_addr,
                   sizeof(data.remote_addr),
                   &data.remote_addr);
        bpf_probe_read(&ip_key.local_addr, sizeof(data.local_addr),
                   &data.local_addr);
        if (has_ip_cache(&ip_key, FLOW_RX)) {
            return 0;
        }
#endif /* CACHE_UDP */
    } else if (hdr_len == sizeof(struct ipv6hdr)) {
        // Why IPv6 address/port is read in a different way than IPv4:
        //  - BPF C compiled to BPF instructions don't always do what we expect
        //  - especially when accessing members of a struct containing bitfields
        struct ipv6hdr *ipv6hdr = (struct ipv6hdr *)hdr;

        data.ipver = AF_INET6;
        bpf_core_read(data.local_addr6, sizeof(uint32_t) * 4,
                   &ipv6hdr->daddr.s6_addr32);
        bpf_core_read(data.remote_addr6, sizeof(uint32_t) * 4,
                   &ipv6hdr->saddr.s6_addr32);

#ifdef CACHE_UDP
        struct ip6_key ip_key = {};
        ip_key.pid = data.header.pid;
        bpf_probe_read(&ip_key.remote_port, sizeof(data.remote_port),
                   &data.remote_port);
        bpf_probe_read(&ip_key.local_port, sizeof(data.local_port),
                   &data.local_port);
        bpf_core_read(ip_key.remote_addr6,
                   sizeof(data.remote_addr6),
                   &ipv6hdr->daddr.s6_addr32);
        bpf_core_read(ip_key.local_addr6, sizeof(data.local_addr6),
                   &ipv6hdr->saddr.s6_addr32);
        if (has_ip6_cache(&ip_key, FLOW_RX)) {
            return 0;
        }
#endif /* CACHE_UDP */
    } else {
        return 0;
    }

    send_event(ctx, &data, sizeof(data));

    return 0;
}

// check for system endianess
static inline bool _is_big_endian(){
    unsigned int x = 1;
    char *c = (char*) &x;
    return ((int)*c == 0);
}

static inline uint16_t _htons(uint16_t hostshort){
    if (_is_big_endian()) {
        return hostshort;
    } else {
        return __builtin_bswap16(hostshort);
    }
}

static inline uint16_t _ntohs(uint16_t netshort){
    if (_is_big_endian()) {
        return netshort;
    } else {
        return __builtin_bswap16(netshort);
    }
}

SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(trace_accept_return)
{
    // u64 id = bpf_get_current_pid_tgid();
    // u32 pid = id >> 32;

    struct sock *newsk = (struct sock *)PT_REGS_RC(ctx);
    if (newsk == NULL) {
        return 0;
    }

    struct net_data data = {};

    __init_header(EVENT_NET_CONNECT_ACCEPT, PP_NO_EXTRA_DATA, &data.header);
    data.protocol = IPPROTO_TCP;

    data.ipver = BPF_CORE_READ(newsk,__sk_common.skc_family);
    __u16 snum = BPF_CORE_READ(newsk, __sk_common.skc_num);
    bpf_core_read(&data.local_port, sizeof(snum), &snum);
    data.local_port = _htons(data.local_port);
    data.remote_port = BPF_CORE_READ(newsk, __sk_common.skc_dport); // network order dport

    if (check_family(newsk, AF_INET)) {
        data.local_addr = BPF_CORE_READ(newsk, __sk_common.skc_rcv_saddr);
        data.remote_addr = BPF_CORE_READ(newsk, __sk_common.skc_daddr);

        if (data.local_addr != 0 && data.remote_addr != 0 &&
            data.local_port != 0 && data.remote_port != 0) {
            send_event(ctx, &data, sizeof(data));
        }
    } else if (check_family(newsk, AF_INET6)) {
        bpf_probe_read(&data.local_addr6, sizeof(data.local_addr6), BPF_CORE_READ(newsk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32));
        bpf_probe_read(&data.remote_addr6, sizeof(data.remote_addr6), BPF_CORE_READ(newsk, __sk_common.skc_v6_daddr.in6_u.u6_addr32));

        send_event(ctx, &data, sizeof(data));
    }
    return 0;
}

SEC("kprobe/udp_recvmsg")
int BPF_KPROBE(trace_udp_recvmsg, struct sock *sk, struct msghdr *msg, size_t length, int noblock, int flags)
{
    u64 pid;

    pid = bpf_get_current_pid_tgid();
    if (flags != MSG_PEEK) {
        bpf_map_update_elem(&currsock2, &pid, &msg, BPF_ANY);
        bpf_map_update_elem(&currsock3, &pid, &sk, BPF_ANY);
    }

    return 0;
}

SEC("kretprobe/udp_recvmsg")
int BPF_KRETPROBE(trace_udp_recvmsg_return)
{
    int ret = PT_REGS_RC(ctx);
    u64 id = bpf_get_current_pid_tgid();
    // u32 pid = id >> 32;

    struct msghdr **msgpp; // for DNS receive probe

    msgpp = bpf_map_lookup_elem(&currsock2, &id);
    if (msgpp == 0) {
        return 0; // missed entry
    }

    if (ret <= 0) {
        bpf_map_delete_elem(&currsock2, &id);
        return 0;
    }

    struct dns_data data = {};
    __init_header(EVENT_NET_CONNECT_DNS_RESPONSE, PP_ENTRY_POINT, &data.header);

    // Send DNS info if port is DNS
    struct msghdr *msgp = *msgpp;

    const char __user *dns;
    struct iov_iter msgiter = BPF_CORE_READ(msgp, msg_iter);
    dns = BPF_CORE_READ(msgiter.iov, iov_base);

    struct sockaddr_in * msgname = (struct sockaddr_in *)BPF_CORE_READ(msgp, msg_name);
    u16 dport = BPF_CORE_READ(msgname, sin_port);
    u16 len = ret;
    data.name_len = ret;

    if (DNS_RESP_PORT_NUM == _ntohs(dport)) {
#pragma unroll
        for (int i = 1; i <= (DNS_RESP_MAXSIZE / DNS_SEGMENT_LEN) + 1; ++i) {
            if (len > 0 && len < DNS_RESP_MAXSIZE) {
                bpf_probe_read(&data.dns, DNS_SEGMENT_LEN, dns);

                if (i > 1) {
                    data.header.state = PP_APPEND;
                }

                send_event(ctx, &data, sizeof(struct dns_data));
                len = len - DNS_SEGMENT_LEN;
                dns = dns + DNS_SEGMENT_LEN;
            } else {
                break;
            }
        }
    }

    bpf_map_delete_elem(&currsock2, &id);
    return 0;
}

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(trace_udp_sendmsg, struct sock *sk, struct msghdr *msg)
{
    u64 id;

    id = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&currsock3, &id, &sk, BPF_ANY);
    bpf_map_update_elem(&currsock2, &id, &msg, BPF_ANY);
    return 0;
}

SEC("kretprobe/udp_sendmsg")
int BPF_KRETPROBE(trace_udp_sendmsg_return)
{
    int ret = PT_REGS_RC(ctx);
    u64 id  = bpf_get_current_pid_tgid();

    struct sock **skpp;
    skpp = bpf_map_lookup_elem(&currsock3, &id);
    if (skpp == 0) {
        return 0;
    }

    struct msghdr **msgpp;
    msgpp = bpf_map_lookup_elem(&currsock2, &id);

    if (ret <= 0) {
        bpf_map_delete_elem(&currsock3, &id);
        bpf_map_delete_elem(&currsock2, &id);
        return 0;
    }

    struct net_data data = {};
    __init_header(EVENT_NET_CONNECT_PRE, PP_NO_EXTRA_DATA, &data.header);
    data.protocol = IPPROTO_UDP;
    // The remote addr could be in the msghdr::msg_name or on the sock
    bool addr_in_msghr = false;

    // get ip version
    struct sock *skp = *skpp;
    data.ipver = BPF_CORE_READ(skp, __sk_common.skc_family);

    if (msgpp)
    {
        struct msghdr msghdr;

        bpf_probe_read(&msghdr, sizeof(msghdr), *msgpp);

        if (msghdr.msg_name && msghdr.msg_namelen > 0)
        {
            if (check_family(skp, AF_INET) && msghdr.msg_namelen >= sizeof(struct sockaddr_in))
            {
                struct sockaddr_in addr_in;
                bpf_probe_read(&addr_in, sizeof(addr_in), msghdr.msg_name);
                data.remote_port = addr_in.sin_port;
                data.remote_addr = addr_in.sin_addr.s_addr;

                addr_in_msghr = true;
            }
            else if (check_family(skp, AF_INET6) && msghdr.msg_namelen >= sizeof(struct sockaddr_in6))
            {
                struct sockaddr_in6 addr_in;
                bpf_probe_read(&addr_in, sizeof(addr_in), msghdr.msg_name);
                data.remote_port = addr_in.sin6_port;
                bpf_probe_read(
                    &data.remote_addr6, sizeof(data.remote_addr6),
                    &addr_in.sin6_addr);

                addr_in_msghr = true;
            }
        }
    }

    __u16 snum = BPF_CORE_READ(skp, __sk_common.skc_num);
    bpf_probe_read(&data.local_port, sizeof(snum), &snum);
    data.local_port = _htons(data.local_port);

    if (!addr_in_msghr)
    {
        data.remote_port = BPF_CORE_READ(skp, __sk_common.skc_dport); // already network order
    }

    if (check_family(skp, AF_INET))
    {
        data.local_addr = BPF_CORE_READ(skp, __sk_common.skc_rcv_saddr);
        if (!addr_in_msghr)
        {
            data.remote_addr = BPF_CORE_READ(skp, __sk_common.skc_daddr);
        }


#ifdef CACHE_UDP
        struct ip_key ip_key = {};
        ip_key.pid = data.header.pid;
        bpf_probe_read(&ip_key.remote_port, sizeof(data.remote_port),
                       &data.remote_port);
        bpf_probe_read(&ip_key.local_port, sizeof(data.local_port),
                       &data.local_port);
        bpf_probe_read(&ip_key.remote_addr, sizeof(data.remote_addr),
                       &data.remote_addr);
        bpf_probe_read(&ip_key.local_addr, sizeof(data.local_addr),
                       &data.local_addr);

        if (has_ip_cache(&ip_key, FLOW_TX))
        {
            goto out;
        }
#endif /* CACHE_UDP */
    }
    else if (check_family(skp, AF_INET6))
    {
        if (!addr_in_msghr)
        {
            __be32 *daddr = BPF_CORE_READ(skp, __sk_common.skc_v6_daddr.in6_u.u6_addr32);
            bpf_probe_read(&data.remote_addr6, sizeof(data.remote_addr6), &daddr);
        }

        __be32 *saddr = BPF_CORE_READ(skp, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read(&data.local_addr6, sizeof(data.local_addr6), &saddr);

#ifdef CACHE_UDP
        struct ip6_key ip_key = {};
        ip_key.pid = data.header.pid;
        bpf_probe_read(&ip_key.remote_port, sizeof(data.remote_port), &data.remote_port);
        bpf_probe_read(&ip_key.local_port, sizeof(data.local_port), &data.local_port);

        bpf_probe_read(ip_key.remote_addr6, sizeof(data.remote_addr6), &data.remote_addr6);
        bpf_probe_read(ip_key.local_addr6, sizeof(data.local_addr6), &data.local_addr6);

        if (has_ip6_cache(&ip_key, FLOW_TX)) {
            goto out;
        }
#endif /* CACHE_UDP */
    }
    send_event(ctx, &data, sizeof(data));

out:
    bpf_map_delete_elem(&currsock3, &id);
    bpf_map_delete_elem(&currsock2, &id);
    return 0;
}

//int on_cgroup_attach_task(struct pt_regs *ctx, struct cgroup *dst_cgrp, struct task_struct *task, bool threadgroup)
//{
//    struct kernfs_node *node = NULL;
//
//    bpf_probe_read(&node, sizeof(node), &(dst_cgrp->kn));
//    if (node == NULL)
//        return 0;
//
//    const char * cgroup_dirname = NULL;
//    bpf_probe_read(&cgroup_dirname, sizeof(cgroup_dirname), &(node->name));
//
//    struct container_data data = {};
//    __init_header(EVENT_CONTAINER_CREATE, PP_ENTRY_POINT, &GENERIC_DATA(&data)->header);
//
//
//    // Check for common container prefixes, and then try to read the full-length CONTAINER_ID
//    unsigned int offset = 0;
//    if (cb_bpf_probe_read_str(&data.container_id, 8, cgroup_dirname) == 8)
//    {
//
//        if (data.container_id[0] == 'd' &&
//            data.container_id[1] == 'o' &&
//            data.container_id[2] == 'c' &&
//            data.container_id[3] == 'k' &&
//            data.container_id[4] == 'e' &&
//            data.container_id[5] == 'r' &&
//            data.container_id[6] == '-')
//        {
//            offset = 7;
//        }
//
//        if (data.container_id[0] == 'l' &&
//            data.container_id[1] == 'i' &&
//            data.container_id[2] == 'b' &&
//            data.container_id[3] == 'p' &&
//            data.container_id[4] == 'o' &&
//            data.container_id[5] == 'd' &&
//            data.container_id[6] == '-')
//        {
//            offset = 7;
//        }
//    }
//
//    if (cb_bpf_probe_read_str(&data.container_id, CONTAINER_ID_LEN + 1, cgroup_dirname + offset) == CONTAINER_ID_LEN + 1)
//    {
//        send_event(ctx, &data, sizeof(data));
//    }
//
//    return 0;
//}

    // TODO: The collector is not currently handling the proxy event, so dont't bother sending it
    //        this needs to be reworked to send multiple events (similar to the file events)
    //int trace_tcp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg)
    //{
    //  struct dns_data data = {};
    //  int cmd = 0;
    //  int offset = 0;
    //
    //  // filter proxy traffic
    //  const char __user *p = (msg->msg_iter).iov->iov_base;
    //  __kernel_size_t cmd_len = (msg->msg_iter).iov->iov_len;
    //
    //  if ((p[0] == 'G') && (p[1] == 'E') && (p[2] == 'T') && (p[4] != '/')) {
    //      cmd = 0;
    //      offset = 3;
    //      goto CATCH;
    //  }
    //  if ((p[0] == 'P') && (p[1] == 'U') && (p[2] == 'T') && (p[4] != '/')) {
    //      cmd = 1;
    //      offset = 3;
    //      goto CATCH;
    //  }
    //  if ((p[0] == 'P') && (p[1] == 'O') && (p[2] == 'S') && (p[3] == 'T') &&
    //      (p[5] != '/')) {
    //      cmd = 2;
    //      offset = 4;
    //      goto CATCH;
    //  }
    //  if ((p[0] == 'D') && (p[1] == 'E') && (p[2] == 'L') && (p[3] == 'E') &&
    //      (p[4] == 'T') && (p[5] == 'E') && (p[7] != '/')) {
    //      cmd = 3;
    //      offset = 6;
    //      goto CATCH;
    //  }
    //  if ((p[0] == 'C') && (p[1] == 'O') && (p[2] == 'N') && (p[3] == 'N') &&
    //      (p[4] == 'E') && (p[5] == 'C') && (p[6] == 'T') && (p[8] != '/')) {
    //      cmd = 4;
    //      offset = 7;
    //      goto CATCH;
    //  }
    //  return 0;
    //
    //CATCH:
    //  __init_header(EVENT_NET_CONNECT_WEB_PROXY, PP_NO_EXTRA_DATA, &data.header);
    //
    //  data.name_len = cmd_len;
    //
    //  // TODO: calculate real url length
    //  int len = PROXY_SERVER_MAX_LEN;
    //
    //  data.ipver = sk->__sk_common.skc_family;
    //  bpf_probe_read(&data.local_port, sizeof(sk->__sk_common.skc_num),
    //             &sk->__sk_common.skc_num);
    //  data.local_port = htons(data.local_port);
    //  data.remote_port = sk->__sk_common.skc_dport;
    //
    //  if (check_family(sk, AF_INET)) {
    //      data.local_addr =
    //          sk->__sk_common.skc_rcv_saddr;
    //      data.remote_addr =
    //          sk->__sk_common.skc_daddr;
    //  } else if (check_family(sk, AF_INET6)) {
    //      bpf_probe_read(
    //          &data.local_addr6, sizeof(data.local_addr6),
    //          sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
    //      bpf_probe_read(&data.remote_addr6,
    //                 sizeof(data.remote_addr6),
    //                 sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
    //  }
    //
    //  p = p + offset + 1;
    //#pragma unroll
    //  for (int i = 1; i <= (PROXY_SERVER_MAX_LEN / DNS_SEGMENT_LEN) + 1;
    //       ++i) {
    //      if (len > 0 && len < DNS_RESP_MAXSIZE) {
    //          data.dns_flag = 0;
    //          bpf_probe_read(&data.dns, DNS_SEGMENT_LEN, p);
    //          if (i == 1)
    //              data.dns_flag = DNS_SEGMENT_FLAGS_START;
    //          if (len <= 40)
    //              data.dns_flag |= DNS_SEGMENT_FLAGS_END;
    //
    //          send_event(ctx, &data, sizeof(data));
    //          len = len - DNS_SEGMENT_LEN;
    //          p = p + DNS_SEGMENT_LEN;
    //      } else {
    //          break;
    //      }
    //  }
    //
    //  return 0;
    //}