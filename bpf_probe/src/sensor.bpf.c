/*
 * Copyright 2019-2021 VMware, Inc.
 * SPDX-License-Identifier: GPL-2.0
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include <linux/errno.h>

#include "missing.h"
#include "transport.h"

// TODO: Fix our kprobe syscall names so arm64 works too
// Field should not be needed to be defined once we start
// linking to newer libbpf like 1.0.0+
_Bool LINUX_HAS_SYSCALL_WRAPPER = 1;

char LICENSE[] SEC("license") = "GPL";

static const char ellipsis[] = "...";

extern int LINUX_KERNEL_VERSION __kconfig;

// Detect the presence of SUSE version that requires special handling of mmap flags
extern int CONFIG_SUSE_VERSION __kconfig __weak;

// Determine if running kernel has pid cgroup subsys
extern bool CONFIG_CGROUP_PIDS __kconfig __weak;

#define DNS_SEGMENT_FLAGS_START 0x01
#define DNS_SEGMENT_FLAGS_END 0x02

#define DNS_RESP_PORT_NUM 53
#define DNS_RESP_MAXSIZE 512
#define PROXY_SERVER_MAX_LEN 100

#define MAXARG 30

// Likely can be 64 but this a safer middle ground
#define MAX_FULL_PATH_ITER   40
// Can be much larger than MAX_FULL_PATH_ITER
#define MAX_DENTRY_PATH_ITER 32

#define MAX_PATH_EDGE_DETECT_ITER 2

struct file_data_cache {
    u64 pid;
    u64 device;
    u64 inode;
    // TODO: Store fs_magic
};

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

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

// Set to 1 when we want to change events map to be a ring buffer
volatile const unsigned int USE_RINGBUF = 0;

// This hash tracks the "observed" file-create events.  This will not be 100% accurate because we will report a
//  file create for any file the first time it is opened with WRITE|TRUNCATE (even if it already exists).  It
//  will however serve to de-dup some events.  (Ie.. If a program does frequent open/write/close.)
// TODO: On kernels with CONFIG_SECURITY_PATH support handle security_path_mknod
// for when files are really created before being opened.
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

// TODO: Scale to also be per proto
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

// TODO: Scale to be per family
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

// Declare scratchpad, might be better as a percpu array
// except that won't work on sleepable prog types.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct _file_event);
} xpad SEC(".maps");

#define DECLARE_FILE_EVENT(DATA) struct _file_event *DATA = __current_blob()
#define GENERIC_DATA(DATA)  (&((struct _file_event *)(DATA))->_data)
#define FILE_DATA(DATA)  (&((struct _file_event*)(DATA))->_file_data)
#define PATH_DATA(DATA)  (&((struct _file_event*)(DATA))->_path_data)
#define RENAME_DATA(DATA)  (&((struct _file_event*)(DATA))->_rename_data)

static struct _file_event empty_dummy = {};

static __always_inline void *__current_blob(void)
{
    u32 index = 0;

    // hack to hopefully reset the data to zero
    (void)bpf_map_update_elem(&xpad, &index, &empty_dummy, BPF_ANY);

    struct _file_event *event_data = bpf_map_lookup_elem(&xpad, &index);

    if (event_data)
    {
        // reset the static header data just in case
        __builtin_memset(event_data, 0, sizeof(event_data->_data.header));
    }

    return (void *)event_data;
}

static __always_inline void send_event(void *ctx, void *data, size_t data_size)
{
    // if (USE_RINGBUF)
    // {
    //     // TODO:
    //     //  Refactor to permit sending ringbuff flags
    //     //  instead of hardcoding BPF_RB_FORCE_WAKEUP.
    //     (void)bpf_ringbuf_output(&events, data, data_size, BPF_RB_FORCE_WAKEUP);
    // }
    // else
    // {
        // Only perf buffer instance should require the event timestamp
        ((struct data*)data)->header.event_time = bpf_ktime_get_ns();
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, data, data_size);
   // }
}

static __always_inline struct super_block *_sb_from_dentry(struct dentry *dentry)
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

static __always_inline struct super_block *_sb_from_file(struct file *file)
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

static __always_inline bool __is_special_filesystem(struct super_block *sb)
{
    if (!sb) {
        return false;
    }

    switch (BPF_CORE_READ(sb, s_magic)) {
    // Special Kernel File Systems
    case CGROUP_SUPER_MAGIC:
    case CGROUP2_SUPER_MAGIC:
    case SELINUX_MAGIC:
    case SMACK_MAGIC:
    case SYSFS_MAGIC:
    case PROC_SUPER_MAGIC:
    case SOCKFS_MAGIC:
    case DEVPTS_SUPER_MAGIC:
    case FUTEXFS_SUPER_MAGIC:
    case ANON_INODE_FS_MAGIC:
    case DEBUGFS_MAGIC:
    case TRACEFS_MAGIC:
    case BINDERFS_SUPER_MAGIC:
    case BPF_FS_MAGIC:
    case NSFS_MAGIC:
        return true;

    default:
        return false;
    }

    return false;
}

static __always_inline unsigned int __get_mnt_ns_id(struct task_struct *task)
{
    if (task && BPF_CORE_READ(task, nsproxy)) { // TODO: use bpf_core_field_exists()?
        return BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
    }
    return 0;
}

static __always_inline u32 __get_device_from_sb(struct super_block *sb)
{
    dev_t device = 0;
    if (sb) {
        bpf_core_read(&device, sizeof(device), &sb->s_dev);
    }
    return new_encode_dev(device);
}

static __always_inline u32 __get_device_from_dentry(struct dentry *dentry)
{
    return __get_device_from_sb(_sb_from_dentry(dentry));
}

static __always_inline u32 __get_device_from_file(struct file *file)
{
    return __get_device_from_sb(_sb_from_file(file));
}

static __always_inline u64 __get_inode_from_pinode(struct inode *pinode)
{
    u64 inode = 0;

    if (pinode) {
        bpf_core_read(&inode, sizeof(inode), &pinode->i_ino);
    }

    return inode;
}

static __always_inline umode_t __get_umode_from_inode(const struct inode *inode)
{
    umode_t umode = 0;

    if (inode) {
        bpf_probe_read(&umode, sizeof(umode), &inode->i_mode);
    }

    return umode;
}

static __always_inline u64 __get_inode_from_file(struct file *file)
{
    if (file) {
        struct inode *pinode = NULL;

        bpf_core_read(&pinode, sizeof(pinode), &(file->f_inode));
        return __get_inode_from_pinode(pinode);
    }

    return 0;
}

static __always_inline u64 __get_inode_from_dentry(struct dentry *dentry)
{
    if (dentry) {
        struct inode *pinode = NULL;

        bpf_core_read(&pinode, sizeof(pinode), &(dentry->d_inode));
        return __get_inode_from_pinode(pinode);
    }

    return 0;
}

static __always_inline bool __has_fmode_nonotify(const struct file *file)
{
    return !!(BPF_CORE_READ(file, f_flags) & FMODE_NONOTIFY) &&
           ((BPF_CORE_READ(file, f_flags) & O_ACCMODE) == O_RDONLY);
}


static __always_inline struct pid *select_task_pid(struct task_struct *task)
{
    struct pid *pid = NULL;

    // Not likely but just in case we have a strange older BTF enabled kernel
    // or use generated BTF info for something like RHEL8.0.
    if (bpf_core_type_exists(struct pid_link)) {
        struct task_struct___pdlink *task_pdlink = (typeof(task_pdlink))task;

        BPF_CORE_READ_INTO(&pid, task_pdlink, pids[PIDTYPE_PID].pid);
    } else {
        BPF_CORE_READ_INTO(&pid, task, thread_pid);
    }

    return pid;
}

//
// Currently provides the pid ns's id that also was used to obtain
// the thread group leader's value. Since we really don't care about
// a thread's virtual pid value aka if a thread is running in a
// different pid ns, we can ignore providing that information.
//
static __always_inline void set_pid_ns_data(struct data_header *hdr,
                                            struct task_struct *task)
{
    struct task_struct *group_leader = NULL;
    struct pid *pid = NULL;

    // Assumes group_leader is in the same pid_ns target task is in.
    BPF_CORE_READ_INTO(&group_leader, task, group_leader);
    pid = select_task_pid(group_leader);
    if (pid) {
        struct pid_namespace *pid_ns = NULL;
        unsigned int level = 0;

        BPF_CORE_READ_INTO(&level, pid, level);
        BPF_CORE_READ_INTO(&pid_ns, pid, numbers[level].ns);
        if (pid_ns) {
            BPF_CORE_READ_INTO(&hdr->pid_ns, pid_ns, ns.inum);
            BPF_CORE_READ_INTO(&hdr->pid_ns_vnr, pid, numbers[level].nr);
        }
    }
}

static __always_inline void __init_header_with_task(u8 type, u8 state, u16 report_flags,
                                                    struct data_header *header,
                                                    struct task_struct *task)
{
    header->type = type;
    header->state = state;
    header->report_flags = report_flags;
    header->payload = 0;

    if (task) {
        BPF_CORE_READ_INTO(&header->tid, task, pid);
        BPF_CORE_READ_INTO(&header->pid, task, tgid);
        BPF_CORE_READ_INTO(&header->uid, task, cred, uid.val);
        BPF_CORE_READ_INTO(&header->ppid, task, real_parent, tgid);
        header->mnt_ns = __get_mnt_ns_id(task);

        set_pid_ns_data(header, task);
    }
}

// Assumed current context is what is valid!
static __always_inline void __init_header(u8 type, u8 state, struct data_header *header)
{
    __init_header_with_task(type, state, REPORT_FLAGS_COMPAT, header,
                            (struct task_struct *)bpf_get_current_task());
}

static __always_inline void __init_header_dynamic(u8 type, u8 state, struct data_header *header)
{
    __init_header_with_task(type, state, REPORT_FLAGS_DYNAMIC, header,
                            (struct task_struct *)bpf_get_current_task());
}


static __always_inline
struct kernfs_node *find_cgroup_node(const struct task_struct *task)
{
    enum cgroup_subsys_id___local {
        pids_cgrp_id___local = 123,
    };
    int cgrp_id = 0;
    struct css_set *css_set = NULL;
    struct kernfs_node *cgroup_node = NULL;

    // Eventually add option to control how we get the cgroup path.

    // Preload the task's rcu protected struct css_set
    BPF_CORE_READ_INTO(&css_set, task, cgroups);
    if (!css_set) {
        return NULL;
    }

    // pids_cgrp_id value can vary between kernels
    if (CONFIG_CGROUP_PIDS) {
        // Ask target kernel what the value is for cgroup_subsys_id.pids_cgroup_id
        cgrp_id = bpf_core_enum_value(enum cgroup_subsys_id___local,
                                          pids_cgrp_id___local);
        // Adjust pids_cgrp_id range before read
        if (cgrp_id < 0 || cgrp_id >= CGROUP_SUBSYS_COUNT) {
            cgrp_id = 0;
        }
    }
    // If we have issues with this index selection approach we still
    // have other options to make this more reliable.
    BPF_CORE_READ_INTO(&cgroup_node, css_set,
                       subsys[cgrp_id], cgroup, kn);

    // The default cgroup kernfs node
    if (!cgroup_node) {
        BPF_CORE_READ_INTO(&cgroup_node, css_set, dfl_cgrp, kn);
    }

    return cgroup_node;
}


// Be careful with making changes to this function!
// Can only read in 255 chunks at time, if the current arg pointer's
// offset is incremented via a non-u8 variable, the verifier
// goes bananas.
//
// Blobifies exec arguments and appends long arguments as well
//
static size_t __blobify_str_array(const char *const *argv, char *blob)
{
    // Some smarter verifiers allows us to write into a map
    // with a signed integer to track the offset of the next write.
#if MAX_ARG_CHUNK_SIZE > MAX_UCHAR_VAL
    long len;
#else
    u8 len;
#endif
    size_t total_blob_len = 0;
    char *argp = NULL;
    unsigned index = 0;

    if (bpf_probe_read(&argp, sizeof(argp), &argv[index++]) || !argp)
    {
        goto out;
    }

#pragma unroll
    for (int i = 0; i < MAXARG; i++)
    {
        len = bpf_probe_read_str(blob, MAX_ARG_CHUNK_SIZE, argp);

        // barrier_var here actually saves an extra insn per iteration
        barrier_var(len);
#if MAX_ARG_CHUNK_SIZE > MAX_UCHAR_VAL
        if (len < 0)
        {
            goto out;
        }
#endif
        if (len == MAX_ARG_CHUNK_SIZE)
        {
            len -= 1;
            blob += len;
            total_blob_len += len;

            // The instruction most sensitive/critical to BPF verifier
            argp = argp + MAX_ARG_CHUNK_SIZE - 1;
        }
        else
        {
            blob += len;
            total_blob_len += len;

            if (bpf_probe_read(&argp, sizeof(argp), &argv[index++]) ||
                !argp)
            {
                goto out;
            }
        }
    }

    bpf_probe_read(blob, sizeof(ellipsis), ellipsis);
    total_blob_len += sizeof(ellipsis);

out:

    return total_blob_len;
}

//
// When blob entry has data, set the size and offset
// of the blob entry/ctx. Then updates the global payload size
// and global position in the blob space.
//
// blob_pos is and address within the xpad BPF map. So max
// hard max size is not based on the size of the event structs
// but the max size of the xpad map entry. The verifier will
// tell us if we ever are close to hitting an map address overflow.
// This may happen if some of the operations with iterating
// changes or we use the incorrect type to manage position
// within the xpad BPF map entry storage space.
//
static __always_inline
char *compute_blob_ctx(u16 blob_size, struct blob_ctx *blob_ctx,
                       u32 *payload, char *blob_pos)
{
    if (blob_ctx && payload) {
        blob_ctx->size = blob_size;
        if (blob_size) {
            blob_ctx->offset = (u16)*payload;
        } else {
            blob_ctx->offset = 0;
        }
        *payload += blob_size;

        if (blob_pos) {
            return blob_pos + blob_size;
        }
    }
    return blob_pos;
}

/* Will add the cgroup path on the blob in reversed order.
   Should be arranged in the userspace */
static size_t __blobify_cgroup_path(struct task_struct *task, char *blob)
{
    struct kernfs_node *cgroup_node = NULL;
    size_t total_len = 0;
    size_t length = 0;

    if (!task) {
        return 0;
    }

    cgroup_node = find_cgroup_node(task);
    if (!cgroup_node) {
        return 0;
    }

#pragma clang loop unroll(full)
    for (int i = 0; i < MAX_CGROUP_PATH_ITER; i++) {
        length = bpf_probe_read_str(blob, MAX_PATH_COMPONENT_SIZE, BPF_CORE_READ(cgroup_node, name));
        barrier_var(length);
        if (length > MAX_PATH_COMPONENT_SIZE) {
            goto out;
        }
        barrier_var(length);
        total_len += length;
        blob += length;

        BPF_CORE_READ_INTO(&cgroup_node, cgroup_node, parent);
        if (!cgroup_node) {
            goto out;
        }
    }

out:
    return total_len;
}

// Helper to __blobify_cgroup_path
#define blobify_cgroup_path(blob) \
    __blobify_cgroup_path((struct task_struct *)bpf_get_current_task(), blob)


static __always_inline int __get_next_parent_dentry(struct dentry **dentry,
                                                    struct vfsmount **vfsmnt,
                                                    struct mount **real_mount,
                                                    struct dentry **mnt_root,
                                                    struct dentry **parent_dentry)
{
    int retVal = 0;
    struct mount *mnt_parent = NULL;

    bpf_core_read(parent_dentry, sizeof(struct dentry *), &(*dentry)->d_parent);

    if (*dentry == *mnt_root || *dentry == *parent_dentry) {
        bpf_core_read(&mnt_parent, sizeof(struct mount *), &(*real_mount)->mnt_parent);
        if (*dentry != *mnt_root) {
            // We reached root, but not mount root - escaped?
            retVal = ENOENT;
        } else if (*real_mount != mnt_parent) {
            // We reached root, but not global root - continue with mount point path
            bpf_core_read(dentry, sizeof(struct dentry *), &(*real_mount)->mnt_mountpoint);
            bpf_core_read(real_mount, sizeof(struct mount *), &(*real_mount)->mnt_parent);
            *vfsmnt = &(*real_mount)->mnt;
            bpf_core_read(mnt_root, sizeof(struct dentry *), &(*vfsmnt)->mnt_root);
            retVal = EAGAIN;
        } else {
            // Global root - path fully parsed
            retVal = ENOENT;
        }
    }

    return retVal;
}


static size_t __do_file_path_x(struct dentry *dentry,
                            struct vfsmount *vfsmnt,
                            char *blob)
{
    size_t total_blob_len = 0;
    size_t len;
    struct mount *real_mount = NULL;
    struct dentry *mnt_root = NULL;
    struct dentry *parent_dentry = NULL;
    int i = 0;

    bpf_core_read(&mnt_root, sizeof(struct dentry *), &vfsmnt->mnt_root);

    // poorman's container_of
    real_mount = ((void *)vfsmnt) - offsetof(struct mount, mnt);

#pragma clang loop unroll(full)
    for (i = 0; i < MAX_FULL_PATH_ITER; ++i) {
        // Helper overhead adds ~250 extra insns
        int retVal = __get_next_parent_dentry(&dentry, &vfsmnt, &real_mount,
                                              &mnt_root, &parent_dentry);

        if (retVal == EAGAIN) {
            continue;
        }

        if (retVal == ENOENT) {
            goto out;
        }

        len = bpf_probe_read_str(blob, MAX_PATH_COMPONENT_SIZE,
                                 BPF_CORE_READ(dentry, d_name.name));
        barrier_var(len);
        if (len > MAX_PATH_COMPONENT_SIZE) {
            goto out;
        }
        barrier_var(len);
        blob += len;
        total_blob_len += len;

        dentry = parent_dentry;
    }

    // Fall through here to check if we likely truncated

    // Best effort to check if path was fully parsed in the last loop iteration.
    // Could still yield a false result because without unbounded looping we can't know
    // beyond all doubts that we have reached the global root mount.
    // We don't add ellipsis if we can't be sure the path is truncated.
#pragma clang loop unroll(full)
    for (i = 0; i < MAX_PATH_EDGE_DETECT_ITER; ++i) {
        int retVal = __get_next_parent_dentry(&dentry, &vfsmnt, &real_mount,
                                              &mnt_root, &parent_dentry);

        // We crossed a mountpoint so we likely truncated
        if (retVal == EAGAIN) {
            continue;
            // Probably could be okay with breaking from loop here
        }

        if (retVal == ENOENT) {
            goto out;
        }

        // The path is truncated for sure!
        break;
    }

    bpf_probe_read(blob, sizeof(ellipsis), ellipsis);
    total_blob_len += sizeof(ellipsis);

out:

    return total_blob_len;
}


static size_t __do_dentry_path_x(struct dentry *dentry, char *blob)
{
    size_t total_blob_len = 0;
    size_t len;
    struct dentry *parent_dentry = NULL;

#pragma unroll
    for (int i = 0; i < MAX_DENTRY_PATH_ITER; i++)
    {
        bpf_core_read(&parent_dentry, sizeof(parent_dentry), &(dentry->d_parent));

        if (parent_dentry == dentry || parent_dentry == NULL) {
            goto out;
        }

        len = bpf_probe_read_str(blob, MAX_PATH_COMPONENT_SIZE,
                                 BPF_CORE_READ(dentry, d_name.name));
        barrier_var(len);
        if (len > MAX_PATH_COMPONENT_SIZE) {
            goto out;
        }
        barrier_var(len);
        blob += len;
        total_blob_len += len;

        dentry = parent_dentry;
    }

    // A dentry path's truncation should be considered
    // undefined behavior so don't too much worry about it.
    bpf_core_read(&parent_dentry, sizeof(parent_dentry), &(dentry->d_parent));
    if (parent_dentry != dentry)
    {
        bpf_probe_read(blob, sizeof(ellipsis), ellipsis);
        total_blob_len += sizeof(ellipsis);
    }

out:

    return total_blob_len;
}

static void submit_exec_arg_event(void *ctx, const char __user *const __user *argv)
{
    struct exec_arg_data *exec_arg_data = __current_blob();
    u32 payload = offsetof(typeof(*exec_arg_data), blob);
    char *blob_pos = NULL;
    u16 blob_size;

    if (!argv || !exec_arg_data) {
        return;
    }

    barrier_var(blob_pos);
    blob_pos = (char *)exec_arg_data->blob;
    barrier_var(blob_size);
    __init_header_dynamic(EVENT_PROCESS_EXEC_ARG, PP_ENTRY_POINT, &exec_arg_data->header);

    blob_size = __blobify_str_array(argv, blob_pos);
    blob_pos = compute_blob_ctx(blob_size, &exec_arg_data->exec_arg_blob,
            &payload, blob_pos);
    blob_size = blobify_cgroup_path(blob_pos);
    blob_pos = compute_blob_ctx(blob_size, &exec_arg_data->cgroup_blob, &payload, blob_pos);

    barrier_var(payload);
    exec_arg_data->header.payload = payload;

    barrier_var(payload);
    if (payload <= MAX_BLOB_EVENT_SIZE) {
        send_event(ctx, exec_arg_data, payload);
    }
}

// Tracepoint of exec entry
SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter* ctx)
{
    // ctx is trace_event struct
    // /sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/format
    const char **argv = (const char **)(ctx->args[1]);
    submit_exec_arg_event(ctx, argv);
    return 0;
}

// Tracepoint of exec exit
SEC("tracepoint/syscalls/sys_exit_execve")
int tracepoint__syscalls__sys_exit_execve(struct trace_event_raw_sys_exit* ctx)
{
    struct exec_data data = {};

    __init_header(EVENT_PROCESS_EXEC_RESULT, PP_NO_EXTRA_DATA, &data.header);
    data.retval = ctx->ret;

    send_event(ctx, &data, sizeof(struct exec_data));

    return 0;
}

// Tracepoint of execveat entry
SEC("tracepoint/syscalls/sys_enter_execveat")
int tracepoint__syscalls__sys_enter_execveat(struct trace_event_raw_sys_enter* ctx)
{
    // ctx is trace_event struct
    // /sys/kernel/debug/tracing/events/syscalls/sys_enter_execveat/format
    const char **argv = (const char **)(ctx->args[2]);
    submit_exec_arg_event(ctx, argv);
    return 0;
}

// Tracepoint of execveat exit
SEC("tracepoint/syscalls/sys_exit_execveat")
int tracepoint__syscalls__sys_exit_execveat(struct trace_event_raw_sys_exit* ctx)
{
    struct exec_data data = {};

    __init_header(EVENT_PROCESS_EXEC_RESULT, PP_NO_EXTRA_DATA, &data.header);
    data.retval = ctx->ret;

    send_event(ctx, &data, sizeof(struct exec_data));

    return 0;
}


static __always_inline void __file_tracking_delete(u64 pid, u64 device, u64 inode)
{
    struct file_data_cache key = { .device = device, .inode = inode };
    bpf_map_delete_elem(&file_map, &key);
}

static __always_inline void __track_write_entry(
    struct file      *file,
    struct file_path_data_x *data)
{
    if (!file || !data) {
        return;
    }

    u64 file_cache_key = (u64)file;

    void *cachep = bpf_map_lookup_elem(&file_write_cache, &file_cache_key);
    if (cachep) {
        struct file_data_cache cache_data = *((struct file_data_cache *) cachep);
        pid_t pid = cache_data.pid;
        cache_data.pid = data->header.pid;
        // if we really care about that multiple tasks
        // these are likely threads or less likely inherited from a fork
        if (pid == data->header.pid) {
            return;
        }

        bpf_map_update_elem(&file_write_cache, &file_cache_key, &cache_data, BPF_ANY);
    } else {
        struct file_data_cache cache_data = {
                .pid = data->header.pid,
                .device = data->device,
                .inode = data->inode
        };
        bpf_map_update_elem(&file_write_cache, &file_cache_key, &cache_data, BPF_NOEXIST);
    }
}

// Only need this hook for kernels without lru_hash
SEC("kprobe/security_file_free")
int BPF_KPROBE(on_security_file_free, struct file *file)
{
    u64 file_cache_key = (u64)file;
    struct file_data_cache *cachep;

    struct file_path_data_x *data_x = NULL;
    uint32_t payload = offsetof(typeof(*data_x), blob);
    char *blob_pos = NULL;
    u16 blob_size;

    if (!file || __has_fmode_nonotify(file)) {
        goto out;
    }

    cachep = bpf_map_lookup_elem(&file_write_cache, &file_cache_key);
    if (!cachep) {
        goto out_del;
    }

    data_x = __current_blob();
    if (!data_x) {
        goto out_del;
    }

    blob_pos = data_x->blob;
    __init_header_dynamic(EVENT_FILE_CLOSE, PP_ENTRY_POINT, &data_x->header);

    data_x->device = cachep->device;
    data_x->inode = cachep->inode;
    data_x->flags = BPF_CORE_READ(file, f_flags);
    data_x->prot = BPF_CORE_READ(file, f_mode);

    blob_size = __do_file_path_x(BPF_CORE_READ(file, f_path.dentry),
                                 BPF_CORE_READ(file, f_path.mnt),
                                 blob_pos);
    blob_pos = compute_blob_ctx(blob_size, &data_x->file_blob,
                                &payload, blob_pos);
    blob_size = blobify_cgroup_path(blob_pos);
    blob_pos = compute_blob_ctx(blob_size, &data_x->cgroup_blob, &payload, blob_pos);

    data_x->header.payload = payload;
    if (payload <= MAX_BLOB_EVENT_SIZE) {
        send_event(ctx, data_x, payload);
    }

out_del:
    bpf_map_delete_elem(&file_write_cache, &file_cache_key);

out:

    return 0;
}

SEC("kprobe/security_mmap_file")
int BPF_KPROBE(on_security_mmap_file, struct file *file, unsigned long prot, unsigned long flags)
{
    unsigned long exec_flags;
    unsigned long file_flags;

    struct file_path_data_x *data_x = NULL;
    uint32_t payload = offsetof(typeof(*data_x), blob);
    char *blob_pos = NULL;
    u16 blob_size;

    if (!file) {
        goto out;
    }
    if (!(prot & PROT_EXEC)) {
        goto out;
    }

    if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(5, 14, 0) && (CONFIG_SUSE_VERSION != 15))
    {
        // This fix is to adjust the flag changes in 5.14 kernel (except SUSE 15 SP4) to match the user space pipeline requirement
        //  - MAP_EXECUTABLE flag is not available for exec mmap function
        //  - MAP_DENYWRITE flag is "reverted" for ld.so and normal mmap
        //  - checking CONFIG_SUSE_VERSION is a temporary fix until SUSE stops using flag MAP_EXECUTABLE

        BPF_CORE_READ_INTO(&file_flags, file, f_flags);
        if ((file_flags & FMODE_EXEC) && flags == (MAP_FIXED | MAP_PRIVATE)) {
            goto out;
        }

        if (flags & MAP_DENYWRITE) {
            flags &= ~MAP_DENYWRITE;
        } else {
            flags |= MAP_DENYWRITE;
        }
    }
    else
    {
        exec_flags = flags & (MAP_DENYWRITE | MAP_EXECUTABLE);
        if (exec_flags == (MAP_DENYWRITE | MAP_EXECUTABLE)) {
            goto out;
        }
    }

    data_x = __current_blob();
    if (!data_x) {
        goto out;
    }

    blob_pos = data_x->blob;
    __init_header_dynamic(EVENT_FILE_MMAP, PP_ENTRY_POINT, &data_x->header);

    // event specific data
    data_x->device = __get_device_from_file(file);
    data_x->inode = __get_inode_from_file(file);
    data_x->flags = flags;
    data_x->prot = prot;

    // submit file path event data
    blob_size = __do_file_path_x(BPF_CORE_READ(file, f_path.dentry),
                                 BPF_CORE_READ(file, f_path.mnt),
                                 blob_pos);
    if (!blob_size) {
        goto out;
    }
    blob_pos = compute_blob_ctx(blob_size, &data_x->file_blob,
                                &payload, blob_pos);
    blob_size = blobify_cgroup_path(blob_pos);
    blob_pos = compute_blob_ctx(blob_size, &data_x->cgroup_blob, &payload, blob_pos);

    data_x->header.payload = payload;
    if (payload <= MAX_BLOB_EVENT_SIZE) {
        send_event(ctx, data_x, payload);
    }

out:

    return 0;
}

// This hook may not be very accurate but at least tells us the intent
// to create the file if needed. So this will likely be written to next.
SEC("kprobe/security_file_open")
int BPF_KPROBE(on_security_file_open, struct file *file)
{
    struct super_block *sb = NULL;
    struct inode *inode = NULL;
    umode_t umode;
    unsigned long f_flags = 0;
    fmode_t f_mode = 0;

    struct file_path_data_x *data_x = NULL;
    uint32_t payload = offsetof(typeof(*data_x), blob);
    char *blob_pos = NULL;
    u16 blob_size;

    if (!file || __has_fmode_nonotify(file)) {
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

    umode = __get_umode_from_inode(inode);
    if (!S_ISREG(umode)) {
        goto out;
    }

    // Indirect store in case f_flags is ever expanded
    f_flags = BPF_CORE_READ(file, f_flags);
    BPF_CORE_READ_INTO(&f_mode, file, f_mode);

    u8 type;
    if (f_flags & FMODE_EXEC) {
        type = EVENT_PROCESS_EXEC_PATH;
    } else if (f_mode & FMODE_CREATED) {
        // create intent may be grabbed sooner via security_path_mknod
        // with CONFIG_SECURITY_PATH enabled.
        type = EVENT_FILE_CREATE;
    } else if (f_flags & O_ACCMODE){
        type = EVENT_FILE_WRITE;
    } else {
        type = EVENT_FILE_READ;
    }

    data_x = __current_blob();
    if (!data_x) goto out;

    blob_pos = data_x->blob;
    __init_header_dynamic(type, PP_ENTRY_POINT, &data_x->header);

    data_x->device = __get_device_from_file(file);
    data_x->inode = __get_inode_from_file(file);
    data_x->flags = BPF_CORE_READ(file, f_flags);
    data_x->prot = BPF_CORE_READ(file, f_mode);
    data_x->fs_magic = BPF_CORE_READ(sb, s_magic);

    if (type == EVENT_FILE_WRITE || type == EVENT_FILE_CREATE)
    {
        // This allows us to send the last-write event on file close
        __track_write_entry(file, data_x);
    }

    blob_size = __do_file_path_x(BPF_CORE_READ(file, f_path.dentry),
                                 BPF_CORE_READ(file, f_path.mnt),
                                 blob_pos);
    if (!blob_size) {
        goto out;
    }
    blob_pos = compute_blob_ctx(blob_size, &data_x->file_blob,
                                &payload, blob_pos);
    blob_size = blobify_cgroup_path(blob_pos);
    blob_pos = compute_blob_ctx(blob_size, &data_x->cgroup_blob, &payload, blob_pos);

    data_x->header.payload = payload;
    if (payload <= MAX_BLOB_EVENT_SIZE) {
        send_event(ctx, data_x, payload);
    }

out:

    return 0;
}

SEC("kprobe/security_inode_unlink")
int BPF_KPROBE(on_security_inode_unlink, struct inode *dir, struct dentry *dentry)
{
    struct super_block *sb = NULL;

    struct file_path_data_x *data_x = NULL;
    uint32_t payload = offsetof(typeof(*data_x), blob);
    char *blob_pos = NULL;
    u16 blob_size;

    sb = _sb_from_dentry(dentry);
    if (!sb || __is_special_filesystem(sb)) {
        return 0;
    }

    data_x = __current_blob();
    if (!data_x) {
        return 0;
    }

    blob_pos = data_x->blob;
    __init_header_dynamic(EVENT_FILE_DELETE, PP_ENTRY_POINT, &data_x->header);
    data_x->header.report_flags |= REPORT_FLAGS_DENTRY;

    data_x->device = __get_device_from_sb(sb);
    data_x->inode = __get_inode_from_dentry(dentry);
    data_x->fs_magic = BPF_CORE_READ(sb, s_magic);

    __file_tracking_delete(0, data_x->device, data_x->inode);

    blob_size = __do_dentry_path_x(dentry, blob_pos);
    blob_pos = compute_blob_ctx(blob_size, &data_x->file_blob,
                                &payload, blob_pos);
    blob_size = blobify_cgroup_path(blob_pos);
    blob_pos = compute_blob_ctx(blob_size, &data_x->cgroup_blob, &payload, blob_pos);

    data_x->header.payload = payload;
    if (payload <= MAX_BLOB_EVENT_SIZE) {
        send_event(ctx, data_x, payload);
    }

    return 0;
}

SEC("kprobe/security_inode_rename")
int BPF_KPROBE(on_security_inode_rename, struct inode *old_dir,
             struct dentry *old_dentry, struct inode *new_dir,
             struct dentry *new_dentry, unsigned int flags)
{
    struct super_block *sb = NULL;

    struct rename_data_x *data_x = NULL;
    uint32_t payload = offsetof(typeof(*data_x), blob);
    char *blob_pos = NULL;
    u16 blob_size;

    sb = _sb_from_dentry(old_dentry);
    if (!sb || __is_special_filesystem(sb)) {
        goto out;
    }

    data_x = __current_blob();
    if (!data_x) {
        goto out;
    }

    blob_pos = data_x->blob;
    __init_header_dynamic(EVENT_FILE_RENAME, PP_ENTRY_POINT, &data_x->header);
    data_x->header.report_flags |= REPORT_FLAGS_DENTRY;

    data_x->device = __get_device_from_dentry(old_dentry);
    data_x->old_inode = __get_inode_from_dentry(old_dentry);
    data_x->fs_magic = sb ? BPF_CORE_READ(sb, s_magic) : 0;

    __file_tracking_delete(0, data_x->device, data_x->old_inode);

    // If the target destination already exists
    if (new_dentry) {
        __file_tracking_delete(0, data_x->device, data_x->new_inode);

        data_x->new_inode = __get_inode_from_dentry(new_dentry);
    } else {
        data_x->new_inode = 0;
    }

    blob_size = __do_dentry_path_x(old_dentry, blob_pos);
    blob_pos = compute_blob_ctx(blob_size, &data_x->old_blob,
                                &payload, blob_pos);

    blob_size = __do_dentry_path_x(new_dentry, blob_pos);
    blob_pos = compute_blob_ctx(blob_size, &data_x->new_blob,
                                &payload, blob_pos);
    blob_size = blobify_cgroup_path(blob_pos);
    blob_pos = compute_blob_ctx(blob_size, &data_x->cgroup_blob, &payload, blob_pos);

    data_x->header.payload = payload;
    if (payload <= MAX_BLOB_EVENT_SIZE) {
        send_event(ctx, data_x, payload);
    }

out:

    return 0;
}

SEC("kprobe/wake_up_new_task")
int BPF_KPROBE(on_wake_up_new_task, struct task_struct *task)
{
    struct file_path_data_x *data_x = __current_blob();
    if (!data_x) {
        goto out;
    }
    uint32_t payload = offsetof(typeof(*data_x), blob);
    u16 blob_size;
    char *blob_pos = data_x->blob;
    if (!task) {
        goto out;
    }

    if (BPF_CORE_READ(task, tgid) != BPF_CORE_READ(task, pid)) {
        goto out;
    }

    __init_header_with_task(EVENT_PROCESS_CLONE, PP_NO_EXTRA_DATA,
                            REPORT_FLAGS_DYNAMIC, &data_x->header, task);

    data_x->header.uid = BPF_CORE_READ(task, real_parent, cred, uid.val);
    if (!(BPF_CORE_READ(task, flags) & PF_KTHREAD) && BPF_CORE_READ(task,mm) && BPF_CORE_READ(task, mm, exe_file)) {
        data_x->device = __get_device_from_file(BPF_CORE_READ(task, mm, exe_file));
        data_x->inode = __get_inode_from_file(BPF_CORE_READ(task, mm, exe_file));
    }

    blob_size = __blobify_cgroup_path(task, blob_pos);
    blob_pos = compute_blob_ctx(blob_size, &data_x->cgroup_blob, &payload, blob_pos);

    data_x->header.payload = payload;
    if (payload <= MAX_BLOB_EVENT_SIZE) {
        send_event(ctx, data_x, payload);
    }

out:
    return 0;
}

static __always_inline bool has_ip_cache(struct ip_key *ip_key, u8 flow)
{
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
    return false;
}

static __always_inline bool has_ip6_cache(struct ip6_key *ip6_key, u8 flow)
{
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
    return false;
}

SEC("kprobe/do_exit")
int BPF_KPROBE(on_do_exit, long code)
{
    struct data_x *data_x = NULL;
    char *blob_pos = NULL;
    uint32_t payload = offsetof(typeof(*data_x), blob);
    size_t blob_size;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) {
        goto out;
    }

    if (BPF_CORE_READ(task, tgid) != BPF_CORE_READ(task, pid)) {
        goto out;
    }

    data_x = __current_blob();
    if (!data_x) {
        goto out;
    }
    blob_pos = data_x->blob;

    __init_header_dynamic(EVENT_PROCESS_EXIT, PP_NO_EXTRA_DATA, &data_x->header);
    blob_size = blobify_cgroup_path(blob_pos);
    blob_pos = compute_blob_ctx(blob_size, &data_x->cgroup_blob, &payload, blob_pos);
    data_x->header.payload = payload;

    if (payload <= MAX_BLOB_EVENT_SIZE) {
        send_event(ctx, data_x, payload);
    }

out:
    return 0;
}


static __always_inline int trace_connect_entry(struct sock *sk)
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

static __always_inline bool check_family(struct sock *sk, u16 expected_family)
{
    u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    return family == expected_family;
}

static __always_inline int trace_connect_return(struct pt_regs *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    struct net_data_x *data = __current_blob();
    uint32_t payload = offsetof(typeof(*data), blob);
    char *blob_pos = NULL;
    size_t blob_size;

    if (!data) {
        return 0;
    }

    int ret = PT_REGS_RC_CORE(ctx);
    if (ret != 0) {
        bpf_map_delete_elem(&currsock, &id);
        return 0;
    }

    struct sock **skpp;
    skpp = bpf_map_lookup_elem(&currsock, &id);
    if (skpp == 0) {
        return 0;
    }

    struct sock *skp = *skpp;
    u16 dport = BPF_CORE_READ(skp, __sk_common.skc_dport);

    __init_header_dynamic(EVENT_NET_CONNECT_PRE, PP_NO_EXTRA_DATA, &data->net_data.header);
    data->net_data.protocol = IPPROTO_TCP;
    data->net_data.remote_port = dport;

    struct inet_sock *sockp = (struct inet_sock *)skp;
    data->net_data.local_port = BPF_CORE_READ(sockp, inet_sport);

    if (check_family(skp, AF_INET)) {
        data->net_data.ipver = AF_INET;
        data->net_data.local_addr = BPF_CORE_READ(skp, __sk_common.skc_rcv_saddr);
        data->net_data.remote_addr = BPF_CORE_READ(skp, __sk_common.skc_daddr);

    } else if (check_family(skp, AF_INET6)) {
        data->net_data.ipver = AF_INET6;
        bpf_probe_read(&data->net_data.local_addr6, sizeof(data->net_data.local_addr6),
            BPF_CORE_READ(skp, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32));
        bpf_probe_read(&data->net_data.remote_addr6, sizeof(data->net_data.remote_addr6),
            BPF_CORE_READ(skp, __sk_common.skc_v6_daddr.in6_u.u6_addr32));
    }

    blob_pos = data->blob;
    blob_size = blobify_cgroup_path(blob_pos);
    blob_pos = compute_blob_ctx(blob_size, &data->cgroup_blob, &payload, blob_pos);
    data->net_data.header.payload = payload;

    if (payload <= MAX_BLOB_EVENT_SIZE) {
        send_event(ctx, data, payload);
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
    struct net_data_x *data = __current_blob();
    uint32_t payload = offsetof(typeof(*data), blob);
    char *blob_pos = NULL;
    size_t blob_size;

    struct sk_buff *skb = (struct sk_buff *)PT_REGS_RC_CORE(ctx);
    if (skb == NULL) {
        return 0;
    }

    if (!data) {
        return 0;
    }

    struct udphdr *udphdr = NULL;

    // Get a pointer to the network header and the header length.
    //  We use the header length to decide if this is IPv4 or IPv6
    void *hdr = (struct iphdr *)(BPF_CORE_READ(skb, head) + BPF_CORE_READ(skb, network_header));
    u32 hdr_len = BPF_CORE_READ(skb, transport_header) - BPF_CORE_READ(skb, network_header);

    __init_header_dynamic(EVENT_NET_CONNECT_ACCEPT, PP_NO_EXTRA_DATA, &data->net_data.header);
    blob_pos = data->blob;

    data->net_data.protocol = IPPROTO_UDP;

    udphdr = (struct udphdr *)(BPF_CORE_READ(skb, head) + BPF_CORE_READ(skb, transport_header));
    data->net_data.remote_port = BPF_CORE_READ(udphdr, source);
    data->net_data.local_port = BPF_CORE_READ(udphdr, dest);

    if (hdr_len == sizeof(struct iphdr)) {
        struct iphdr *iphdr = (struct iphdr *)hdr;

        data->net_data.ipver = AF_INET;
        data->net_data.local_addr = BPF_CORE_READ(iphdr, daddr);
        data->net_data.remote_addr = BPF_CORE_READ(iphdr, saddr);

        struct ip_key ip_key = {};
        ip_key.pid = data->net_data.header.pid;
        bpf_probe_read(&ip_key.remote_port, sizeof(data->net_data.remote_port),
                   &data->net_data.remote_port);
        bpf_probe_read(&ip_key.local_port, sizeof(data->net_data.local_port),
                   &data->net_data.local_port);
        bpf_probe_read(&ip_key.remote_addr,
                   sizeof(data->net_data.remote_addr),
                   &data->net_data.remote_addr);
        bpf_probe_read(&ip_key.local_addr, sizeof(data->net_data.local_addr),
                   &data->net_data.local_addr);
        if (has_ip_cache(&ip_key, FLOW_RX)) {
            return 0;
        }
    } else if (hdr_len == sizeof(struct ipv6hdr)) {
        // Why IPv6 address/port is read in a different way than IPv4:
        //  - BPF C compiled to BPF instructions don't always do what we expect
        //  - especially when accessing members of a struct containing bitfields
        struct ipv6hdr *ipv6hdr = (struct ipv6hdr *)hdr;

        data->net_data.ipver = AF_INET6;
        bpf_core_read(data->net_data.local_addr6, sizeof(uint32_t) * 4,
                   &ipv6hdr->daddr.s6_addr32);
        bpf_core_read(data->net_data.remote_addr6, sizeof(uint32_t) * 4,
                   &ipv6hdr->saddr.s6_addr32);

        struct ip6_key ip_key = {};
        ip_key.pid = data->net_data.header.pid;
        bpf_probe_read(&ip_key.remote_port, sizeof(data->net_data.remote_port),
                   &data->net_data.remote_port);
        bpf_probe_read(&ip_key.local_port, sizeof(data->net_data.local_port),
                   &data->net_data.local_port);
        bpf_core_read(ip_key.remote_addr6,
                   sizeof(data->net_data.remote_addr6),
                   &ipv6hdr->daddr.s6_addr32);
        bpf_core_read(ip_key.local_addr6, sizeof(data->net_data.local_addr6),
                   &ipv6hdr->saddr.s6_addr32);
        if (has_ip6_cache(&ip_key, FLOW_RX)) {
            return 0;
        }
    } else {
        return 0;
    }

    blob_size = blobify_cgroup_path(blob_pos);
    blob_pos = compute_blob_ctx(blob_size, &data->cgroup_blob, &payload, blob_pos);
    data->net_data.header.payload = payload;

    if (payload <= MAX_BLOB_EVENT_SIZE) {
        send_event(ctx, data, payload);
    }


    return 0;
}

// check for system endianess
#ifdef __BYTE_ORDER__
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define _is_big_endian() false
#else
#define _is_big_endian() true
#endif
#else
static __always_inline bool _is_big_endian()
{
    unsigned int x = 1;
    char *c = (char*) &x;
    return ((int)*c == 0);
}
#endif /* __BYTE_ORDER__ */

static __always_inline uint16_t _htons(uint16_t hostshort)
{
    if (_is_big_endian()) {
        return hostshort;
    } else {
        return __builtin_bswap16(hostshort);
    }
}

static __always_inline uint16_t _ntohs(uint16_t netshort)
{
    if (_is_big_endian()) {
        return netshort;
    } else {
        return __builtin_bswap16(netshort);
    }
}

SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(trace_accept_return)
{
    struct net_data_x *data = __current_blob();
    uint32_t payload = offsetof(typeof(*data), blob);
    char *blob_pos = NULL;
    size_t blob_size;

    struct sock *newsk = (struct sock *)PT_REGS_RC_CORE(ctx);
    if (newsk == NULL) {
        return 0;
    }

    if (!data) {
        return 0;
    }

    __init_header_dynamic(EVENT_NET_CONNECT_ACCEPT, PP_NO_EXTRA_DATA, &data->net_data.header);
    blob_pos = data->blob;

    data->net_data.protocol = IPPROTO_TCP;

    data->net_data.ipver = BPF_CORE_READ(newsk,__sk_common.skc_family);
    __u16 snum = BPF_CORE_READ(newsk, __sk_common.skc_num);
    bpf_core_read(&data->net_data.local_port, sizeof(snum), &snum);
    data->net_data.local_port = _htons(data->net_data.local_port);
    data->net_data.remote_port = BPF_CORE_READ(newsk, __sk_common.skc_dport); // network order dport
    if (data->net_data.local_port == 0 || data->net_data.remote_port == 0) {
        return 0;
    }

    if (check_family(newsk, AF_INET)) {
        data->net_data.local_addr = BPF_CORE_READ(newsk, __sk_common.skc_rcv_saddr);
        data->net_data.remote_addr = BPF_CORE_READ(newsk, __sk_common.skc_daddr);
        if (data->net_data.local_addr == 0 || data->net_data.remote_addr == 0) {
                return 0;
        }
    } else if (check_family(newsk, AF_INET6)) {
        bpf_probe_read(&data->net_data.local_addr6, sizeof(data->net_data.local_addr6), BPF_CORE_READ(newsk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32));
        bpf_probe_read(&data->net_data.remote_addr6, sizeof(data->net_data.remote_addr6), BPF_CORE_READ(newsk, __sk_common.skc_v6_daddr.in6_u.u6_addr32));
        if ((IPV6_COMPARE_TO_0(data->net_data.local_addr6)) || (IPV6_COMPARE_TO_0(data->net_data.remote_addr6))) {
                return 0;
        }
    }

    blob_pos = data->blob;
    blob_size = blobify_cgroup_path(blob_pos);
    blob_pos = compute_blob_ctx(blob_size, &data->cgroup_blob, &payload, blob_pos);
    data->net_data.header.payload = payload;

    if (payload <= MAX_BLOB_EVENT_SIZE) {
        send_event(ctx, data, payload);
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
    int ret = PT_REGS_RC_CORE(ctx);
    u64 id = bpf_get_current_pid_tgid();

    struct msghdr **msgpp; // for DNS receive probe

    msgpp = bpf_map_lookup_elem(&currsock2, &id);
    if (msgpp == 0) {
        return 0; // missed entry
    }

    if (ret <= 0) {
        goto out;
    }

    // Send DNS info if port is DNS
    struct msghdr *msgp = *msgpp;
    struct sockaddr_in *msgname = (struct sockaddr_in *)BPF_CORE_READ(msgp, msg_name);
    u16 dport = BPF_CORE_READ(msgname, sin_port);

    // TODO: Allow this to be configurable
    if (_ntohs(dport) != DNS_RESP_PORT_NUM) {
        goto out;
    }

    const char __user *dns = BPF_CORE_READ(msgp, msg_iter.iov, iov_base);
    if (!dns) {
        goto out;
    }

    struct dns_data_x *data_x = __current_blob();
    u32 payload = offsetof(typeof(*data_x), blob);
    char *blob_pos = NULL;
    u16 blob_size;

    if (!data_x) {
        goto out;
    }

    blob_pos = data_x->blob;
    __init_header_dynamic(EVENT_NET_CONNECT_DNS_RESPONSE, PP_ENTRY_POINT, &data_x->header);

    //
    // barrier_var is still NEEDED below!
    //
    // Payload return value has to be re-checked in order
    // to ensure to the verifier that bpf_probe_read's
    // requested read size won't cause overflow in the
    // xpad map's storage space. Careful when modifying this!
    //
    barrier_var(ret);
    if (ret <= 0) {
        goto out;
    } else if (ret > MAX_DNS_BLOB_SIZE) {
        blob_size = MAX_DNS_BLOB_SIZE;
    } else {
        barrier_var(ret);
        blob_size = (u16)ret;
    }

    barrier_var(blob_size);
    if (blob_size >= 1 && blob_size <= MAX_DNS_BLOB_SIZE) {
        if (bpf_probe_read(blob_pos, blob_size, dns)) {
            // On error of read aka fault don't send event
            goto out;
        }

        blob_pos = compute_blob_ctx(blob_size, &data_x->dns_blob,
                                    &payload, blob_pos);
    }

    barrier_var(payload);
    data_x->header.payload = payload;

    barrier_var(payload);

    blob_size = blobify_cgroup_path(blob_pos);
    blob_pos = compute_blob_ctx(blob_size, &data_x->cgroup_blob, &payload, blob_pos);

    if (payload <= sizeof(typeof(*data_x))) {
        send_event(ctx, data_x, payload);
    }

out:
    // Don't remove from bpf map currsock3
    bpf_map_delete_elem(&currsock2, &id);
    return 0;
}

static int trace_udp_sendmsg(struct sock *sk, struct msghdr *msg)
{
    u64 id;

    id = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&currsock3, &id, &sk, BPF_ANY);
    bpf_map_update_elem(&currsock2, &id, &msg, BPF_ANY);
    return 0;
}

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(kprobe_udp_sendmsg, struct sock *sk, struct msghdr *msg)
{
    return trace_udp_sendmsg(sk, msg);
}

SEC("kprobe/udpv6_sendmsg")
int BPF_KPROBE(kprobe_udpv6_sendmsg, struct sock *sk, struct msghdr *msg)
{
    return trace_udp_sendmsg(sk, msg);
}

static int trace_udp_sendmsg_return(struct pt_regs *ctx)
{
    int ret = PT_REGS_RC_CORE(ctx);
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

    struct net_data_x *data = __current_blob();
    if (!data) {
        goto out;
    }

    __init_header_dynamic(EVENT_NET_CONNECT_PRE, PP_NO_EXTRA_DATA, &data->net_data.header);
    u32 payload = offsetof(typeof(*data), blob);
    char *blob_pos = data->blob;
    u16 blob_size;

    data->net_data.protocol = IPPROTO_UDP;
    // The remote addr could be in the msghdr::msg_name or on the sock
    bool addr_in_msghr = false;

    // get ip version
    struct sock *skp = *skpp;
    data->net_data.ipver = BPF_CORE_READ(skp, __sk_common.skc_family);

    struct msghdr *msg;
    if (msgpp && (msg = *msgpp))
    {
        void *msg_name = BPF_CORE_READ(msg, msg_name);
        int msg_namelen = BPF_CORE_READ(msg, msg_namelen);

        if (msg_name && msg_namelen > 0)
        {
            switch (BPF_CORE_READ(skp, __sk_common.skc_family))
            {
            case AF_INET: {
                struct sockaddr_in *addr_in = (typeof(addr_in))msg_name;

                data->net_data.remote_port = BPF_CORE_READ(addr_in, sin_port);
                data->net_data.remote_addr = BPF_CORE_READ(addr_in, sin_addr.s_addr);
                addr_in_msghr = true;
                break;
            }

            case AF_INET6: {
                struct sockaddr_in6 *addr_in6 = (typeof(addr_in6))msg_name;

                data->net_data.remote_port = BPF_CORE_READ(addr_in6, sin6_port);
                bpf_probe_read(
                    &data->net_data.remote_addr6, sizeof(data->net_data.remote_addr6),
                    BPF_CORE_READ(addr_in6, sin6_addr.in6_u.u6_addr32));
                addr_in_msghr = true;
                break;
            }

            default:
                goto out;
            }
        }
    }

    __u16 snum = BPF_CORE_READ(skp, __sk_common.skc_num);
    bpf_probe_read(&data->net_data.local_port, sizeof(snum), &snum);
    data->net_data.local_port = _htons(data->net_data.local_port);

    if (!addr_in_msghr)
    {
        data->net_data.remote_port = BPF_CORE_READ(skp, __sk_common.skc_dport); // already network order
    }

    switch (BPF_CORE_READ(skp, __sk_common.skc_family))
    {
    case AF_INET: {
        data->net_data.local_addr = BPF_CORE_READ(skp, __sk_common.skc_rcv_saddr);
        if (!addr_in_msghr)
        {
            data->net_data.remote_addr = BPF_CORE_READ(skp, __sk_common.skc_daddr);
        }

        struct ip_key ip_key = {};
        ip_key.pid = data->net_data.header.pid;
        bpf_probe_read(&ip_key.remote_port, sizeof(data->net_data.remote_port),
                       &data->net_data.remote_port);
        bpf_probe_read(&ip_key.local_port, sizeof(data->net_data.local_port),
                       &data->net_data.local_port);
        bpf_probe_read(&ip_key.remote_addr, sizeof(data->net_data.remote_addr),
                       &data->net_data.remote_addr);
        bpf_probe_read(&ip_key.local_addr, sizeof(data->net_data.local_addr),
                       &data->net_data.local_addr);

        if (has_ip_cache(&ip_key, FLOW_TX))
        {
            goto out;
        }
        break;
    }

    case AF_INET6: {
        if (!addr_in_msghr)
        {
            __be32 *daddr = BPF_CORE_READ(skp, __sk_common.skc_v6_daddr.in6_u.u6_addr32);
            bpf_probe_read(&data->net_data.remote_addr6, sizeof(data->net_data.remote_addr6), daddr);
        }

        __be32 *saddr = BPF_CORE_READ(skp, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read(&data->net_data.local_addr6, sizeof(data->net_data.local_addr6), saddr);

        struct ip6_key ip_key = {};
        ip_key.pid = data->net_data.header.pid;
        bpf_probe_read(&ip_key.remote_port, sizeof(data->net_data.remote_port), &data->net_data.remote_port);
        bpf_probe_read(&ip_key.local_port, sizeof(data->net_data.local_port), &data->net_data.local_port);

        bpf_probe_read(ip_key.remote_addr6, sizeof(data->net_data.remote_addr6), &data->net_data.remote_addr6);
        bpf_probe_read(ip_key.local_addr6, sizeof(data->net_data.local_addr6), &data->net_data.local_addr6);

        if (has_ip6_cache(&ip_key, FLOW_TX)) {
            goto out;
        }
        break;
    }

    default:
        goto out;
    }

    blob_size = blobify_cgroup_path(blob_pos);
    blob_pos = compute_blob_ctx(blob_size, &data->cgroup_blob, &payload, blob_pos);
    data->net_data.header.payload = payload;

    if (payload <= sizeof(typeof(*data))) {
        send_event(ctx, data, payload);
    }

out:
    bpf_map_delete_elem(&currsock3, &id);
    bpf_map_delete_elem(&currsock2, &id);
    return 0;
}

SEC("kretprobe/udp_sendmsg")
int BPF_KRETPROBE(kretpobe_udp_sendmsg)
{
    return trace_udp_sendmsg_return(ctx);
}

SEC("kretprobe/udpv6_sendmsg")
int BPF_KRETPROBE(kretpobe_udpv6_sendmsg)
{
    return trace_udp_sendmsg_return(ctx);
}


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
