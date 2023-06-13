/*
 * Copyright 2019-2021 VMware, Inc.
 * SPDX-License-Identifier: GPL-2.0
 */

//
// NOTE:
// Structs related to transport of data
// payloads are inject at top of file.
//

// Struct randomization causes issues on 4.13 and some early versions of 4.14
// These are redefined to work around this, per:
// https://lists.iovisor.org/g/iovisor-dev/topic/21386300#1239
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
#ifdef randomized_struct_fields_start
#undef randomized_struct_fields_start
#endif
#define randomized_struct_fields_start struct {
#ifdef randomized_struct_fields_end
#undef randomized_struct_fields_end
#endif
#define randomized_struct_fields_end \
	}                            \
	;
#endif

#ifndef KBUILD_MODNAME
#define KBUILD_MODNAME "vmw_bcc_bpfsensor"
#endif

#include <uapi/linux/limits.h>
#include <uapi/linux/in.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/ptrace.h>
#include <uapi/linux/stat.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/magic.h>

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
#else
#define BPF_LRU BPF_HASH
#endif
#endif

#ifndef PT_REGS_RC
#define PT_REGS_RC(x) ((x)->ax)
#endif

// Note that these functions are not 100% compatible.  The read_str function returns the number of bytes read,
//   while the old version returns 0 on success.  Some of the logic we use does depend on the non-zero result
//   (described later).
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0)
#define FLAG_TRUNCATED_ARG_BEHAVIOR
static long cb_bpf_probe_read_str(void *dst, u32 size, const void *unsafe_ptr)
{
	bpf_probe_read(dst, size, unsafe_ptr);
	return size;
}
#else
#define FLAG_EXTENDED_ARG_BEHAVIOR
#define cb_bpf_probe_read_str bpf_probe_read_str
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
// Existence of map tells userspace if kernel is LRU map capable
BPF_ARRAY(has_lru, uint32_t, 1);
#define FALLBACK_FIELD_TYPE(A, B) A
#else
#define FALLBACK_FIELD_TYPE(A, B) B
#endif

#define CACHE_UDP

struct mnt_namespace {
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
	atomic_t count;
#endif
	struct ns_common ns;
};

struct mount {
	struct hlist_node mnt_hash;
	struct mount *mnt_parent;
	struct dentry *mnt_mountpoint;
	struct vfsmount mnt;
	void *cb_args;
} __randomize_layout;

// Refer to kernel/trace/trace.h syscall_trace_exit
// Only explicitly include trace_events.h
// for kernels that have patched struct trace_entry
#if defined(RHEL_MAJOR) && RHEL_MAJOR == 9
#include <linux/trace_events.h>
struct syscalls_sys_exit_args {
	struct trace_entry ent;
	int __syscall_nr;
	long int ret;
};
#else
struct syscalls_sys_exit_args {
	__u64 pad;
	int __syscall_nr;
	long int ret;
};
#endif

#define DNS_RESP_PORT_NUM 53
#define DNS_RESP_MAXSIZE 512
#define PROXY_SERVER_MAX_LEN 100
#define DNS_SEGMENT_FLAGS_START 0x01
#define DNS_SEGMENT_FLAGS_END 0x02


#define DECLARE_FILE_EVENT(DATA) struct _file_event __##DATA = {}; struct _file_event *DATA = &__##DATA
#define GENERIC_DATA(DATA)  ((struct data*)&((struct _file_event*)(DATA))->_data)
#define FILE_DATA(DATA)  ((struct file_data*)&((struct _file_event*)(DATA))->_file_data)
#define PATH_DATA(DATA)  ((struct path_data*)&((struct _file_event*)(DATA))->_path_data)
#define RENAME_DATA(DATA)  ((struct rename_data*)&((struct _file_event*)(DATA))->_rename_data)

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0)
BPF_HASH(last_parent, u32, u32, 8192);
BPF_HASH(root_fs, u32, void *, 3); // stores last known root fs
#endif

BPF_PERF_OUTPUT(events);

static void send_event(
	struct pt_regs *ctx,
	void           *data,
	size_t          data_size)
{
    ((struct data*)data)->header.event_time = bpf_ktime_get_ns();
	events.perf_submit(ctx, data, data_size);
}

static inline struct super_block *_sb_from_dentry(struct dentry *dentry)
{
	struct super_block *sb = NULL;
	// Can't get dentry info return NULL
	if (!dentry) {
		goto out;
	}
	// Try dentry inode before dentry's sb
	if (dentry->d_inode) {
		sb = dentry->d_inode->i_sb;
	}
	if (sb) {
		goto out;
	}
	// This might not exactly be the sb we are looking for
	sb = dentry->d_sb;

out:
	return sb;
}

static inline struct super_block *_sb_from_file(struct file *file)
{
	struct super_block *sb = NULL;

	if (!file) {
		goto out;
	}

	if (file->f_inode) {
		struct inode *pinode = NULL;

		bpf_probe_read(&pinode, sizeof(pinode), &(file->f_inode));
		if (!pinode) {
			goto out;
		}
		bpf_probe_read(&sb, sizeof(sb), &(pinode->i_sb));
	}
	if (sb) {
		goto out;
	}
	sb = _sb_from_dentry(file->f_path.dentry);

out:
	return sb;
}

static inline bool __is_special_filesystem(struct super_block *sb)
{
	if (!sb) {
		return false;
	}

	switch (sb->s_magic) {
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
#ifdef NSFS_MAGIC
	case NSFS_MAGIC:
#endif /* NSFS_MAGIC */

		return true;

	default:
		return false;
	}

	return false;
}

static inline unsigned int __get_mnt_ns_id(struct task_struct *task)
{
	struct nsproxy *nsproxy;

	if (task && task->nsproxy) {
		return task->nsproxy->mnt_ns->ns.inum;
	}
	return 0;
}

static inline u32 __get_device_from_sb(struct super_block *sb)
{
	dev_t device = 0;
	if (sb) {
		bpf_probe_read(&device, sizeof(device), &sb->s_dev);
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
		bpf_probe_read(&inode, sizeof(inode), &pinode->i_ino);
	}

	return inode;
}

static inline u64 __get_inode_from_file(struct file *file)
{
	if (file) {
		struct inode *pinode = NULL;

		bpf_probe_read(&pinode, sizeof(pinode), &(file->f_inode));
		return __get_inode_from_pinode(pinode);
	}

	return 0;
}

static inline u64 __get_inode_from_dentry(struct dentry *dentry)
{
	if (dentry) {
		struct inode *pinode = NULL;

		bpf_probe_read(&pinode, sizeof(pinode), &(dentry->d_inode));
		return __get_inode_from_pinode(pinode);
	}

	return 0;
}

static inline bool __has_fmode_nonotify(const struct file *file)
{
#ifdef FMODE_NONOTIFY
    if (file && (file->f_flags & FMODE_NONOTIFY)) {
        // If open for read then definitely eat the event.
        if (((file->f_flags & (O_WRONLY|O_RDWR)) == 0)) {
            return true;
        }

#ifdef FMODE_NOACCOUNT
        // Definitely are opened for internal use
        if (file->f_mode & FMODE_NOACCOUNT) {
            return true;
        }
#endif /* FMODE_NOACCOUNT */

    }
#endif /* FMODE_NONOTIFY */

    return false;
}

static inline struct pid *select_task_pid(struct task_struct *task)
{
    struct pid *pid = NULL;

#if defined(RHEL_MAJOR) && defined(RHEL_MINOR) && RHEL_MAJOR == 8 && RHEL_MINOR > 0
    bpf_probe_read(&pid, sizeof(pid), &task->thread_pid);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0)
    bpf_probe_read(&pid, sizeof(pid), &task->pids[PIDTYPE_PID].pid);
#else
    bpf_probe_read(&pid, sizeof(pid), &task->thread_pid);
#endif
    return pid;
}

static __always_inline void set_pid_ns_data(struct data_header *hdr,
                                            struct task_struct *task)
{
    struct task_struct *group_leader = NULL;
    struct pid *pid = NULL;

    // Assumes group_leader is in the same pid_ns as current task.
    bpf_probe_read(&group_leader, sizeof(group_leader), &task->group_leader);
    pid = select_task_pid(group_leader);
    if (pid) {
        struct pid_namespace *pid_ns = NULL;
        unsigned int level = 0;

        bpf_probe_read(&level, sizeof(level), &pid->level);
        bpf_probe_read(&pid_ns, sizeof(pid_ns), &pid->numbers[level].ns);

        // Sets both only when pid_ns is available
        if (pid_ns) {
            bpf_probe_read(&hdr->pid_ns, sizeof(hdr->pid_ns), &pid_ns->ns.inum);
            bpf_probe_read(&hdr->pid_ns_vnr, sizeof(hdr->pid_ns_vnr), &pid->numbers[level].nr);
        }
    }
}

static inline void __init_header_with_task(u8 type, u8 state, struct data_header *header, struct task_struct *task)
{
	header->type = type;
	header->state = state;
	header->report_flags = REPORT_FLAGS_COMPAT;
	header->payload = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
	if (task) {
		header->tid = task->pid;
		header->pid = task->tgid;
		if (task->cred) {
			header->uid = __kuid_val(task->cred->uid);
		}
		if (task->real_parent) {
			header->ppid = task->real_parent->tgid;
		}
		header->mnt_ns = __get_mnt_ns_id(task);
		set_pid_ns_data(header, task);
	}
#else
	u64 id = bpf_get_current_pid_tgid();
	header->tid = id & 0xffffffff;
	header->pid = id >> 32;

	u32 *ppid = last_parent.lookup(&header->pid);
	if (ppid) {
		header->ppid = *ppid;
	}
#endif

}

// Assumed current context is what is valid!
static inline void __init_header(u8 type, u8 state, struct data_header *header)
{
	__init_header_with_task(type, state, header, (struct task_struct *)bpf_get_current_task());
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 18, 0)
// The verifier on older kernels does not like us to play with the size dynamically
// # R5 type=inv expected=imm  (from verifier)
#define PATH_MSG_SIZE(DATA) (sizeof(struct path_data))
#else
#define PATH_MSG_SIZE(DATA) (size_t)(sizeof(struct path_data) - MAX_FNAME + (DATA)->size)
#endif

static inline u8 cgroup_name_from_task(char *buf, struct task_struct *task)
{
    struct kernfs_node *cgroup_node = NULL;

    // BCC seems to somtimes get confused with global enum values and ptr arrays
    struct css_set *css_set = NULL;

    bpf_probe_read(&css_set, sizeof(css_set), &task->cgroups);
    if (css_set) {
        struct cgroup_subsys_state *subsys = NULL;

#if defined(CONFIG_CGROUP_PIDS)
        bpf_probe_read(&subsys, sizeof(subsys), css_set->subsys + pids_cgrp_id);
        if (subsys) {
            struct cgroup *cgroup = NULL;

            bpf_probe_read(&cgroup, sizeof(cgroup), &subsys->cgroup);
            if (cgroup) {
                bpf_probe_read(&cgroup_node, sizeof(cgroup_node), &cgroup->kn);
            }
        }
#endif /* CONFIG_CGROUP_PIDS */

        if (!cgroup_node) {
            bpf_probe_read(&subsys, sizeof(subsys), css_set->subsys);
            if (subsys) {
                struct cgroup *cgroup = NULL;

                bpf_probe_read(&cgroup, sizeof(cgroup), &subsys->cgroup);
                if (cgroup) {
                    bpf_probe_read(&cgroup_node, sizeof(cgroup_node), &cgroup->kn);
                }
            }
        }
    }

    if (cgroup_node) {
        const char *name = NULL;
        bpf_probe_read(&name, sizeof(name), &cgroup_node->name);

        if (name) {
            return (u8)cb_bpf_probe_read_str(buf, MAX_FNAME, name);
        }
    }

    return 0;
}

#define sizeof_without_extra(t) offsetof(typeof((t)), extra)

#define init_extra_task_data(extra, ...) do { \
	(extra)->cgroup_size = 0; \
	(extra)->cgroup_name[0] = 0; \
} while (0)


static void __send_final_event(void *ctx, struct data *data,
                               struct task_struct *task)
{
    data->header.state = PP_FINALIZED;
    if (task) {
        init_extra_task_data(&data->extra);
        u8 cgroup_len = cgroup_name_from_task(data->extra.cgroup_name, task);
        if (cgroup_len) {
            data->extra.cgroup_size = cgroup_len;
            data->header.report_flags |= REPORT_FLAGS_TASK_DATA;
            send_event(ctx, data, sizeof(*data));
            data->header.report_flags &= ~(REPORT_FLAGS_TASK_DATA);
            return;
        }
    }
    send_event(ctx, data, sizeof_without_extra(*data));
}

#define __send_single_event(ctx, var, hdr, task_var) do { \
	if ((task_var)) { \
		init_extra_task_data(&(var)->extra); \
		u8 cgroup_len = cgroup_name_from_task((var)->extra.cgroup_name, (task_var)); \
		if (cgroup_len) { \
			(hdr)->report_flags |= REPORT_FLAGS_TASK_DATA; \
			(var)->extra.cgroup_size = cgroup_len; \
			send_event(ctx, (var), sizeof(*(var))); \
			break; \
		} \
	} \
	send_event(ctx, (var), sizeof_without_extra(*(var))); \
} while (0)


#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0)
#define send_single_event(ctx, var) \
    send_event(ctx, var, sizeof_without_extra(*(var)));

#define send_single_net_event(ctx, net_var) \
    send_event(ctx, net_var, sizeof_without_extra(*(net_var)));

#define send_final_event(ctx, var) \
    __send_final_event(ctx, var, NULL)

#else
#define send_single_event(ctx, var) do { \
    struct task_struct *task = (typeof(task))bpf_get_current_task(); \
    __send_single_event(ctx, var, &((var)->header), task); \
} while (0)

#define send_single_net_event(ctx, net_var) do { \
    struct task_struct *task = (typeof(task))bpf_get_current_task(); \
    __send_single_event(ctx, net_var, &((net_var)->net_data.header), task); \
} while (0)

#define send_final_event(ctx, data) do { \
    struct task_struct *task = (typeof(task))bpf_get_current_task(); \
    __send_final_event((ctx), (data), task); \
} while (0)

#endif

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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
#define MAXARG 30
#else
#define MAXARG 20
#endif

// All arguments will be capped at MAX_FNAME bytes per argument
// (This is deliberately defined as a separate version of the function to cut down on the number
// of instructions needed, as older kernels have stricter limitations on the max count of the probe insns)
#ifdef FLAG_TRUNCATED_ARG_BEHAVIOR
static void submit_all_args(struct pt_regs *ctx,
                            const char __user *const __user *_argv,
                            struct path_data *data)
{
    void *argp = NULL;
    int index = 0;

#pragma unroll
    for (int i = 0; i < MAXARG; i++) {
        data->header.state = PP_ENTRY_POINT;
        bpf_probe_read(&argp, sizeof(argp), &_argv[index++]);
        if (!argp) {
            // We have reached the last arg so bail out
            goto out;
        }

        __submit_arg(ctx, argp, data);
    }

    // handle truncated argument list
    char ellipsis[] = "...";
    __submit_arg(ctx, (void *)ellipsis, data);

out:
    send_final_event(ctx, GENERIC_DATA(data));

    return;
}
#endif

#ifdef FLAG_EXTENDED_ARG_BEHAVIOR
// PSCLNX-6764 - Improve EXEC event performance
//  This logic should be refactored to write the multiple args into a single
//  event buffer instead of one event per arg.
static void submit_all_args(struct pt_regs *ctx,
				const char __user *const __user *_argv,
				struct path_data *data)
{
	void *argp = NULL;
	void *next_argp = NULL;
	int index = 0;

#pragma unroll
	for (int i = 0; i < MAXARG; i++) {
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

	// handle truncated argument list
	char ellipsis[] = "...";
	__submit_arg(ctx, (void *)ellipsis, data);

out:
	send_final_event(ctx, GENERIC_DATA(data));

	return;
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
  #ifndef MAX_FULL_PATH_ITER
    #define MAX_FULL_PATH_ITER 40
  #endif
  #ifndef MAX_DENTRY_PATH_ITER
    #define MAX_DENTRY_PATH_ITER 32
   #endif
#else
  #define MAX_FULL_PATH_ITER 24
  #define MAX_DENTRY_PATH_ITER 24
#endif

#define MAX_PATH_EDGE_DETECT_ITER 2

static inline int __get_next_parent_dentry(struct dentry **dentry,
										   struct vfsmount **vfsmnt,
										   struct mount **real_mount,
										   struct dentry **mnt_root,
										   struct dentry **parent_dentry)
{
	int retVal = 0;
	struct mount *mnt_parent = NULL;

	bpf_probe_read(parent_dentry, sizeof(struct dentry *), &(*dentry)->d_parent);

	if (*dentry == *mnt_root || *dentry == *parent_dentry) {
		bpf_probe_read(&mnt_parent, sizeof(struct mount *), &(*real_mount)->mnt_parent);
		if (*dentry != *mnt_root) {
			// We reached root, but not mount root - escaped?
			retVal = ENOENT;
		} else if (*real_mount != mnt_parent) {
			// We reached root, but not global root - continue with mount point path
			bpf_probe_read(dentry, sizeof(struct dentry *), &(*real_mount)->mnt_mountpoint);
			bpf_probe_read(real_mount, sizeof(struct mount *), &(*real_mount)->mnt_parent);
			*vfsmnt = &(*real_mount)->mnt;
			bpf_probe_read(mnt_root, sizeof(struct dentry *), &(*vfsmnt)->mnt_root);
			retVal = EAGAIN;
		} else {
			// Global root - path fully parsed
			retVal = ENOENT;
		}
	}

	return retVal;
}

static inline int __do_file_path(struct pt_regs *ctx,
								 struct dentry *dentry,
								 struct vfsmount *vfsmnt,
								 struct path_data *data)
{
	struct mount *real_mount = NULL;
	struct dentry *mnt_root = NULL;
	struct dentry *parent_dentry = NULL;
	struct qstr sp = {};
	int i = 0;

	bpf_probe_read(&mnt_root, sizeof(struct dentry *), &vfsmnt->mnt_root);

	// poorman's container_of
	real_mount = ((void *)vfsmnt) - offsetof(struct mount, mnt);

	data->header.state = PP_PATH_COMPONENT;
#pragma clang loop unroll(full)
	for (i = 0; i < MAX_FULL_PATH_ITER; ++i) {
		int retVal = __get_next_parent_dentry(&dentry, &vfsmnt, &real_mount, &mnt_root, &parent_dentry);

		if (retVal == EAGAIN) {
			continue;
		}

		if (retVal == ENOENT) {
			break;
		}

		bpf_probe_read(&sp, sizeof(sp), (void *)&(dentry->d_name));
		__write_fname(data, sp.name);
		dentry = parent_dentry;
		send_event(ctx, data, PATH_MSG_SIZE(data));
	}

	// Best effort to check if path was fully parsed in the last loop iteration.
	// Could still yield a false result because without unbounded looping we can't know
	// beyond all doubts that we have reached the global root mount.
	// We don't add ellipsis if we can't be sure the path is truncated.
	if (i >= MAX_FULL_PATH_ITER) {
		bool truncated = false;

#pragma clang loop unroll(full)
		for (i = 0; i < MAX_PATH_EDGE_DETECT_ITER; ++i) {
			int retVal = __get_next_parent_dentry(&dentry, &vfsmnt, &real_mount, &mnt_root, &parent_dentry);

			if (retVal == EAGAIN) {
				continue;
			}

			if (retVal == ENOENT) {
				break;
			}

			// The path is truncated for sure!
			truncated = true;
			break;
		}

		if (truncated) {
			char ellipsis[] = "...";
			__write_fname(data, ellipsis);
			send_event(ctx, data, PATH_MSG_SIZE(data));
		}
	}

	send_final_event(ctx, GENERIC_DATA(data));

	return 0;
}

static inline int __do_dentry_path(struct pt_regs *ctx, struct dentry *dentry,
				   struct path_data *data, uint64_t fs_magic)
{
	struct dentry *parent_dentry = NULL;
	struct qstr sp = {};
	bool truncated = false;
	int i = 0;

	data->header.state = PP_PATH_COMPONENT;
#pragma unroll
	for (i = 0; i < MAX_DENTRY_PATH_ITER; ++i) {
		bpf_probe_read(&parent_dentry, sizeof(parent_dentry), &(dentry->d_parent));

		if (parent_dentry == dentry || parent_dentry == NULL) {
			break;
		}

		bpf_probe_read(&sp, sizeof(struct qstr), (void *)&(dentry->d_name));

		// Check that the name is valid
		//  We sometimes get a dentry of '/', so this logic will skip it
		if (__write_fname(data, sp.name) > 0 && data->size > 1) {
			send_event(ctx, data, PATH_MSG_SIZE(data));
		}

		dentry = parent_dentry;
	}

	// Best effort to check if path was fully parsed in the last loop iteration.
	// Could still yield a false result because without unbounded looping we can't know
	// beyond all doubts that we have reached the global root mount.
	// We don't add ellipsis if we can't be sure the path is truncated.
	if (i >= MAX_DENTRY_PATH_ITER) {
#pragma unroll
		for (i = 0; i < MAX_PATH_EDGE_DETECT_ITER; ++i) {
			bpf_probe_read(&parent_dentry, sizeof(parent_dentry), &(dentry->d_parent));

			if (parent_dentry == dentry || parent_dentry == NULL) {
				break;
			}

			bpf_probe_read(&sp, sizeof(struct qstr), (void *)&(dentry->d_name));

			// Do we have a valid path entry
			if (__write_fname(data, sp.name) > 0 && data->size > 1) {
				// Path is not truncated if we have reached btrfs subvolume root
				if (fs_magic != BTRFS_SUPER_MAGIC || data->fname[0] != '@') {
					// The path is truncated for sure!
					truncated = true;
					break;
				}
			}

			dentry = parent_dentry;
		}
	}

	if (truncated) {
		char ellipsis[] = "...";
		__write_fname(data, ellipsis);
		send_event(ctx, data, PATH_MSG_SIZE(data));
	} else {
		// Trigger the agent to add the mount path
		data->header.state = PP_NO_EXTRA_DATA;
		send_event(ctx, GENERIC_DATA(data), offsetof(struct data, extra));
	}

	send_final_event(ctx, GENERIC_DATA(data));

	return 0;
}

int syscall__on_sys_execveat(struct pt_regs *ctx, int fd,
				 const char __user *filename,
				 const char __user *const __user *argv,
				 const char __user *const __user *envp, int flags)
{
	DECLARE_FILE_EVENT(data);
	if (!data) return 0;

	__init_header(EVENT_PROCESS_EXEC_ARG, PP_ENTRY_POINT, &GENERIC_DATA(data)->header);

	submit_all_args(ctx, argv, PATH_DATA(data));

	return 0;
}
int syscall__on_sys_execve(struct pt_regs *ctx, const char __user *filename,
			   const char __user *const __user *argv,
			   const char __user *const __user *envp)
{
	DECLARE_FILE_EVENT(data);
	if (!data) return 0;

	__init_header(EVENT_PROCESS_EXEC_ARG, PP_ENTRY_POINT, &GENERIC_DATA(data)->header);

	submit_all_args(ctx, argv, PATH_DATA(data));

	return 0;
}

static inline void do_sys_exec_exit(void *ctx, long retval)
{
	struct exec_data data = {};

	__init_header(EVENT_PROCESS_EXEC_RESULT, PP_ENTRY_POINT, &data.header);
	data.retval = (int)retval;

	send_single_event(ctx, &data);
}

int after_sys_execve(struct pt_regs *ctx)
{
	do_sys_exec_exit(ctx, PT_REGS_RC(ctx));
	return 0;
}

int on_sys_exit_execve(struct syscalls_sys_exit_args *args)
{
	long ret = args->ret;

#if defined(__aarch64__)
	if (ret != 0)
#endif /* __aarch64__ */
	{
		do_sys_exec_exit(args, ret);
	}
	return 0;
}

int on_sys_exit_execveat(struct syscalls_sys_exit_args *args)
{
	long ret = args->ret;

#if defined(__aarch64__)
	if (ret != 0)
#endif /* __aarch64__ */
	{
		do_sys_exec_exit(args, ret);
	}
	return 0;
}

// We don't worry about arg data here. If we attach to
// sched:sched_process_exec, safe to say the exec will complete
// task will segfault.
int on_sched_process_exec(void *ctx)
{
	do_sys_exec_exit(ctx, 0);
	return 0;
}

struct file_data_cache {
	u64 pid;
	u64 device;
	u64 inode;
};

// This hash tracks the "observed" file-create events.  This will not be 100% accurate because we will report a
//  file create for any file the first time it is opened with WRITE|TRUNCATE (even if it already exists).  It
//  will however serve to de-dup some events.  (Ie.. If a program does frequent open/write/close.)
BPF_LRU(file_map, struct file_data_cache, u32);

static void __file_tracking_delete(u64 pid, u64 device, u64 inode)
{
	struct file_data_cache key = { .device = device, .inode = inode };
	file_map.delete(&key);
}


// Older kernels do not support the struct fields so allow for fallback
BPF_LRU(file_write_cache, u64, FALLBACK_FIELD_TYPE(struct file_data_cache, u32));

static inline void __track_write_entry(
    struct file      *file,
    struct file_data *data)
{
	if (!file || !data) {
		return;
	}

	u64 file_cache_key = (u64)file;

	void *cachep = file_write_cache.lookup(&file_cache_key);
	if (cachep) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
		struct file_data_cache cache_data = *((struct file_data_cache *)cachep);
		pid_t pid = cache_data.pid;
		cache_data.pid = data->header.pid;
#else
		u32 cache_data = *(u32 *)cachep;
		pid_t pid = cache_data;
		cache_data = data->header.pid;
#endif

		// if we really care about that multiple tasks
		// these are likely threads or less likely inherited from a fork
		if (pid == data->header.pid) {
			return;
		}

		file_write_cache.update(&file_cache_key, &cache_data);
	} else {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
		struct file_data_cache cache_data = {
			.pid = data->header.pid,
			.device = data->device,
			.inode = data->inode
		};
#else
		u32 cache_data = data->header.pid;
#endif
		file_write_cache.insert(&file_cache_key, &cache_data);
	}
}

// Only need this hook for kernels without lru_hash
int on_security_file_free(struct pt_regs *ctx, struct file *file)
{
	if (!file || __has_fmode_nonotify(file)) {
		return 0;
	}
	u64 file_cache_key = (u64)file;

	void *cachep = file_write_cache.lookup(&file_cache_key);
	if (cachep) {
		DECLARE_FILE_EVENT(data);
		if (!data) return 0;

		__init_header(EVENT_FILE_CLOSE, PP_ENTRY_POINT, &GENERIC_DATA(data)->header);
		struct file_data *file_data = FILE_DATA(data);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
		file_data->device = ((struct file_data_cache *)cachep)->device;
		file_data->inode = ((struct file_data_cache *)cachep)->inode;
#else
		file_data->device = __get_device_from_file(file);
		file_data->inode = __get_inode_from_file(file);
#endif

		send_event(ctx, file_data, sizeof_without_extra(*file_data));

		__do_file_path(ctx, file->f_path.dentry, file->f_path.mnt, PATH_DATA(data));
	}

	file_write_cache.delete(&file_cache_key);
	return 0;
}

int on_security_mmap_file(struct pt_regs *ctx, struct file *file,
			  unsigned long prot, unsigned long flags)
{
	unsigned long exec_flags;
	struct super_block *sb = NULL;

	if (!file) {
		goto out;
	}
	if (!(prot & PROT_EXEC)) {
		goto out;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0) && !defined(CONFIG_SUSE_VERSION)
	// This fix is to adjust the flag changes in 5.14 kernel to match the user space pipeline requirement
	//  - MAP_EXECUTABLE flag is not available for exec mmap function
	//  - MAP_DENYWRITE flag is "reverted" for ld.so and normal mmap
	if (file->f_flags & FMODE_EXEC && flags == (MAP_FIXED | MAP_PRIVATE)) {
	    goto out;
	}

	if (flags & MAP_DENYWRITE) {
	    flags &= ~MAP_DENYWRITE;
	} else {
	    flags |= MAP_DENYWRITE;
	}
#else
	exec_flags = flags & (MAP_DENYWRITE | MAP_EXECUTABLE);
	if (exec_flags == (MAP_DENYWRITE | MAP_EXECUTABLE)) {
		goto out;
	}
#endif

	sb = _sb_from_file(file);
	DECLARE_FILE_EVENT(data);
	if (!data) goto out;

	__init_header(EVENT_FILE_MMAP, PP_ENTRY_POINT, &GENERIC_DATA(data)->header);
	struct file_data *file_data = FILE_DATA(data);

	// event specific data
	file_data->device = __get_device_from_file(file);
	file_data->inode = __get_inode_from_file(file);
	file_data->flags = flags;
	file_data->prot = prot;
	if (sb) {
		file_data->fs_magic = sb->s_magic;
	}
	// submit initial event data
	send_event(ctx, file_data, sizeof_without_extra(*file_data));

	// submit file path event data
	__do_file_path(ctx, file->f_path.dentry, file->f_path.mnt, PATH_DATA(data));
out:
	return 0;
}

// This is not available on older kernels.  So it will mean that we can not detect file creates
#ifndef FMODE_CREATED
#define FMODE_CREATED 0
#endif

// This hook may not be very accurate but at least tells us the intent
// to create the file if needed. So this will likely be written to next.
int on_security_file_open(struct pt_regs *ctx, struct file *file)
{
	struct super_block *sb = NULL;
	struct inode *inode = NULL;
	int mode;

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

	bpf_probe_read(&inode, sizeof(inode), &(file->f_inode));
	if (!inode) {
		goto out;
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
	bpf_probe_read(&mode, sizeof(mode), &(inode->i_mode));
	if (!S_ISREG(mode)) {
		goto out;
	}
#endif

	u8 type;
	if (file->f_flags & FMODE_EXEC) {
		type = EVENT_PROCESS_EXEC_PATH;
	} else if ((file->f_mode & FMODE_CREATED)) {
		type = EVENT_FILE_CREATE;
	} else if (file->f_flags & (O_RDWR | O_WRONLY)) {
		type = EVENT_FILE_WRITE;
	} else {
		type = EVENT_FILE_READ;
	}

	DECLARE_FILE_EVENT(data);
	if (!data) goto out;
	struct file_data *file_data = FILE_DATA(data);

	__init_header(type, PP_ENTRY_POINT, &GENERIC_DATA(data)->header);
	file_data->device = __get_device_from_file(file);
	file_data->inode = __get_inode_from_file(file);
	file_data->flags = file->f_flags;
	file_data->prot = file->f_mode;
	file_data->fs_magic = sb->s_magic;

	if (type == EVENT_FILE_WRITE || type == EVENT_FILE_CREATE)
	{
		// This allows us to send the last-write event on file close
		__track_write_entry(file, FILE_DATA(data));
	}

	send_event(ctx, FILE_DATA(data), sizeof_without_extra(*file_data));

	__do_file_path(ctx, file->f_path.dentry, file->f_path.mnt, PATH_DATA(data));

out:
	return 0;
}

static bool __send_dentry_delete(struct pt_regs *ctx, void *data, struct dentry *dentry)
{
	if (data && dentry)
	{
		struct super_block *sb = _sb_from_dentry(dentry);

		if (sb && !__is_special_filesystem(sb))
		{
			__init_header(EVENT_FILE_DELETE, PP_ENTRY_POINT, &GENERIC_DATA(data)->header);
			struct file_data *file_data = FILE_DATA(data);

			file_data->device = __get_device_from_sb(sb);
			file_data->inode = __get_inode_from_dentry(dentry);
			file_data->fs_magic = sb->s_magic;

			__file_tracking_delete(0, file_data->device, file_data->inode);

			send_event(ctx, file_data, sizeof_without_extra(*file_data));
			__do_dentry_path(ctx, dentry, PATH_DATA(data), file_data->fs_magic);
			return true;
		}
	}

	return false;
}

int on_security_inode_unlink(struct pt_regs *ctx, struct inode *dir,
				 struct dentry *dentry)
{
	if (dentry) {
		DECLARE_FILE_EVENT(data);

		if (data)
		{
			__send_dentry_delete(ctx, data, dentry);
		}
	}

	return 0;
}

int on_security_inode_rename(struct pt_regs *ctx, struct inode *old_dir,
				 struct dentry *old_dentry, struct inode *new_dir,
				 struct dentry *new_dentry, unsigned int flags)
{
    DECLARE_FILE_EVENT(data);
    if (!data) goto out;
    struct super_block *sb = NULL;

    // send event for delete of source file
    if (!__send_dentry_delete(ctx, data, old_dentry)) {
        goto out;
    }

    __init_header(EVENT_FILE_RENAME, PP_ENTRY_POINT, &GENERIC_DATA(data)->header);

    sb = _sb_from_dentry(old_dentry);

    RENAME_DATA(data)->device = __get_device_from_dentry(old_dentry);
    RENAME_DATA(data)->old_inode = __get_inode_from_dentry(old_dentry);
    RENAME_DATA(data)->fs_magic = sb ? sb->s_magic : 0;

    __file_tracking_delete(0, RENAME_DATA(data)->device, RENAME_DATA(data)->old_inode);

    // If the target destination already exists
    if (new_dentry)
    {
        __file_tracking_delete(0, RENAME_DATA(data)->device, RENAME_DATA(data)->new_inode);

        RENAME_DATA(data)->new_inode  = __get_inode_from_dentry(new_dentry);
    }
    else
    {
        RENAME_DATA(data)->new_inode  = 0;
    }

    send_event(ctx, RENAME_DATA(data), sizeof(struct rename_data));

    __do_dentry_path(ctx, new_dentry, PATH_DATA(data), RENAME_DATA(data)->fs_magic);
out:
    return 0;
}

int on_wake_up_new_task(struct pt_regs *ctx, struct task_struct *task)
{
	struct inode *pinode = NULL;
	struct file_data data = {};
	if (!task) {
		goto out;
	}

	if (task->tgid != task->pid) {
		goto out;
	}

	__init_header_with_task(EVENT_PROCESS_CLONE, PP_ENTRY_POINT, &data.header, task);

	data.header.uid = __kuid_val(task->real_parent->cred->uid); // override

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0)
	// Poorman's method for storing root fs path data->
	// This is to prevent us from iterating past '/'
	u32 index;
	struct dentry *root_fs_dentry = task->fs->root.dentry;
	struct vfsmount *root_fs_vfsmount = task->fs->root.mnt;
	index = 0;
	root_fs.update(&index, (void *)&root_fs_dentry);
	index += 1;
	root_fs.update(&index, (void *)&root_fs_vfsmount);
#endif

	if (!(task->flags & PF_KTHREAD) && task->mm && task->mm->exe_file) {
		data.device = __get_device_from_file(task->mm->exe_file);
		data.inode = __get_inode_from_file(task->mm->exe_file);
	}

	__send_single_event(ctx, &data, &data.header, task);

out:
	return 0;
}

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

BPF_LRU(ip_cache, FALLBACK_FIELD_TYPE(struct ip_key, u32),
	FALLBACK_FIELD_TYPE(struct ip_entry, struct ip_key));
BPF_LRU(ip6_cache, FALLBACK_FIELD_TYPE(struct ip6_key, u32),
	FALLBACK_FIELD_TYPE(struct ip_entry, struct ip6_key));

static inline bool has_ip_cache(struct ip_key *ip_key, u8 flow)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)
	struct ip_key *ip_entry = ip_cache.lookup(&ip_key->pid);
	if (ip_entry) {
		if (ip_entry->remote_port == ip_key->remote_port &&
			ip_entry->local_port == ip_key->local_port &&
			ip_entry->remote_addr == ip_key->remote_addr &&
			ip_entry->local_addr == ip_key->local_addr) {
			return true;
		} else {
			// Update entry
			ip_cache.update(&ip_key->pid, ip_key);
		}
	} else {
		ip_cache.insert(&ip_key->pid, ip_key);
	}
#else
	struct ip_key ip_key_alternate = *ip_key;
	struct ip_entry *ip_entry = NULL;

	if (flow == FLOW_RX)
	{
		ip_key->remote_port = 0;
		ip_key_alternate.local_port = 0;
	} else {
		ip_key->local_port = 0;
		ip_key_alternate.remote_port = 0;
	}

	ip_entry = ip_cache.lookup(ip_key);
	if (!ip_entry) {
		struct ip_entry new_entry = {};
		new_entry.flow = flow;
		ip_cache.insert(ip_key, &new_entry);

		ip_entry = ip_cache.lookup(&ip_key_alternate);
		if (!ip_entry) {
			ip_cache.insert(&ip_key_alternate, &new_entry);
		} else {
			return true;
		}
	} else {
		return true;
	}
#endif
	return false;
}

static inline bool has_ip6_cache(struct ip6_key *ip6_key, u8 flow)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)
	struct ip6_key *ip_entry = ip6_cache.lookup(&ip6_key->pid);
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
			ip6_cache.update(&ip6_key->pid, ip6_key);
		}
	} else {
		ip6_cache.insert(&ip6_key->pid, ip6_key);
	}
#else
	struct ip_entry *ip_entry = NULL;
	struct ip_entry new_entry;

	u16 local_port = ip6_key->local_port;
	u16 remote_port = ip6_key->remote_port;

	new_entry.flow = flow;
	if (flow == FLOW_RX) {
		ip6_key->remote_port = 0;
	} else {
		ip6_key->local_port = 0;
	}

	// Check main pkt flow and insert as needed.
	ip_entry = ip6_cache.lookup(ip6_key);
	if (ip_entry) {
		return true;
	}
	ip6_cache.insert(ip6_key, &new_entry);

	// Fix up alternate flow ports
	if (flow == FLOW_RX) {
		ip6_key->remote_port = remote_port;
		ip6_key->local_port = 0;
	} else {
		ip6_key->remote_port = 0;
		ip6_key->local_port = local_port;
	}

	// Check alt flow and insert as needed.
	ip_entry = ip6_cache.lookup(ip6_key);
	if (ip_entry) {
		return true;
	}
	ip6_cache.insert(ip6_key, &new_entry);
#endif
	return false;
}
#endif /* CACHE_UDP */

int on_do_exit(struct pt_regs *ctx, long code)
{
	struct data data = {};
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();

	if (!task) {
		goto out;
	}
	if (task->tgid != task->pid) {
		goto out;
	}

	__init_header(EVENT_PROCESS_EXIT, PP_ENTRY_POINT, &data.header);
	send_single_event(ctx, &data);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0)
	last_parent.delete(&data.header.pid);
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)
#ifdef CACHE_UDP
	// Remove burst cache entries
	//  We only need to do this for older kernels that do not have an LRU
	ip_cache.delete(&data.header.pid);
	ip6_cache.delete(&data.header.pid);
#endif /* CACHE_UDP */
#endif
out:
	return 0;
}

BPF_LRU(currsock, u64, struct sock *);
BPF_LRU(currsock2, u64, struct msghdr *);
BPF_LRU(currsock3, u64, struct sock *);

int trace_connect_v4_entry(struct pt_regs *ctx, struct sock *sk)
{
	u64 id = bpf_get_current_pid_tgid();
	currsock.update(&id, &sk);
	return 0;
}

int trace_connect_v6_entry(struct pt_regs *ctx, struct sock *sk)
{
	u64 id = bpf_get_current_pid_tgid();
	currsock.update(&id, &sk);
	return 0;
}

static inline bool check_family(struct sock *sk, u16 expected_family)
{
	u16 family = sk->__sk_common.skc_family;
	return family == expected_family;
}

static int trace_connect_return(struct pt_regs *ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	u32 pid = id >> 32;
	int ret = PT_REGS_RC(ctx);
	if (ret != 0) {
		currsock.delete(&id);
		return 0;
	}

	struct sock **skpp;
	skpp = currsock.lookup(&id);
	if (skpp == 0) {
		return 0;
	}

	struct net_data_compat net_data = {};
	struct net_data *data = &net_data.net_data;
	struct sock *skp = *skpp;
	u16 dport = skp->__sk_common.skc_dport;

	__init_header(EVENT_NET_CONNECT_PRE, PP_ENTRY_POINT, &data->header);
	data->protocol = IPPROTO_TCP;
	data->remote_port = dport;

	struct inet_sock *sockp = (struct inet_sock *)skp;
	data->local_port = sockp->inet_sport;

	if (check_family(skp, AF_INET)) {
		data->ipver = AF_INET;
		data->local_addr =
			skp->__sk_common.skc_rcv_saddr;
		data->remote_addr =
			skp->__sk_common.skc_daddr;

	} else if (check_family(skp, AF_INET6)) {
		data->ipver = AF_INET6;
		bpf_probe_read(
			&data->local_addr6, sizeof(data->local_addr6),
			skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		bpf_probe_read(&data->remote_addr6,
				   sizeof(data->remote_addr6),
				   skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);

	}

	send_single_net_event(ctx, &net_data);

	currsock.delete(&id);
	return 0;
}

int trace_connect_v4_return(struct pt_regs *ctx)
{
	return trace_connect_return(ctx);
}

int trace_connect_v6_return(struct pt_regs *ctx)
{
	return trace_connect_return(ctx);
}

int trace_skb_recv_udp(struct pt_regs *ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	u32 pid = id >> 32;

	struct sk_buff *skb = (struct sk_buff *)PT_REGS_RC(ctx);
	if (skb == NULL) {
		return 0;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0)
	// Older kernels we probe __skb_recv_datagram which can be used by
	// other protocols. We filter by sk_family or skb->protocol
	if (!skb->sk) {
		return 0;
	}
	if (!(skb->sk->sk_family == AF_INET ||
		  skb->sk->sk_family == AF_INET6)) {
		return 0;
	}
#endif
	struct udphdr *udphdr = NULL;

	// Get a pointer to the network header and the header length.
	//  We use the header length to decide if this is IPv4 or IPv6
	void *hdr = (struct iphdr *)(skb->head + skb->network_header);
	u32 hdr_len = skb->transport_header - skb->network_header;

	struct net_data_compat net_data = {};
	struct net_data *data = &net_data.net_data;

	__init_header(EVENT_NET_CONNECT_ACCEPT, PP_ENTRY_POINT, &data->header);

	data->protocol = IPPROTO_UDP;

	udphdr = (struct udphdr *)(skb->head + skb->transport_header);
	data->remote_port = udphdr->source;
	data->local_port = udphdr->dest;

	if (hdr_len == sizeof(struct iphdr)) {
		struct iphdr *iphdr = (struct iphdr *)hdr;

		data->ipver = AF_INET;
		data->local_addr = iphdr->daddr;
		data->remote_addr = iphdr->saddr;

#ifdef CACHE_UDP
		struct ip_key ip_key = {};
		ip_key.pid = data->header.pid;
		bpf_probe_read(&ip_key.remote_port, sizeof(data->remote_port),
				   &data->remote_port);
		bpf_probe_read(&ip_key.local_port, sizeof(data->local_port),
				   &data->local_port);
		bpf_probe_read(&ip_key.remote_addr,
				   sizeof(data->remote_addr),
				   &data->remote_addr);
		bpf_probe_read(&ip_key.local_addr, sizeof(data->local_addr),
				   &data->local_addr);
		if (has_ip_cache(&ip_key, FLOW_RX)) {
			return 0;
		}
#endif /* CACHE_UDP */
	} else if (hdr_len == sizeof(struct ipv6hdr)) {
		// Why IPv6 address/port is read in a different way than IPv4:
		//  - BPF C compiled to BPF instructions don't always do what we expect
		//  - especially when accessing members of a struct containing bitfields
		struct ipv6hdr *ipv6hdr = (struct ipv6hdr *)hdr;

		data->ipver = AF_INET6;
		bpf_probe_read(data->local_addr6, sizeof(uint32_t) * 4,
				   &ipv6hdr->daddr.s6_addr32);
		bpf_probe_read(data->remote_addr6, sizeof(uint32_t) * 4,
				   &ipv6hdr->saddr.s6_addr32);

#ifdef CACHE_UDP
		struct ip6_key ip_key = {};
		ip_key.pid = data->header.pid;
		bpf_probe_read(&ip_key.remote_port, sizeof(data->remote_port),
				   &data->remote_port);
		bpf_probe_read(&ip_key.local_port, sizeof(data->local_port),
				   &data->local_port);
		bpf_probe_read(ip_key.remote_addr6,
				   sizeof(data->remote_addr6),
				   &ipv6hdr->daddr.s6_addr32);
		bpf_probe_read(ip_key.local_addr6, sizeof(data->local_addr6),
				   &ipv6hdr->saddr.s6_addr32);
		if (has_ip6_cache(&ip_key, FLOW_RX)) {
			return 0;
		}
#endif /* CACHE_UDP */
	} else {
		return 0;
	}

	send_single_net_event(ctx, &net_data);

	return 0;
}

int trace_accept_return(struct pt_regs *ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	u32 pid = id >> 32;

	struct sock *newsk = (struct sock *)PT_REGS_RC(ctx);
	if (newsk == NULL) {
		return 0;
	}

	struct net_data_compat net_data = {};
	struct net_data *data = &net_data.net_data;

	__init_header(EVENT_NET_CONNECT_ACCEPT, PP_ENTRY_POINT, &data->header);
	data->protocol = IPPROTO_TCP;

	data->ipver = newsk->__sk_common.skc_family;
	bpf_probe_read(&data->local_port, sizeof(newsk->__sk_common.skc_num),
			   &newsk->__sk_common.skc_num);
	data->local_port = htons(data->local_port);
	data->remote_port =
		newsk->__sk_common.skc_dport; // network order dport

	if (check_family(newsk, AF_INET)) {
		data->local_addr =
			newsk->__sk_common.skc_rcv_saddr;
		data->remote_addr =
			newsk->__sk_common.skc_daddr;

		if (data->local_addr != 0 && data->remote_addr != 0 &&
			data->local_port != 0 && data->remote_port != 0) {
			send_single_net_event(ctx, &net_data);
		}
	} else if (check_family(newsk, AF_INET6)) {
		bpf_probe_read(
			&data->local_addr6, sizeof(data->local_addr6),
			newsk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		bpf_probe_read(&data->remote_addr6,
				   sizeof(data->remote_addr6),
				   newsk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
		send_single_net_event(ctx, &net_data);
	}
	return 0;
}

int trace_udp_recvmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg,
			  size_t length, int noblock, int flags)
{
	u64 pid;

	pid = bpf_get_current_pid_tgid();
	if (flags != MSG_PEEK) {
		currsock2.update(&pid, &msg);
		currsock3.update(&pid, &sk);
	}

	return 0;
}

int trace_udp_recvmsg_return(struct pt_regs *ctx, struct sock *sk,
				 struct msghdr *msg)
{
	int ret = PT_REGS_RC(ctx);
	u64 id = bpf_get_current_pid_tgid();
	u32 pid = id >> 32;

	struct msghdr **msgpp; // for DNS receive probe

	msgpp = currsock2.lookup(&id);
	if (msgpp == 0) {
		return 0; // missed entry
	}

	if (ret <= 0) {
		// Don't remove from bpf map currsock3
		currsock2.delete(&id);
		return 0;
	}

	// Anonymous union to guarantee enough space for final event
	union {
		struct dns_data dns_data;
		struct data dummy;
	} u = {};

	struct dns_data *data = &u.dns_data;
	__init_header(EVENT_NET_CONNECT_DNS_RESPONSE, PP_ENTRY_POINT, &data->header);

	// Send DNS info if port is DNS
	struct msghdr *msgp = *msgpp;

	const char __user *dns;
	dns = (msgp->msg_iter).iov->iov_base;

	u16 dport = (((struct sockaddr_in *)(msgp->msg_name))->sin_port);
	u16 len = ret;
	data->name_len = ret;

    if (DNS_RESP_PORT_NUM == ntohs(dport)) {
#pragma unroll
        for (int i = 1; i <= (DNS_RESP_MAXSIZE / DNS_SEGMENT_LEN) + 1;
             ++i) {
            if (len > 0 && len < DNS_RESP_MAXSIZE) {
                bpf_probe_read(&data->dns, DNS_SEGMENT_LEN, dns);

                if (i > 1) {
                    data->header.state = PP_APPEND;
                }

                send_event(ctx, data, sizeof(struct dns_data));
                len = len - DNS_SEGMENT_LEN;
                dns = dns + DNS_SEGMENT_LEN;
            } else {
                break;
            }
        }

        send_final_event(ctx, (struct data *)data);
	}

	// Don't remove from bpf map currsock3
	currsock2.delete(&id);
	return 0;
}

int trace_udp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg)
{
    u64 id;

    id = bpf_get_current_pid_tgid();
    currsock3.update(&id, &sk);
    currsock2.update(&id, &msg);
    return 0;
}

int trace_udp_sendmsg_return(struct pt_regs *ctx, struct sock *sk,
                             struct msghdr *msg)
{
    int ret = PT_REGS_RC(ctx);
    u64 id  = bpf_get_current_pid_tgid();

    struct sock **skpp;
    skpp = currsock3.lookup(&id);
    if (skpp == 0)
    {
        return 0;
    }

    struct msghdr **msgpp;
    msgpp = currsock2.lookup(&id);

    if (ret <= 0)
    {
        currsock3.delete(&id);
        currsock2.delete(&id);
        return 0;
    }

	struct net_data_compat net_data = {};
	struct net_data *data = &net_data.net_data;
    __init_header(EVENT_NET_CONNECT_PRE, PP_ENTRY_POINT, &data->header);
    data->protocol = IPPROTO_UDP;
    // The remote addr could be in the msghdr::msg_name or on the sock
    bool addr_in_msghr = false;

    // get ip version
    struct sock *skp = *skpp;
    data->ipver = skp->__sk_common.skc_family;

    if (msgpp)
    {
        void * 	msg_name;
        int 	msg_namelen;

        bpf_probe_read(&msg_name, sizeof(void *), &(*msgpp)->msg_name);
        bpf_probe_read(&msg_namelen, sizeof(int), &(*msgpp)->msg_namelen);

        if (msg_name && msg_namelen > 0)
        {
            if (check_family(skp, AF_INET) && msg_namelen >= sizeof(struct sockaddr_in))
            {
                struct sockaddr_in addr_in;
                bpf_probe_read(&addr_in, sizeof(addr_in), msg_name);
                data->remote_port = addr_in.sin_port;
                data->remote_addr = addr_in.sin_addr.s_addr;

                addr_in_msghr = true;
            }
            else if (check_family(skp, AF_INET6) && msg_namelen >= sizeof(struct sockaddr_in6))
            {
                struct sockaddr_in6 addr_in;
                bpf_probe_read(&addr_in, sizeof(addr_in), msg_name);
                data->remote_port = addr_in.sin6_port;
                bpf_probe_read(
                    &data->remote_addr6, sizeof(data->remote_addr6),
                    &addr_in.sin6_addr);

                addr_in_msghr = true;
            }
        }
    }

    bpf_probe_read(&data->local_port, sizeof(skp->__sk_common.skc_num),
                   &skp->__sk_common.skc_num);
    data->local_port = htons(data->local_port);

    if (!addr_in_msghr)
    {
        data->remote_port =
            skp->__sk_common.skc_dport; // already network order
    }

    if (check_family(skp, AF_INET))
    {
        if (!addr_in_msghr)
        {
            data->remote_addr =
                skp->__sk_common.skc_daddr;
        }

        data->local_addr =
            skp->__sk_common.skc_rcv_saddr;

#ifdef CACHE_UDP
        struct ip_key ip_key = {};
        ip_key.pid = data->header.pid;
        bpf_probe_read(&ip_key.remote_port,
                       sizeof(data->remote_port),
                       &data->remote_port);
        bpf_probe_read(&ip_key.local_port, sizeof(data->local_port),
                       &data->local_port);
        bpf_probe_read(&ip_key.remote_addr,
                       sizeof(data->remote_addr),
                       &data->remote_addr);
        bpf_probe_read(&ip_key.local_addr, sizeof(data->local_addr),
                       &data->local_addr);

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
            bpf_probe_read(
                &data->remote_addr6, sizeof(data->remote_addr6),
                &(skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32));
        }

        bpf_probe_read(
            &data->local_addr6, sizeof(data->local_addr6),
            &(skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32));

#ifdef CACHE_UDP
        struct ip6_key ip_key = {};
        ip_key.pid = data->header.pid;
        bpf_probe_read(&ip_key.remote_port,
                       sizeof(data->remote_port),
                       &data->remote_port);
        bpf_probe_read(&ip_key.local_port, sizeof(data->local_port),
                       &data->local_port);
        bpf_probe_read(
            ip_key.remote_addr6, sizeof(data->remote_addr6),
            &data->remote_addr6);
        bpf_probe_read(
            ip_key.local_addr6, sizeof(data->local_addr6),
            &data->local_addr6);
        if (has_ip6_cache(&ip_key, FLOW_TX))
        {
            goto out;
        }
#endif /* CACHE_UDP */
    }

	send_single_net_event(ctx, &net_data);

out:
	currsock3.delete(&id);
	currsock2.delete(&id);
	return 0;
}

// TODO: The collector is not currently handling the proxy event, so dont't bother sending it
//        this needs to be reworked to send multiple events (similar to the file events)
//int trace_tcp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg)
//{
//	struct dns_data data = {};
//	int cmd = 0;
//	int offset = 0;
//
//	// filter proxy traffic
//	const char __user *p = (msg->msg_iter).iov->iov_base;
//	__kernel_size_t cmd_len = (msg->msg_iter).iov->iov_len;
//
//	if ((p[0] == 'G') && (p[1] == 'E') && (p[2] == 'T') && (p[4] != '/')) {
//		cmd = 0;
//		offset = 3;
//		goto CATCH;
//	}
//	if ((p[0] == 'P') && (p[1] == 'U') && (p[2] == 'T') && (p[4] != '/')) {
//		cmd = 1;
//		offset = 3;
//		goto CATCH;
//	}
//	if ((p[0] == 'P') && (p[1] == 'O') && (p[2] == 'S') && (p[3] == 'T') &&
//		(p[5] != '/')) {
//		cmd = 2;
//		offset = 4;
//		goto CATCH;
//	}
//	if ((p[0] == 'D') && (p[1] == 'E') && (p[2] == 'L') && (p[3] == 'E') &&
//		(p[4] == 'T') && (p[5] == 'E') && (p[7] != '/')) {
//		cmd = 3;
//		offset = 6;
//		goto CATCH;
//	}
//	if ((p[0] == 'C') && (p[1] == 'O') && (p[2] == 'N') && (p[3] == 'N') &&
//		(p[4] == 'E') && (p[5] == 'C') && (p[6] == 'T') && (p[8] != '/')) {
//		cmd = 4;
//		offset = 7;
//		goto CATCH;
//	}
//	return 0;
//
//CATCH:
//	__init_header(EVENT_NET_CONNECT_WEB_PROXY, PP_NO_EXTRA_DATA, &data.header);
//
//	data.name_len = cmd_len;
//
//	// TODO: calculate real url length
//	int len = PROXY_SERVER_MAX_LEN;
//
//	data.ipver = sk->__sk_common.skc_family;
//	bpf_probe_read(&data.local_port, sizeof(sk->__sk_common.skc_num),
//			   &sk->__sk_common.skc_num);
//	data.local_port = htons(data.local_port);
//	data.remote_port = sk->__sk_common.skc_dport;
//
//	if (check_family(sk, AF_INET)) {
//		data.local_addr =
//			sk->__sk_common.skc_rcv_saddr;
//		data.remote_addr =
//			sk->__sk_common.skc_daddr;
//	} else if (check_family(sk, AF_INET6)) {
//		bpf_probe_read(
//			&data.local_addr6, sizeof(data.local_addr6),
//			sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
//		bpf_probe_read(&data.remote_addr6,
//				   sizeof(data.remote_addr6),
//				   sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
//	}
//
//	p = p + offset + 1;
//#pragma unroll
//	for (int i = 1; i <= (PROXY_SERVER_MAX_LEN / DNS_SEGMENT_LEN) + 1;
//		 ++i) {
//		if (len > 0 && len < DNS_RESP_MAXSIZE) {
//			data.dns_flag = 0;
//			bpf_probe_read(&data.dns, DNS_SEGMENT_LEN, p);
//			if (i == 1)
//				data.dns_flag = DNS_SEGMENT_FLAGS_START;
//			if (len <= 40)
//				data.dns_flag |= DNS_SEGMENT_FLAGS_END;
//
//			send_event(ctx, &data, sizeof(data));
//			len = len - DNS_SEGMENT_LEN;
//			p = p + DNS_SEGMENT_LEN;
//		} else {
//			break;
//		}
//	}
//
//	return 0;
//}
