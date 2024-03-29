/* Copyright 2021 VMware Inc.  All rights reserved. */
/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

#pragma once

//
// Contains missing macro defintions and perhaps frequently
// used inline functions are used.
//

#define AF_INET     2       /* internetwork: UDP, TCP, etc. */
#define AF_INET6    10      /* IPv6 */

// Ignore compat syscalls for now
#if defined(bpf_target_arm64)
#define __NR_execve 221
#define __NR_execveat 281
#elif defined(bpf_target_x86)
#define __NR_execve 59
#define __NR_execveat 322
#endif

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
#define BTRFS_SUPER_MAGIC       0x9123683E
#define NSFS_MAGIC              0x6e736673


#define PROT_EXEC               0x4                /* Page can be executed.  */

// TODO: Fix architecture specific macro definitions
#define MAP_DENYWRITE          0x00800                /* ETXTBSY */
#define MAP_EXECUTABLE         0x01000                /* Mark it as an executable.  */
#define MAP_PRIVATE            0x00002
#define MAP_FIXED              0x00010

#define     S_IFMT              00170000
#define     S_IFREG             0100000
#define     S_ISREG(m)   (((m) & S_IFMT) == S_IFREG)

/* File is opened for execution with sys_execve / sys_uselib */
#define FMODE_EXEC      ((fmode_t)0x20)
#define FMODE_CREATED   ((fmode_t)0x100000)
#define FMODE_NONOTIFY  ((fmode_t)0x4000000)
#define FMODE_NOACCOUNT ((fmode_t)0x20000000)

#define O_ACCMODE       00000003
#define O_RDONLY        00000000
#define O_WRONLY        00000001
#define O_RDWR          00000002

#define PF_KTHREAD      0x00200000  /* I am a kernel thread */

#define MSG_PEEK    2

#define MINORBITS   20
#define MINORMASK   ((1U << MINORBITS) - 1)

#define MAJOR(dev)  ((unsigned int) ((dev) >> MINORBITS))
#define MINOR(dev)  ((unsigned int) ((dev) & MINORMASK))

#ifndef __user
#define __user
#endif /* ! __user */

#define s6_addr32       in6_u.u6_addr32

// Missing inlined functions

static __always_inline u32 new_encode_dev(dev_t dev)
{
    unsigned major = MAJOR(dev);
    unsigned minor = MINOR(dev);

    return (minor & 0xff) | (major << 8) | ((minor & ~0xff) << 12);
}

// Custom structs

// Handle pid_link before migration of pid_thread in task_struct. Roughly
// targets RHEL8.1+ and 4.19.x+ kernels.
struct task_struct___pdlink {
    struct pid_link {
        struct hlist_node node;
        struct pid *pid;
    } pids[PIDTYPE_MAX];
};
