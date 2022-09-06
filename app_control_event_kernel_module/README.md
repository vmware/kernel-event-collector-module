# app-control-event-kernel-module

# App Control Event Kernel Module

## Overview
This project was originally developed to first perform access control
requests on a small set of LSM hooks where fanotify could not on older
kernels. This was extended to other LSM hooks geared towards protecting
other file operations.

Other than access controls, the kmod provides audit-like events for
process creations and exits for easier userspace process tracking. There
are several event reporting options and can go into a full audit mode
with no access control requests required.

Some events may contain PreActions or Intents. Intents are the common
userspace entrypoints that may contain more helpful context clues before
hitting the requesting acess control.

## Supported Kernel Versions
The kernel module currently support EL7, EL8 and EL9 based distros. However
this could support other kernels with some better kver checks. Source does
compile for some EL6 kernels but is not supported.

## Events
Every event has a core header that tells us it's payload, metadata,
and report flags. And provides just enough data to send a response
back to the kernel if it's needed. Report flags tells how to work
with the event like an access control, is an intent, the access control
was cached or other context clues.

### PreActions/Intents
The last known event is cached on a per-task level basis with it event
unique identifier some other metadata. The regular event may tell us if
there was an intent event by providing us the intent event's id. PreActions
are always enqueued before the regular event.

In the absence of `CONFIG_SECURITY_PATH` system call hooks are used to
get normalized paths. However for better portability tracepoints or the
usage of `CONFIG_SECURITY_PATH` oriented hooks would be less invasive
to the end user and kernel.

## Inode Read Only Cache
File open events that stall have the ability to determine whether a file
should not stall until it is opened for write. This can only be handled
on the access control response to file open events.

## Access Control Response
Like fanotify you `write` your response back to the file but also allows
you to provide primitive per-task level access control caching options.

Inode read-only cache flags can be passed as well here.

## Kernel Object Labeling
Currently we label tasks in a LRU-ish mechanism so they are always
on default secure if they get evicted. Task labeling currently also is
the magic to tying Intents to other events. Relabeling tasks
typically can happen on it's next access control request.

Currently the labeling options still send the events but may not always
stall or pause the waiting task. There are strict cache options that
can allow the task to safely evict their own options to re-enable
access control requests. This is to ensure we allow for primitive
default-secure options that do not require userspace intervention or
some `reference monitor` to make a decision.

## Process Labeling
The kmod provides the ability to disable stalling or kernel module level
ignoring of events. These are meant to be performance optimizations when
the kernel module has stalling enabled. If stalling is disabled ignoring
events is much more efficient at the userspace level for most cases.

Forked children on lose the parent's label unless inheritability options
are set or are explicitly labeled from userspace.

### Inherit
When a main process is labeled it new children or not yet labeled children
have the capability to inherit the label from it's parent. When a child
process inherits the parent label, the inheritability option is unset.
Basically this option ensures the labeling may exist for children but not
for grand children.

Child threads will inherit the label of the main thread. Regardless of
inheritibility options. This form of inheritance is really just a copy,
inorder to maintain similar labeling behavior until it requested to
change.

### Inherit Recursive
When the inherit recursive option is set in a label, it will retain the
inherit options that normally are unset on a fork. This is the greediest
form of label retention and is meant to label process trees.

### statistics in proc file
The module creates an entry in the proc file system 
/proc/cb\_appc\_events\_NNNNN\_stats file contains the following
information:
 * dynsec config:    shows current value of bypass mode, stall mode etc.
 * stall queue size: shows current size of stall queue.
 * stall timeout events: shows number of continuous events for which user
                         space does not respond within 5 seconds.
 * access denied events: shows number of events for which access
                         was denied.
 * stall table average wait time: time average for 64 events (in msec)
                       Each value is amount of time a event stays in the
                       stall queue of kernel module.
 * stall table maximum wait time: maximum time spend in the stall queue
                       in milliseconds
 * StallTable buckets: number of (non-zero) entries in stall table hash buckets.
                       hash bucket number and number of entries
 * TaskCache buckets : number of (non-zero) entries in task cache hash buckets.
                       hash bucket number and number of entries
 * InodeCache buckets: number of (non-zero) entries in inode cache hash buckets.
                       hash bucket number and number of entries
 
### Dynamic debugging
The source code uses dynamic debug macros which can be enabled at run
time to trace the code flow. This works only if the kernel is compiled
with CONFIG\_DYNAMIC\_DEBUG flag.
Refer to dynamic-debug-howto.txt from kernel Documentation.

Use following procedure to tracing the code path:
1. mount the debug file system if it not mounted already.
   mount  | grep -i debugfs
   mount -t debugfs nodev /sys/kernel/debug

2. configure default console log level if needed.
   echo 8 > /proc/sys/kernel/printk

3. Sample ways to debug kernel module

 a. debug inode cache
    echo 'file inode_cache.c +p' > /sys/kernel/debug/dynamic_debug/control

 b. debug path appending
    echo 'file path_utils.c +p' > /sys/kernel/debug/dynamic_debug/control

 c. debug protect path matching
    echo 'file protect.c +p' > /sys/kernel/debug/dynamic_debug/control

 d. debug task labeling
    echo 'module cb_appc_events_<NNNNN> file task_cache.c +p' > /sys/kernel/debug/dynamic_debug/control

 e. debug stalling code 
    echo 'module cb_appc_events_<NNNNN> file wait.c +p' > /sys/kernel/debug/dynamic_debug/control

   In order to avoid conflicts with files having same names, module name can be prepended to  file.

  OR

  f. debug all dynamic logs
    echo 'module cb_appc_events_<NNNNN> +p' > /sys/kernel/debug/dynamic_debug/control

4. Check kernel logs using dmesg command.
