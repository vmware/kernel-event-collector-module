# Dynamic Security Linux Kernel Module

## Overview
The DynSec kmod was originally developed to first perform access control
requests on a small set of LSM hooks where fanotify could not on older
kernels. This was extended to other LSM hooks geared towards other
file operations other than OPEN.

Other than access controls the kmod provides audit-like events for
process creations and exits for easier userspace process tracking. There
are several event reporting options and can go into a full audit mode
with no access control requests required.

Some events may contain PreActions or Intents. Intents are the common
userspace entrypoints that may contain more helpful context clues before
hitting the event requesting acess control. This is helpful for file
create and rename operations.

### Intent
Provide fanotify-like events and access controls to LSM hooks. Primarily
for kernels that do not have sleepable BPF LSM hooks that.
However we do not currently install open file descriptors to a connected
client.


## Supported Kernel Versions
DynSec currently support EL7 and EL8 based distros. However this could
support other kernels with some better kver checks. This does compile
for some EL6 kernels but if it worked, would be at a limited capacity.


## Events
Every event has a core header that tells us it's payload, metadata,
and report flags. And provides just enough data to send a response
back to the kernel if it's needed. Report flags tells how to work
with the event like an access control, is an intent, the access control
was cached or other context clues.

### PreActions/Intents
The last known event is cached on a per-task level basis with it event
unique identifer some other metadata. The regular event may tell us if
there was an intent event by providing us the intent event's id. PreActions
are always enqueued before the regular event.

In the absence of `CONFIG_SECURITY_PATH` system call hooks are used to
get normalized paths. However for better portability tracepoints or the
usage of `CONFIG_SECURITY_PATH` oriented hooks would be less invasive
to the end user and kernel. Having preactions utilize `security_path_*`
based hooks is not feasible on most RHEL based kernels.

## Access Control Response
Like fanotify you `write` your response back to the file but also allows
you to provide primitive per-task level access control caching options.

## Kernel Object Labeling
Currently we label tasks in a LRU-ish mechanism so they are always
on default secure if the get evicted. Task labeling currently also is
the magic to tying Intents to other events. Relabeling tasks occurs
typically can happen on it's next access control request. 

Currently the caching options still send the events but may not always
stall or pause the waiting task. There are strict cache options that
can allow the task to safely evict their own options to re-enable
access control requests. This is ensure we allow for primitive
default-secure options that doesn't require userspace intervention or
some `reference monitor` to make a decision.

### Future Kernel Object Labeling
In the future the task labeling options may be used to ignore events
from the kernel. However it is still best to do that in userspace first
before opting to do that at the kernel level for stronger auditing.

To allow for kernel object labeling similar to the BPF LSM inode object
labeling. Labeling `struct inode` might be another step. However reason
for labeling inodes probably would gear towards computing trust
and how an inode's label may affect a task's label on a per-event type
basis.

## Things That Need Work
 - Better `#ifdef` support aka kernel version support
 - More portable PreAction options
 - More Feature Testing
 - Per-client config options
 - Limited multiple client support
