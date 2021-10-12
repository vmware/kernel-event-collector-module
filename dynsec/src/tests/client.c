// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 VMware, Inc. All rights reserved.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <signal.h>
#include <sys/mman.h>
#include <signal.h>
#include <stdbool.h>
#include <limits.h>

#include "print.h"
#include "client.h"

#define PROC_DEVICE_FILE "/proc/devices"

// May want to be dynamic or more precise for stacking/branding
#define KMOD_BASE_NAME "dynsec"


// Default callbacks for event hooks
static enum DYNSEC_EAT do_print_raw(struct dynsec_client *client,
                        const struct dynsec_msg_hdr *hdr)
{
    print_event_raw((struct dynsec_msg_hdr *)hdr);
    return DYNSEC_EAT_DEFAULT;
}
static enum DYNSEC_EAT discard_dummy_cb(struct dynsec_client *client,
                    const struct dynsec_msg_hdr *hdr, bool may_override)
{
    return DYNSEC_EAT_DEFAULT;
}

// Default callbacks for event processing loop
static const struct dynsec_client_ops default_ops = {
    .event_hook = do_print_raw,
    .event_discarded_hook = discard_dummy_cb,
    .release_hook = NULL,
};

static int find_device_major(struct client_device *device)
{
    FILE *fh = NULL;
    char *line = NULL;
    size_t len = 0;
    int major = -ENOENT;
    char buf[MAX_KMOD_NAME_LEN];

    if (device && device->proc_file) {
        fh = fopen(device->proc_file, "r");
    }

    if (!fh) {
        return -EINTR;
    }

    memset(device->kmod_name, 0, sizeof(device->kmod_name));

    if (!device->proc_file) {
        if (fh) {
            fclose(fh);
            fh = NULL;
        }
        return -EINVAL;
    }

    while (true) {
        int local_major;
        ssize_t nread = getline(&line, &len, fh);

        if (nread == -1) {
            break;
        }
        memset(buf, 0, sizeof(buf));

        sscanf(line, "%d %s", &local_major, buf);
        if (strstr(buf, device->kmod_search_str)) {
            device->major = local_major;
            strncpy(device->kmod_name, buf, sizeof(device->kmod_name));
            break;
        }
    }

    if (fh) {
        fclose(fh);
        fh = NULL;
    }

    if (line) {
        free(line);
        line = NULL;
    }
    return major;
}


void dynsec_client_register(struct dynsec_client *client,
                        uint32_t default_cache_flags,
                        const struct dynsec_client_ops *ops,
                        void *private_data)
{
    if (!client) {
        return;
    }

    memset(client, 0, sizeof(*client));

    client->cache_flags = default_cache_flags;
    if (ops) {
        client->ops = ops;
    } else {
        client->ops = &default_ops;
    }
    client->private_data = private_data;

    client->fd = -1;
    client->device.proc_file = PROC_DEVICE_FILE;
    client->device.kmod_search_str = KMOD_BASE_NAME;

    find_device_major(&client->device);
    if (!client->device.major && !client->device.minor) {
        fprintf(stderr, "Invalid device: %d:%d\n", client->device.major,
                client->device.minor);
        return;
    }
}


static int create_chrdev(struct client_device *device,
                         const char *dev_path)
{
    dev_t dev = 0;
    int ret;
    struct stat sb;
    bool reuse_device = false;

    if (!device || !dev_path || !*dev_path) {
        return -EINVAL;
    }

    dev = makedev(device->major, device->minor);
    ret = stat(dev_path, &sb);
    if (!ret) {
        if (S_ISCHR(sb.st_mode)) {
            if (sb.st_rdev == dev) {
                reuse_device = true;
            } else {
                unlink(dev_path);
            }
        } else {
            // Don't delete a regular file
            fprintf(stderr, "Non chrdev file exists for: %s\n",
                    dev_path);
            return -EEXIST;
        }
    }

    ret = mknod(dev_path, S_IFCHR|S_IRUSR|S_IWUSR, dev);
    if (!ret || (ret < 0 && errno == EEXIST)) {
        ret = open(dev_path, O_RDWR | O_CLOEXEC);
        if (ret < 0) {
            ret = -errno;
            fprintf(stderr, "Unable to open(%s,O_RDWR| O_CLOEXEC) = %m\n",
                    dev_path);
        } else {
            if (!reuse_device) {
                unlink(dev_path);
            }
        }
    } else {
        ret = -errno;
        // Likely file system doesn't support creating char devices
        // OR we are in a container/unpriv usernamespace etc..
        // If in container, create externally and bind mount to container.
    }
    return ret;
}

void dynsec_client_shutdown(struct dynsec_client *client)
{
    if (!client) {
        return;
    }

    client->tracking.shutdown = true;

    if (client->fd >= 0) {
        close(client->fd);
        client->fd = -1;
    }
}

void dynsec_client_reset(struct dynsec_client *client)
{
    if (!client) {
        return;
    }
    dynsec_client_shutdown(client);

    if (client->ops->release_hook) {
        client->ops->release_hook(client);
    }
    memset(client, 0, sizeof(*client));
}

int dynsec_client_connect(struct dynsec_client *client,
                          int verbosity, int debug, bool is_tracing)
{
    if (!client) {
        return -EINVAL;
    }

    dynsec_client_shutdown(client);

    if (!client->device.major && !client->device.minor) {
        return -EINVAL;
    }

    // Perhaps use a randomly generated file name beforehand
    client->fd = create_chrdev(&client->device, client->device.kmod_name);
    if (client->fd < 0) {
        client->fd = create_chrdev(&client->device, client->device.kmod_search_str);
    }
    if (client->fd < 0) {
        client->fd = -errno;
    } else {
        client->tracking.shutdown = false;
        client->tracking.verbosity = verbosity;
        client->tracking.debug = debug;
        client->tracking.is_tracing = is_tracing;
        client->tracking.follow_progeny = false;
    }

    return client->fd;
}

#define client_is_shutdown(client) \
    ((client)->tracking.shutdown || (client)->fd < 0)

bool dynsec_client_is_shutdown(struct dynsec_client *client)
{
    if (!client) {
        return true;
    }
    return client_is_shutdown(client);
}

static int respond_to_access_request(int fd, struct dynsec_msg_hdr *hdr,
                              int response_type, int cache_flags)
{
    ssize_t ret;
    struct dynsec_response response = {
        .req_id = hdr->req_id,
        .event_type = hdr->event_type,
        .tid = hdr->tid,
        .response = response_type,
        .cache_flags = cache_flags,
    };

    if (fd < 0) {
        return -EBADF;
    }

    ret = write(fd, &response, sizeof(response));
    if (ret < 0) {
        return -errno;
    }
    if (ret != sizeof(response)) {
        return (int)ret;
    }
    return 0;
}


static bool is_empty_trace_list(struct client_tracking *track)
{
    int i;

    for (i = 0; i < MAX_TRACK_PIDS; i++) {
        if (track->progeny[i]) {
            if (track->debug)
                fprintf(stderr, "NOT EMPTY: [%d]%d\n", i, track->progeny[i]);
            return false;
        }
    }
    return true;
}

static bool insert_trace_list(struct client_tracking *track, pid_t pid)
{
    int i;

    for (i = 0; i < track->max_index; i++) {
        if (!track->progeny[i]) {
            track->progeny[i] = pid;
            if (track->debug)
                fprintf(stderr, "INSERT: [%d]%d\n", i, track->progeny[i]);
            return true;
        }
    }

    if (i == track->max_index && track->max_index < MAX_TRACK_PIDS) {
        track->max_index += 1;
        track->progeny[track->max_index] = pid;
        if (track->debug)
            fprintf(stderr, "INSERT NEW MAX: [%d]%d\n", i,
                    track->progeny[track->max_index]);
        return true;
    } else {
        return false;
    }
}

static bool in_trace_list(struct client_tracking *track, pid_t pid, bool remove)
{
    int i;
    int prev_valid = 0;

    for (i = 0; i <= track->max_index && i < MAX_TRACK_PIDS; i++) {
        if (!track->progeny[i]) {
            continue;
        }
        if (track->progeny[i] == pid) {
            if (remove) {
                if (track->debug)
                    fprintf(stderr, "REMOVING: [%d]%d max_index:%d\n", i, pid,
                            track->max_index);
                if (i == track->max_index) {
                    track->max_index = prev_valid;
                }
                track->progeny[i] = 0;
            }
            return true;
        } else {
            prev_valid = i;
        }
    }

    return false;
}

static bool pre_process_task_event(struct dynsec_client *client,
                                   struct dynsec_task_umsg *task_msg)
{
    struct client_tracking *track = NULL;
    bool is_trace_event = false;

    if (!client || !client->tracking.is_tracing) {
        return false;
    }
    track = &client->tracking;

    if (task_msg->hdr.event_type == DYNSEC_EVENT_TYPE_EXIT) {
        if (in_trace_list(track, task_msg->msg.task.pid, true)) {
            is_trace_event = true;
        }
        if (is_empty_trace_list(track)) {
            dynsec_client_shutdown(client);
        }
    } else if (task_msg->hdr.event_type == DYNSEC_EVENT_TYPE_CLONE) {
        if (track->follow_progeny) {
            if (in_trace_list(track, task_msg->msg.task.ppid, false)) {
                is_trace_event = true;
                insert_trace_list(track, task_msg->msg.task.pid);
            }
        }
    }

    return is_trace_event;
}

static bool event_in_trace_list(struct dynsec_client *client,
                                struct dynsec_msg_hdr *hdr)
{
    struct client_tracking *track = NULL;

    if (!client || !client->tracking.is_tracing) {
        return false;
    }
    track = &client->tracking;

    switch (hdr->event_type)
    {
    case DYNSEC_EVENT_TYPE_EXEC:
        return in_trace_list(track, hdr->tid, false)
            || in_trace_list(track, ((struct dynsec_exec_umsg *)hdr)->msg.task.pid, false);

    case DYNSEC_EVENT_TYPE_UNLINK:
    case DYNSEC_EVENT_TYPE_RMDIR:
        return in_trace_list(track, hdr->tid, false)
            || in_trace_list(track, ((struct dynsec_unlink_umsg *)hdr)->msg.task.pid, false);

    case DYNSEC_EVENT_TYPE_RENAME:
        return in_trace_list(track, hdr->tid, false)
            || in_trace_list(track, ((struct dynsec_rename_umsg *)hdr)->msg.task.pid, false);

    case DYNSEC_EVENT_TYPE_SETATTR:
        return in_trace_list(track, hdr->tid, false)
            || in_trace_list(track, ((struct dynsec_setattr_umsg *)hdr)->msg.task.pid, false);

    case DYNSEC_EVENT_TYPE_CREATE:
    case DYNSEC_EVENT_TYPE_MKDIR:
        return in_trace_list(track, hdr->tid, false)
            || in_trace_list(track, ((struct dynsec_create_umsg *)hdr)->msg.task.pid, false);

    case DYNSEC_EVENT_TYPE_OPEN:
    case DYNSEC_EVENT_TYPE_CLOSE:
        return in_trace_list(track, hdr->tid, false)
            || in_trace_list(track, ((struct dynsec_file_umsg *)hdr)->msg.task.pid, false);

    case DYNSEC_EVENT_TYPE_MMAP:
        return in_trace_list(track, hdr->tid, false)
            || in_trace_list(track, ((struct dynsec_mmap_umsg *)hdr)->msg.task.pid, false);

    case DYNSEC_EVENT_TYPE_LINK:
        return in_trace_list(track, hdr->tid, false)
            || in_trace_list(track, ((struct dynsec_link_umsg *)hdr)->msg.task.pid, false);

    case DYNSEC_EVENT_TYPE_SYMLINK:
        return in_trace_list(track, hdr->tid, false)
            || in_trace_list(track, ((struct dynsec_symlink_umsg *)hdr)->msg.task.pid, false);

    case DYNSEC_EVENT_TYPE_PTRACE:
        return in_trace_list(track, hdr->tid, false)
            || in_trace_list(track, ((struct dynsec_ptrace_umsg *)hdr)->msg.source.pid, false)
            || in_trace_list(track, ((struct dynsec_ptrace_umsg *)hdr)->msg.target.pid, false);

    case DYNSEC_EVENT_TYPE_SIGNAL:
        return in_trace_list(track, hdr->tid, false)
            || in_trace_list(track, ((struct dynsec_signal_umsg *)hdr)->msg.source.pid, false)
            || in_trace_list(track, ((struct dynsec_signal_umsg *)hdr)->msg.target.pid, false);

    case DYNSEC_EVENT_TYPE_CLONE:
    case DYNSEC_EVENT_TYPE_EXIT:
        return pre_process_task_event(client, (struct dynsec_task_umsg *)hdr);

    default:
        break;
    }

    return false;
}

// Implicitly enables tracing
void dynsec_client_track_pid(struct dynsec_client *client, pid_t pid,
                             bool follow_progeny)
{
    if (!client) {
        return;
    }
    client->tracking.is_tracing = true;
    client->tracking.follow_progeny = follow_progeny;
    insert_trace_list(&client->tracking, pid);
}


int dynsec_client_read_events(struct dynsec_client *client)
{
#define DEFAULT_POLL_TIMEOUT_MS 50
#define MAX_POLL_TIMEOUT_MS 300

    int timeout_ms = DEFAULT_POLL_TIMEOUT_MS;
    char *buf = NULL;

    if (!client || client_is_shutdown(client)) {
        return -EFAULT;
    }
    buf = client->buf;
    memset(buf, 'A',  MAX_BUF_SZ);

    while (1)
    {
        ssize_t bytes_read = 0;
        ssize_t bytes_parsed = 0;
        struct pollfd pollfd = {
             .fd = client->fd,
             .events = POLLIN | POLLOUT,
             .revents = 0,
        };
        int events_on_read_count = 0;
        int ret;


        if (client_is_shutdown(client)) {
            break;
        }

        ret = poll(&pollfd, 1, timeout_ms);
        // Check for shutdown first
        if (client_is_shutdown(client)) {
            break;
        }
        if (ret < 0) {
            // 
            // if (errno == EINTR) {
            //     continue;
            // }
            return -errno;
        }

        // Timeout
        if (ret == 0) {
            timeout_ms += DEFAULT_POLL_TIMEOUT_MS;
            if (timeout_ms > MAX_POLL_TIMEOUT_MS) {
                timeout_ms = MAX_POLL_TIMEOUT_MS;
            }
            continue;
        }
        if (ret != 1 || !(pollfd.revents & POLLIN)) {
            // fprintf(stderr, "poll ret:%d revents:%#x\n",
            //         ret, pollfd.revents);
            break;
        }
        // Reset timeout even if we get -EAGAIN on read
        timeout_ms = DEFAULT_POLL_TIMEOUT_MS;

        bytes_read = read(pollfd.fd, buf, MAX_BUF_SZ);
        if (bytes_read <= 0) {
            if (bytes_read == -1 && errno == EAGAIN) {
                continue;
            }
            break;
        }

        while (bytes_parsed < bytes_read)
        {
            struct dynsec_msg_hdr *hdr = (struct dynsec_msg_hdr *)(buf + bytes_parsed);
            enum DYNSEC_EAT eaten = DYNSEC_EAT_KEEP;

            events_on_read_count++;

            // TODO: Require implemented callbacks do this
            if (hdr->report_flags & DYNSEC_REPORT_STALL) {
                respond_to_access_request(client->fd, hdr,
                                          DYNSEC_RESPONSE_ALLOW,
                                          client->cache_flags);
            }

            // Check if we are discarding this event via tracing
            if (client->tracking.is_tracing && !event_in_trace_list(client, hdr)) {
                eaten = DYNSEC_EAT_DISCARD;

                // Discard on trace. Optionally allow this event to
                // not be discarded.
                if (client->ops->event_discarded_hook) {
                    eaten = client->ops->event_discarded_hook(client, hdr, true);
                }
            }

            if (eaten == DYNSEC_EAT_KEEP) {
                // Regular Event Callback
                if (client->ops->event_hook) {
                    eaten = client->ops->event_hook(client, hdr);

                    // Regular Discard Callback
                    if (eaten == DYNSEC_EAT_DISCARD) {
                        if (client->ops->event_discarded_hook) {
                            (void)client->ops->event_discarded_hook(client, hdr, false);
                        }
                    }
                }
            }
            if (eaten == DYNSEC_EAT_SHUTDOWN) {
                dynsec_client_shutdown(client);
            }

            bytes_parsed += hdr->payload;
            if (client->tracking.shutdown) {
                goto out;
            }
        }

        if (client->tracking.shutdown) {
            break;
        }

        // Observe bytes committed to
        memset(buf, 'A', bytes_read);
    }

out:
    dynsec_client_shutdown(client);
    return 0;
}


static int __dynsec_client_dump_one(struct dynsec_client *client,
                                    pid_t pid, uint16_t opts,
                                    struct dynsec_task_dump_data *data)
{
    int ret = -EINVAL;
    struct dynsec_task_dump *task_dump;


    // Fill in storage blob with 'A' for helpful debugging on dumps
    memset(data, 'A', sizeof(*data));
    task_dump = (struct dynsec_task_dump *)data;
    task_dump->hdr.size = sizeof(*data);
    task_dump->hdr.pid = pid;
    task_dump->hdr.opts = opts;

    ret = ioctl(client->fd, DYNSEC_IOC_TASK_DUMP, task_dump);
    if (ret < 0) {
        ret = -errno;
    }
    return ret;
}

static int __dynsec_client_dump_all(struct dynsec_client *client, pid_t pid,
                                    uint16_t opts)
{
    struct dynsec_task_dump_all task_dump_all = {
        .hdr = {
            .size = sizeof(task_dump_all),
            .pid = pid,
            .opts = opts,
        },
    };
    return ioctl(client->fd, DYNSEC_IOC_TASK_DUMP_ALL, &task_dump_all);
}

// Dump the nearest matching thread or process
int dynsec_client_dump_one_thread(struct dynsec_client *client, pid_t tid,
                                  struct dynsec_task_dump_data *data)
{
    if (!client || !data) {
        return -EINVAL;
    }
    return __dynsec_client_dump_one(client, tid, DUMP_NEXT_THREAD, data);
}

// Dumps the nearest matching process
int dynsec_client_dump_one_process(struct dynsec_client *client, pid_t pid,
                                   struct dynsec_task_dump_data *data)
{
    if (!client || !data) {
        return -EINVAL;
    }
    return __dynsec_client_dump_one(client, pid, DUMP_NEXT_TGID, data);
}

// Dumps everything into event queue
int dynsec_client_dump_all_processes(struct dynsec_client *client)
{
    if (!client) {
        return -EINVAL;
    }
    return __dynsec_client_dump_all(client, 1, DUMP_NEXT_TGID);
}

int dynsec_client_dump_all_threads(struct dynsec_client *client)
{
    if (!client) {
        return -EINVAL;
    }
    return __dynsec_client_dump_all(client, 1, DUMP_NEXT_THREAD);
}


int dynsec_client_get_config(struct dynsec_client *client,
                             struct dynsec_config *config)
{
    int ret;

    if (!client || !config) {
        return -EINVAL;
    }

    ret = ioctl(client->fd, DYNSEC_IOC_GET_CONFIG, config);
    if (ret < 0) {
        ret = -errno;
    }
    return ret;
}


static int __dynsec_ioc_generic(struct dynsec_client *client,
                                unsigned long cmd, unsigned long arg)
{
    int ret;

    if (!client) {
        return -EINVAL;
    }

    ret = ioctl(client->fd, cmd, arg);
    if (ret < 0) {
        ret = -errno;
    }
    return ret;
}
int dynsec_client_disable_bypass_mode(struct dynsec_client *client)
{
    return __dynsec_ioc_generic(client, DYNSEC_IOC_BYPASS_MODE, 0);
}
int dynsec_client_enable_bypass_mode(struct dynsec_client *client)
{
    return __dynsec_ioc_generic(client, DYNSEC_IOC_BYPASS_MODE, 1);
}

int dynsec_client_disable_stalling(struct dynsec_client *client)
{
    return __dynsec_ioc_generic(client, DYNSEC_IOC_STALL_MODE, 0);
}
int dynsec_client_enable_stalling(struct dynsec_client *client)
{
    return __dynsec_ioc_generic(client, DYNSEC_IOC_STALL_MODE, 1);
}


// kmod will only commit these change if they are valid.
//  - lazy_notifier, queue_threshold, notify_threshold
int dynsec_client_set_queue_options(struct dynsec_client *client,
                                    struct dynsec_config *config)
{
    int ret = -EINVAL;

    if (!client || !config) {
        return -EINVAL;
    }

    ret = ioctl(client->fd, DYNSEC_IOC_QUEUE_OPTS, config);
    if (ret < 0) {
        ret = -errno;
    }
    return ret;
}

// Tells kmod to notify poll() when possible
int dynsec_client_disable_lazy_notifier(struct dynsec_client *client)
{
    int ret;
    struct dynsec_config config;

    ret = dynsec_client_get_config(client, &config);
    if (ret < 0) {
        return ret;
    }
    config.lazy_notifier = 0;

    return dynsec_client_set_queue_options(client, &config);
}

// Basically let's kmod not always notify poll() when enqueueing events.
// Aka Lazy Mode
int dynsec_client_enable_lazy_notifier(struct dynsec_client *client)
{
    int ret;
    struct dynsec_config config;

    ret = dynsec_client_get_config(client, &config);
    if (ret < 0) {
        return ret;
    }
    config.lazy_notifier = 1;
    return dynsec_client_set_queue_options(client, &config);
}

// Soft threshold to tell us when to explicity notify poll()
// Reads off queue will may very be above this value
// When ZERO notifying poll() will depend on if the event
// needs to explicity notify poll().
int dynsec_client_set_notify_threshold(struct dynsec_client *client,
                                       uint32_t threshold)
{
    int ret;
    struct dynsec_config config;

    ret = dynsec_client_get_config(client, &config);
    if (ret < 0) {
        return ret;
    }

    config.notify_threshold = threshold;
    return dynsec_client_set_queue_options(client, &config);
}

// A ZERO notify threshold disables it.
// However this is helpful to keep enabled for burst event mitigations.
int dynsec_client_disable_notify_threshold(struct dynsec_client *client)
{
    return dynsec_client_set_notify_threshold(client, 0);
}

// Hard threshold to tell us when to stop copying event to userspace.
// This value SHOULD be greater than or equal to the notify_threshold.
// When ZERO the number of copies to userspace is bounded by buffer size.
// Helpful to ensure we don't read too many events for a read operation.
int dynsec_client_set_queue_threshold(struct dynsec_client *client,
                                      uint32_t threshold)
{
    int ret;
    struct dynsec_config config;

    ret = dynsec_client_get_config(client, &config);
    if (ret < 0) {
        return ret;
    }

    config.queue_threshold = threshold;
    return dynsec_client_set_queue_options(client, &config);
}

// A ZERO queue threshold allows us to fill in the buffer as much as possible.
int dynsec_client_disable_queue_threshold(struct dynsec_client *client)
{
    return dynsec_client_set_queue_threshold(client, 0);
}

int dynsec_client_set_stall_timeout(struct dynsec_client *client,
                                    unsigned int timeout_ms)
{
    return __dynsec_ioc_generic(client, DYNSEC_IO_STALL_TIMEOUT_MS,
                                timeout_ms);
}
