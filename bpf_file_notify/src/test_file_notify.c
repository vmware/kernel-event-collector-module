/*
 * Copyright 2023 VMware, Inc.
 * SPDX-License-Identifier: GPL-2.0
 */

#include <stdio.h>
#include <unistd.h>
#include <stdint.h>

#include "file_notify.h"
#include "file_notify_transport.h"
#include "file_notify.skel.h"


static void print_blob(const void *base, const struct file_notify__blob_ctx *blob)
{
    if (blob && blob->size && blob->offset)
    {
        const char *type = "UNKNOWN";

        const char *loc = (typeof(loc))base + blob->offset;

        switch (blob->type)
        {
        case BLOB_TYPE_DENTRY_PATH:
            type = "DENTRY_PATH";
        case BLOB_TYPE_FULL_PATH:
            type = "FULL_PATH";
        case BLOB_TYPE_DPATH:
            type = "DPATH";

            printf("%s:{sz:%u off:%u flags:%#x strlen:%lu %s}", type,
                   blob->size, blob->offset, blob->flags, strlen(loc), loc);
            break;

        case BLOB_TYPE_NUL_TERMINATE_STRING:
            type = "NUL_TERMINATE_STRING";
            printf("%s:{sz:%u off:%u flags:%#x}", type,
                   blob->size, blob->offset, blob->flags);
            break;

        case BLOB_TYPE_RAW:
            type = "RAW";
            printf("%s:{sz:%u off:%u flags:%#x}", type,
                   blob->size, blob->offset, blob->flags);
            break;

        default:
            printf("%s[%u]:{sz:%u off:%u flags:%#x}", type, blob->type,
                   blob->size, blob->offset, blob->flags);
            break;
        }
    }
}

static void perf_print_data(void *ctx, int cpu, void *data, __u32 data_sz)
{
    struct file_notify_msg *msg = data;

    printf("%lu payload:%u %s[%u] total_deny:%lu ", msg->hdr.ts, msg->hdr.payload,
           msg->task_ctx.comm, msg->task_ctx.pid,
           msg->inode_entry.total_deny);
    print_blob(msg, &msg->path);
    printf("\n");
}

// TODO: Figure out what callback return value can do
static int ringbuf_print_data(void *ctx, void *data, size_t len)
{
    struct file_notify_msg *msg = data;

    printf("%lu payload:%u %s[%u] total_deny:%lu ", msg->hdr.ts, msg->hdr.payload,
           msg->task_ctx.comm, msg->task_ctx.pid,
           msg->inode_entry.total_deny);
    print_blob(msg, &msg->path);
    printf("\n");

    return 0;
}

int init_basic(int argc, const char *argv[])
{
    bool use_perf = false;
    int ret = 0;
    struct file_notify_bpf *skel = NULL;
    struct ring_buffer *ringbuf = NULL;
    struct perf_buffer *pb = NULL;

    skel = file_notify_bpf__open();
    if (!skel) {
        printf("Unabled to open and load bpf\n");
        return 1;
    }

    // Set global and statics and constants to instance here

    if (use_perf) {
        skel->rodata->USE_RINGBUF = 0;
        bpf_map__set_autocreate(skel->maps.ringbuf, false);
    } else {
        skel->rodata->USE_RINGBUF = 1;
        bpf_map__set_autocreate(skel->maps.events, false);
        bpf_map__set_max_entries(skel->maps.ringbuf, 4096 * 512);
    }

    ret = file_notify_bpf__load(skel);
    if (ret) {
        printf("Unabled to open and load bpf: ret:%d\n", ret);
        return 1;
    }

    if (use_perf) {
        pb = perf_buffer__new(bpf_map__fd(skel->maps.events), 512,
                              perf_print_data, NULL,
                              NULL, NULL);
            printf("Unable to create perf_buffer\n");
            ret = 1;
            goto out;
    } else {
        ringbuf = ring_buffer__new(bpf_map__fd(skel->maps.ringbuf),
                                   ringbuf_print_data, NULL, NULL);
        if (!ringbuf) {
            printf("Unable to create ring_buffer\n");
            ret = 1;
            goto out;
        }
    }

    ret = file_notify_bpf__attach(skel);
    if (ret) {
        printf("Unable to attach bpf: %d\n", ret);\
        goto out;
    }

    for (int i = 1; i < argc; i++)
    {
        if (argv[i] && argv[i]) {
            int ret = file_notify__ban_filepath(skel, argv[i]);

            if (ret) {
                fprintf(stderr, "Unable to ban file:%s :%d\n", argv[i], ret);
            } else {
                printf("Banning file:%s\n", argv[i]);
            }
        } else {
            break;
        }
    }

    // Where we'd poll for events from perf or ring buffer
    while (true)
    {
        if (use_perf)
            ret = perf_buffer__poll(pb, -1);
        else
            ret = ring_buffer__poll(ringbuf, -1);
        if (ret < 0 && ret != -EINTR) {
            break;
        }
    }

out:
    if (pb)
        perf_buffer__free(pb);
    if (ringbuf)
        ring_buffer__free(ringbuf);

    if (skel) {
        file_notify_bpf__destroy(skel);
    }
    return ret;
}

bool has_bpf_lsm_loaded(void)
{
    return file_notify__bpf_lsm_enabled() == 0;
}


int main(int argc, const char *argv[])
{
    if (!has_bpf_lsm_loaded()) {
        fprintf(stderr, "Unable to run tests: bpf lsm not loaded\n");
        fprintf(stderr, "  Kernels with BPF LSM can be configured to load this on boot.\n");
        return 0;
    }

    init_basic(argc, argv);

    return 0;
}
