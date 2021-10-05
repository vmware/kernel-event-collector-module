/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2021 VMware, Inc. All rights reserved.
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>
#include "dynsec.h"

// Size of the read buffer
#define MAX_BUF_SZ (1 << 15)
// Rough average size of events
#define EVENT_AVG_SZ (1 << 7)
// Rough safe max reads based on average event payload
#define MAX_EVENTS_PER_READ (MAX_BUF_SZ / EVENT_AVG_SZ)

#define MAX_TRACK_PIDS 256
// refer to MODULE_NAME_LEN in mount.h kernel
// 100 is much larger than the 64 bytes module names are limited to
#define MAX_KMOD_NAME_LEN 100

#define MAX_VERBOSE_LEVEL 3

struct dynsec_client;
struct dynsec_msg_hdr;

// struct event_stats {
//     unsigned long long total_events;
//     unsigned long long total_bytes;
//     unsigned long long total_stall;
//     unsigned long long total_cached;
//     unsigned long long total_nonstall;
//     unsigned long long total_intent;
//     unsigned long long total_intents_found;
// };

// struct client_stats {
//     unsigned int largest_read;
//     int max_parsed_per_read;
//     int max_bytes_per_event;
//     unsigned long long total_reads;

//     struct event_stats queue;
//     struct event_stats event[DYNSEC_EVENT_TYPE_MAX];
//     unsigned long long events_per_read[MAX_EVENTS_PER_READ];
// };

struct client_device {
    unsigned int major;
    unsigned int minor;
    const char *proc_file;
    const char *kmod_search_str;
    char kmod_name[MAX_KMOD_NAME_LEN];
};

struct client_tracking {
    int verbosity;
    int debug;
    bool shutdown;
    bool follow_progeny;

    bool is_tracing;
    pid_t progeny[MAX_TRACK_PIDS];
    int max_index;
};

// Event Callback
enum DYNSEC_EAT {
    DYNSEC_EAT_ERROR = -1,  // Hook 
    DYNSEC_EAT_DEFAULT,        // Accept as default response
    DYNSEC_EAT_DISCARD,     // Explicitly discard event
    DYNSEC_EAT_KEEP,        // Explicitly keep event from being discarded
    DYNSEC_EAT_SHUTDOWN,    // Signal a shutdown
    DYNSEC_EAT_MAX,
};


struct dynsec_client_ops {
    enum DYNSEC_EAT (*event_hook)(struct dynsec_client *client,
                    const struct dynsec_msg_hdr *hdr);
    enum DYNSEC_EAT (*event_discarded_hook)(struct dynsec_client *client,
                              const struct dynsec_msg_hdr *hdr, bool may_override);
    void (*release_hook)(struct dynsec_client *client);
};

struct dynsec_client {
    int fd;
    char buf[MAX_BUF_SZ];

    struct client_tracking tracking;
    struct client_device device;
    // struct client_stats stats;

    uint32_t cache_flags;

    const struct dynsec_client_ops *ops;

    void *private_data;
};


extern void dynsec_client_register(struct dynsec_client *client,
                        uint32_t default_cache_flags,
                        const struct dynsec_client_ops *ops,
                        void *private_data);

extern void dynsec_client_shutdown(struct dynsec_client *client);

extern int dynsec_client_connect(struct dynsec_client *client,
                          int verbosity, int debug, bool is_tracing);

extern void dynsec_client_read_events(struct dynsec_client *client);

extern void dynsec_client_reset(struct dynsec_client *client);

extern void dynsec_client_track_pid(struct dynsec_client *client, pid_t pid,
                                    bool follow_progeny);

