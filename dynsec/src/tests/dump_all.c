// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 VMware, Inc. All rights reserved.

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include "client.h"


//
// Dumps all the processes or tasks
//

struct task_dump_data {
    pid_t self_pid;
    pid_t max_pid;
};

// Event callback. Only print the task dumps from ourself.
// Find and store the largest pid value.
static enum DYNSEC_EAT only_print_task_dump(struct dynsec_client *client,
                        const struct dynsec_msg_hdr *hdr)
{
    struct task_dump_data *data = client->private_data;

    if (data && hdr->tid == data->self_pid &&
        hdr->event_type == DYNSEC_EVENT_TYPE_TASK_DUMP) {
        const struct dynsec_task_dump_umsg *task_dump = (const struct dynsec_task_dump_umsg *)hdr;

        // should always hold true since incrementing
        if (task_dump->msg.task.tid > data->max_pid) {
            data->max_pid = task_dump->msg.task.tid;
        }
        printf("%s tid:%u pid:%u ppid:%u\n", task_dump->msg.task.comm,
               task_dump->msg.task.tid, task_dump->msg.task.pid,
               task_dump->msg.task.ppid);
        return DYNSEC_EAT_DEFAULT;
    }
    return DYNSEC_EAT_DISCARD;
}
// Default Discard Callback - does nothing
static enum DYNSEC_EAT event_discarded_cb(struct dynsec_client *client,
                        const struct dynsec_msg_hdr *hdr,
                        bool may_override)
{
    return DYNSEC_EAT_DEFAULT;
}
// Print out the max pid if we found it
static void release_cb(struct dynsec_client *client)
{
    struct task_dump_data *data = client->private_data;

    if (data && data->max_pid) {
        fprintf(stdout, "MaxPid: %d\n", data->max_pid);
    }
}

static struct task_dump_data dump_data = {
    .self_pid = 0,
    .max_pid = 0,
};
static struct dynsec_client_ops task_dump_ops = {
    .event_hook = only_print_task_dump,
    .event_discarded_hook = event_discarded_cb,
    .release_hook = release_cb,
};
static struct dynsec_client client;

void sig_alarm_handler(int sig)
{
    // Timedout shutdown
    if (sig == SIGALRM) {
        dynsec_client_shutdown(&client);
    }
}

int main(int argc, const char *argv[])
{
    int ret = 0;
    int verbosity = 0;
    int debug = 0;
    bool is_tracing = false;
    bool dump_threads = false;

    dump_data.self_pid = getpid();

    // Allow for a simple single paramter
    if (argc > 1 && argv[1] &&
        strcmp(argv[1], "--threads") == 0) {
        dump_threads = true;
    }

    dynsec_client_register(&client, DYNSEC_CACHE_ENABLE,
                           &task_dump_ops, &dump_data);
    if (dynsec_client_connect(&client, verbosity,
                              debug, is_tracing) < 0) {
        fprintf(stderr, "Unable to connect to kmod\n");
        return 1;
    }

    // Requests to place TASK_DUMP events onto event queue
    if (dump_threads) {
        ret = dynsec_client_dump_all_threads(&client);
    } else {
        ret = dynsec_client_dump_all_processes(&client);
    }
    if (ret < 0) {
        fprintf(stderr, "Unable to make task_dump_all request: %s\n",
                strerror(-ret));
        dynsec_client_reset(&client);
        return 1;
    }
    // By the time dynsec_client_dump_all_processes completes
    // the TASK_DUMP events will be on the queue.

    signal(SIGALRM, sig_alarm_handler);
    alarm(1);
    ret = dynsec_client_read_events(&client);
    dynsec_client_reset(&client);
    if (ret < 0) {
        fprintf(stderr, "dynsec_client_read_events: %s\n",
                strerror(-ret));
    }

    return 0;
}
