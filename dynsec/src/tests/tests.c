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
#include <getopt.h>
#include <stdbool.h>
#include <limits.h>

#include "dynsec.h"
#include "test_utils.h"
#include "rename.h"
#include "exp.h"
#include "client.h"
#include "print.h"

static struct dynsec_client global_client;
static int exit_status = 0;

static enum DYNSEC_EAT match_event_cb(struct dynsec_client *client,
                                      const struct dynsec_msg_hdr *hdr)
{
    print_event_raw((struct dynsec_msg_hdr *)hdr);
    return DYNSEC_EAT_DEFAULT;
}
static enum DYNSEC_EAT discard_cb(struct dynsec_client *client,
                                  const struct dynsec_msg_hdr *hdr,
                                  bool may_override)
{
    return DYNSEC_EAT_DEFAULT;
}

// Default callbacks for event processing loop
static const struct dynsec_client_ops self_test_ops = {
    .event_hook = match_event_cb,
    .event_discarded_hook = discard_cb,
    .release_hook = NULL,
};

static struct dynsec_client_ops ambient_ops;

static int setup_client(struct dynsec_client *client,
                        struct test_case *test_case)
{
    // Default to using the self_test_ops callbacks
    memcpy(&ambient_ops, &self_test_ops, sizeof(ambient_ops));

    if (test_case) {
        // Override event_cb as desired. Primarily for matching
        if (test_case->event_hook) {
            ambient_ops.event_hook = test_case->event_hook;
        }
    }

    dynsec_client_register(client, 0, &ambient_ops, test_case);

    return dynsec_client_connect(client, 0, 0, true);
}

static void teardown_client(struct dynsec_client *client)
{
    dynsec_client_reset(client);
}

static void run_fork_child_side(struct test_case *test_case)
{
    teardown_client(&global_client);
    if (test_case) {
        if (test_case->func) {
            (void)test_case->func(test_case);
        }
        // Don't Tear everything down. Might trigger events.
        if (test_case->release) {
            test_case->release(test_case);
        }
        teardown_base_test_data(test_case);
    }
    exit(0);
}

void run_fork_test_case(struct test_case *test_case, int id)
{
    int test_error;
    int client_fd = -1;
    pid_t pid = -1;

    if (!test_case) {
        return;
    }

    // Eventually print out if SKIPPED.
    if (test_case->setup) {

        // TODO: Randomly generate basedir instead of current dir
        setup_base_test_data(test_case, ".");

        test_error = test_case->setup(test_case);
        if (test_error) {
            fprintf(stderr, "\tWARN: SETUP ERROR: %d\n", test_error);
            if (test_case->teardown) {
                test_case->teardown(test_case);
            }
            if (test_case->release) {
                test_case->release(test_case);
            }
            teardown_base_test_data(test_case);
            return;
        }
    }
    client_fd = setup_client(&global_client, test_case);
    if (client_fd < 0) {
        fprintf(stderr, "\tWARN: CLIENT ERROR: %d\n", client_fd);
        if (test_case->teardown) {
            test_case->teardown(test_case);
        }
        if (test_case->release) {
            test_case->release(test_case);
        }
        teardown_base_test_data(test_case);
        return;
    }

    pid = fork();
    // Ran out of PIDS
    if (pid < 0) {
        teardown_client(&global_client);
        if (test_case->teardown) {
            test_case->teardown(test_case);
        }
        if (test_case->release) {
            test_case->release(test_case);
        }
        teardown_base_test_data(test_case);
        exit(1);
        return;
    }

    // Child that triggers events
    if (!pid) {
        run_fork_child_side(test_case);
        return;
    }

    // Parent that tries to record/match and verify results
    if (test_case->setup_matcher) {
        test_case->setup_matcher(test_case);
    }

    // Tell client to track forked process
    // and record it's matching events.
    dynsec_client_track_pid(&global_client, pid, true);
    dynsec_client_read_events(&global_client);
    teardown_client(&global_client);

    // TODO: Really should be the verify step
    if (test_case->verify) {
        test_error = test_case->verify(test_case);
        if (test_error) {
            fprintf(stderr, "\tWARN: RUN MATCH ERROR: %d\n", test_error);
        }
        if (test_error > 0) {
            printf("\tFAIL: %s.%d [%d]\n", test_case->name, id, test_error);
            exit_status = 1;
        } else if (test_case < 0) {
            printf("\tERROR: %s.%d [%d]\n", test_case->name, id, test_error);
            exit_status = 1;
        } else {
            printf("\tPASS: %s.%d\n", test_case->name, id);
        }
    }
    test_case->teardown(test_case);
    if (test_case->release) {
        test_case->release(test_case);
    }

    // Eventually rmdir base testdir
    teardown_base_test_data(test_case);
}


void run_fork_rename_tests()
{
    int i;
    struct test_suite rename = {};

    // struct copy for now
    rename = rename_fork_test_suite;

    printf("TEST SUITE: fork_rename\n");
    for (i = 0; i < rename.size; i++) {
        run_fork_test_case(&rename.test_case[i], i);
    }
}

void run_self_tests()
{
    run_fork_rename_tests();
}


int main(int argc, char *const *argv)
{
    int fd;

    // Attempt to connect to the kmod first before
    // doing anything else.
    // Would be a good place to get testing capabilities before
    // running tests.
    fd = setup_client(&global_client, NULL);
    if (fd < 0) {
        fprintf(stderr, "Cannot setup client\n");
        return 1;
    }
    teardown_client(&global_client);

    run_self_tests();

    return exit_status;
}
