/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2021 VMware, Inc. All rights reserved.
#pragma once

#include "dynsec.h"
#include "client.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#ifndef offsetof
#define offsetof(TYPE, MEMBER)  ((size_t)&((TYPE *)0)->MEMBER)
#endif

#define container_of(ptr, TYPE, MEMBER) ({\
        const typeof( ((TYPE *)0)->MEMBER ) *__mptr = (ptr);\
        (TYPE *)( (char *)__mptr - offsetof(TYPE,MEMBER) );})

#define sizeof_field(TYPE, MEMBER) sizeof((((TYPE *)0)->MEMBER))

#define offsetofend(TYPE, MEMBER) \
        (offsetof(TYPE, MEMBER) + sizeof_field(TYPE, MEMBER))


#define CREATE_MODE (S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH)

struct case_result {
    int act_errno;
    int result;
#define RESULT_LOG_SZ 128
    char msg[RESULT_LOG_SZ];
};
struct base_test_data {
    int dirfd;
    const char *dir;
    int exp_errno;
    int pipe[2];
    struct case_result result;
};

struct test_case {
    const char *name;
    const char *desc;
    int (*setup)(struct test_case *test_case);
    int (*setup_matcher)(struct test_case *test_case);
    int (*func)(struct test_case *test_case);

    // Called after event reading as completed. Ideal
    // for checking recorded or matched data.
    int (*verify)(struct test_case *test_case);

    // Typically will perform syscalls to shut things down
    // Not best candidate to free things.
    int (*teardown)(struct test_case *test_case);

    // Ideal place to do non event triggering cleanup.
    // Mostly to free things or relase other resources.
    void (*release)(struct test_case *test_case);

    // Use to override the default event_cb for the client event loop
    // Primarily for custom event matching/recording.
    enum DYNSEC_EAT (*event_hook)(struct dynsec_client *client,
                                const struct dynsec_msg_hdr *hdr);
    struct base_test_data base;
    void *private_data;
};

struct test_suite {
    unsigned int total_pass;
    unsigned int total_fail;
    unsigned int total_skipped;
    unsigned int total_error;

    size_t size;
    struct test_case *test_case;
};

extern void fill_in_exp_dynsec_file(int parent_fd,
                                    int fd, struct dynsec_file *file);

extern void setup_base_test_data(struct test_case *test_case,
                                 const char *basedir);

extern void teardown_base_test_data(struct test_case *test_case);

extern void write_test_result(struct test_case *test_case,
                              int result, int act_errno,
                                const char *msg);

extern void read_test_result(struct test_case *test_case);
