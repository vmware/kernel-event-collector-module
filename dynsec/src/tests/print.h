/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2021 VMware, Inc. All rights reserved.
#pragma once

#include "dynsec.h"
struct local_dynsec_event {
    struct dynsec_msg_hdr *hdr;
    struct dynsec_msg_hdr *intent;
};

extern int debug_print;

extern void print_dynsec_config(struct dynsec_config *dynsec_config);
extern void print_event(struct local_dynsec_event *event);
extern void print_event_raw(struct dynsec_msg_hdr *hdr);
extern const char *event_type_name(enum dynsec_event_type event_type);

