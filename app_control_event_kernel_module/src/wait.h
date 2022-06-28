/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright 2022 VMware, Inc. All rights reserved.

#pragma once

extern int dynsec_wait_event_timeout(struct dynsec_event *dynsec_event,
                                     int *response, gfp_t mode);

extern int handle_stall_ioc(const struct dynsec_stall_ioc_hdr *hdr);
