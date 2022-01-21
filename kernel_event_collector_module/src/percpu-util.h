/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2021 VMware, Inc. All rights reserved.

#pragma once

#include <linux/version.h>
#include <linux/percpu_counter.h>

#if RHEL_RELEASE_CODE <= RHEL_RELEASE_VERSION(7, 1)
#define ec_percpu_counter_init(fbc, value, gfp)  percpu_counter_init(fbc, value)
#define ec_alloc_percpu(type, gfp)               alloc_percpu(type)
#else
#define ec_percpu_counter_init(fbc, value, gfp)  percpu_counter_init(fbc, value, gfp)
#define ec_alloc_percpu(type, gfp)               alloc_percpu_gfp(type, gfp)
#endif
