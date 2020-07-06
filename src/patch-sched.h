/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#pragma once

#include "priv.h"
#include <linux/sched.h>

bool patch_sched(ProcessContext *context);
void restore_sched(ProcessContext *context);
bool sched_changed(ProcessContext *context);
