/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#pragma once

#include "process-context.h"


bool path_buffers_init(ProcessContext *context);
void path_buffers_shutdown(ProcessContext *context);
char *get_path_buffer(ProcessContext *context);
void put_path_buffer(char *buffer);
