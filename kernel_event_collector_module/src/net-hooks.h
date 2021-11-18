/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright 2021 VMware Inc.  All rights reserved. */

#pragma once

bool ec_network_hooks_initialize(ProcessContext *context, uint64_t enableHooks);
void ec_network_hooks_shutdown(ProcessContext *context, uint64_t enableHooks);
