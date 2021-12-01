/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright 2021 VMWare, Inc.  All rights reserved. */

#pragma once

extern bool g_webproxy_enabled;

extern bool ec_netfilter_initialize(ProcessContext *context);
extern void ec_netfilter_cleanup(ProcessContext *context);
extern bool ec_netfilter_enable(ProcessContext *context);
extern void ec_netfilter_disable(ProcessContext *context);

