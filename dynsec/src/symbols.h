/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2021 VMware, Inc. All rights reserved.

#pragma once

extern int find_symbol_indirect(const char *symbol_name, unsigned long *addr);
extern bool dynsec_sym_init(void);
