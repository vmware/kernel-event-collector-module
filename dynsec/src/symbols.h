/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2021 VMware, Inc. All rights reserved.

#pragma once

extern int find_symbol_indirect(const char *symbol_name, unsigned long *addr);
extern bool dynsec_sym_init(void);

extern int dynsec_lookup_symbol_name(unsigned long addr, char *symname);
extern int dynsec_module_name(unsigned long addr, char *modname, size_t size);

#define OUR_DECL(t, a) t a = (__force typeof(a))
#ifdef CONFIG_X86_64
// Refer to entry_64.S
#define DECL_ARG_1(t,a) OUR_DECL(t, a)regs->di
#define DECL_ARG_2(t,a) OUR_DECL(t, a)regs->si
#define DECL_ARG_3(t,a) OUR_DECL(t, a)regs->dx
#define DECL_ARG_4(t,a) OUR_DECL(t, a)regs->r10
#define DECL_ARG_5(t,a) OUR_DECL(t, a)regs->r8
#define DECL_ARG_6(t,a) OUR_DECL(t, a)regs->r9
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 10, 0)
#define USE_PT_REGS
#endif
