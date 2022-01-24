// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 VMware, Inc. All rights reserved.

#include <linux/kallsyms.h>
#include <linux/version.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include "symbols.h"

#define lock_module() preempt_disable()
#define unlock_module() preempt_enable()

struct kallsymz {
    unsigned long (*kallsyms_lookup_name)(const char *name);
    struct module *(*__module_address)(unsigned long addr);
    int (*lookup_symbol_name)(unsigned long addr, char *symname);
};
static struct kallsymz syms;

static int __kprobes dummy_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
    return 0;
}
static void __kprobes dummy_post_handler(struct kprobe *p, struct pt_regs *regs,
                unsigned long flags)
{

}
static int dummy_fault_handler(struct kprobe *p, struct pt_regs *regs, int trapnr)
{
    return 0;
}

static int find_symbol_by_kprobe(const char *symbol_name, unsigned long *addr)
{
    int ret;

    struct kprobe p = {
        .addr          = NULL,
        .symbol_name   = symbol_name,
        .pre_handler   = dummy_pre_handler,
        .post_handler  = dummy_post_handler,
        .fault_handler = dummy_fault_handler,
    };

    ret = register_kprobe(&p);
    if (ret >= 0) {
        *addr = (unsigned long)p.addr;
        unregister_kprobe(&p);
        return 0;
    }

    return ret;
}

static int find_symbol_kallsyms(const char *symbol_name, unsigned long *addr)
{
    if (addr && syms.kallsyms_lookup_name) {
        *addr = syms.kallsyms_lookup_name(symbol_name);
    }
    return 0;
}

bool dynsec_sym_init(void)
{
    memset(&syms, 0, sizeof(syms));

    // may want to fall back to kprobe symbol lookups on
    // newer kernels if this fails
    find_symbol_by_kprobe("kallsyms_lookup_name",
                          (unsigned long *)&syms.kallsyms_lookup_name);

    find_symbol_indirect("__module_address",
                         (unsigned long *)&syms.__module_address);
    find_symbol_indirect("lookup_symbol_name",
                         (unsigned long *)&syms.lookup_symbol_name);

    if (!syms.kallsyms_lookup_name) {
        return false;
    }
    return true;
}

// Doesn't count in for multiple modules with the same exposed symbol
int find_symbol_indirect(const char *symbol_name, unsigned long *addr)
{
    if (!symbol_name || !addr || !*symbol_name) {
        return -EINVAL;
    }

    if (addr) {
        *addr = 0;
    }

    find_symbol_kallsyms(symbol_name, addr);
    if (!addr) {
        find_symbol_by_kprobe(symbol_name, addr);
    }
    return 0;
}

int dynsec_lookup_symbol_name(unsigned long addr, char *symname)
{
    if (!symname) {
        return -EINVAL;
    }

    if (!syms.lookup_symbol_name) {
        return -ENOENT;
    }
    return syms.lookup_symbol_name(addr, symname);
}

static struct module *dynsec__module_address(unsigned long addr)
{
    if (!syms.__module_address) {
        return NULL;
    }
    return syms.__module_address(addr);
}

// Return 0 if module found. Module name copied if name found.
// Can be used to detect if an address is from a kmod.
int dynsec_module_name(unsigned long addr, char *modname, size_t size)
{
    int ret = -ENOENT;
    struct module *mod = NULL;

    if (modname && size) {
        memset(modname, 0, size);
    }

    lock_module();
    mod = dynsec__module_address(addr);
    if (mod) {
        ret = 0;
        if (mod->name && modname && size) {
            strlcpy(modname, mod->name, size);
        }
    }
    unlock_module();

    return ret;
}
