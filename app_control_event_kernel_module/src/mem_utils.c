// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2022 VMware, Inc. All rights reserved.

#include <linux/errno.h>
#include <linux/stddef.h>
#include <linux/types.h>
#include <linux/version.h>
#include "symbols.h"

//
// Intended to temporarily set read-only memory to rw
// to insert callbacks we care about.
// The current drawback to using this approach on older kernels
// may cause us to set memory to be read-only even
// if it originally was not read-only protected.
// However the pte in a generic way may give a better idea.
//

struct mem_symz {
    int (*set_memory_ro)(unsigned long addr, int numpages);
    int (*set_memory_rw)(unsigned long addr, int numpages);
};
static struct mem_symz mem_syms;

bool dynsec_mem_utils_init(void)
{
    find_symbol_indirect("set_memory_ro", (unsigned long *)&mem_syms.set_memory_ro);
    find_symbol_indirect("set_memory_rw", (unsigned long *)&mem_syms.set_memory_rw);

    if (!mem_syms.set_memory_ro || !mem_syms.set_memory_rw) {
        return false;
    }
    return true;
}

int dynsec_set_memory_ro(unsigned long addr, int numpages)
{
    if (mem_syms.set_memory_ro) {
        return mem_syms.set_memory_ro(addr, numpages);
    }
    return -ENOSYS;
}

int dynsec_set_memory_rw(unsigned long addr, int numpages)
{
    if (mem_syms.set_memory_rw) {
        return mem_syms.set_memory_rw(addr, numpages);
    }
    return -ENOSYS;
}
