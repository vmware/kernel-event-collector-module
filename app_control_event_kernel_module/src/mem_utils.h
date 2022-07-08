/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2022 VMware, Inc. All rights reserved.

#pragma once

extern bool dynsec_mem_utils_init(void);

extern int dynsec_set_memory_ro(unsigned long addr, int numpages);

extern int dynsec_set_memory_rw(unsigned long addr, int numpages);

#ifdef CONFIG_X86_64
#define GPF_DISABLE() write_cr0(read_cr0() & (~ 0x10000))
#define GPF_ENABLE()  write_cr0(read_cr0() | 0x10000)
#else
#define GPF_DISABLE() do { } while(0)
#define GPF_ENABLE() do { } while(0)
#endif /* CONFIG_X86_64 */

// Assumes irq disabled
static inline bool set_page_state_rw(void *addr, unsigned long *old_page_rw)
{
#ifdef USE_X86_SET_PAGE
    unsigned int level;
    pte_t *pte = NULL;

    pte = lookup_address((unsigned long)addr, &level);
    if (!pte) {
        return false;
    }

    *old_page_rw = pte->pte & _PAGE_RW;
    pte->pte |= _PAGE_RW;

#else
    if (dynsec_set_memory_rw((unsigned long) addr, 1) < 0) {
        return false;
    }
#endif
    return true;
}

// Assumes irq disabled
static inline void restore_page_state(void *addr, unsigned long page_rw)
{
#ifdef USE_X86_SET_PAGE
    unsigned int level;
    pte_t *pte = NULL;

    pte = lookup_address((unsigned long)addr, &level);
    if (!pte) {
        return;
    }

    // If the page state was originally RO, restore it to RO.
    // We don't just assign the original value back here in case some other bits were changed.
    if (!page_rw) pte->pte &= ~_PAGE_RW;
#else
    (void)dynsec_set_memory_ro((unsigned long) addr, 1);
#endif
}
