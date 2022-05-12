/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright 2022 VMware, Inc. All rights reserved.

#pragma once

#ifdef CONFIG_X86_64
#define GPF_DISABLE() write_cr0(read_cr0() & (~ 0x10000))
#define GPF_ENABLE()  write_cr0(read_cr0() | 0x10000)

static inline bool set_page_state_rw(void *addr, unsigned long *old_page_rw)
{
    unsigned int level;
    unsigned long irq_flags;
    pte_t *pte = NULL;

    local_irq_save(irq_flags);
    local_irq_disable();

    pte = lookup_address((unsigned long)addr, &level);
    if (!pte) {
        local_irq_restore(irq_flags);
        return false;
    }

    *old_page_rw = pte->pte & _PAGE_RW;
    pte->pte |= _PAGE_RW;

    local_irq_restore(irq_flags);
    return true;
}

static inline void restore_page_state(void *addr, unsigned long page_rw)
{
    unsigned int level;
    unsigned long irq_flags;
    pte_t *pte = NULL;

    local_irq_save(irq_flags);
    local_irq_disable();

    pte = lookup_address((unsigned long)addr, &level);
    if (!pte)
    {
        local_irq_restore(irq_flags);
        return;
    }

    // If the page state was originally RO, restore it to RO.
    // We don't just assign the original value back here in case some other bits were changed.
    if (!page_rw) pte->pte &= ~_PAGE_RW;
    local_irq_restore(irq_flags);
}
#endif /* CONFIG_X86_64 */
