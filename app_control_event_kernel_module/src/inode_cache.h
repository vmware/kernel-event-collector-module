/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2021 VMware, Inc. All rights reserved.
#pragma once

extern int inode_cache_register(void);
extern void inode_cache_clear(void);
extern void inode_cache_enable(void);
extern void inode_cache_disable(void);
extern void inode_cache_shutdown(void);
extern int inode_cache_lookup(unsigned long inode_addr, u64 *hits,
                              bool insert, gfp_t mode);
extern int inode_cache_update(unsigned long inode_addr,
                              unsigned long cache_flags);
extern void inode_cache_remove_entry(unsigned long inode_addr);

extern void inode_cache_display_buckets(struct seq_file *m);
