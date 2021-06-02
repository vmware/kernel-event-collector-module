/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/// @file    opcache.h
///
/// @brief   Declarations of macros/functions/types required to cache operation
///          results.
///
/// @copyright (c) 2019 Carbon Black, Inc. All rights reserved.
///

#pragma once
#include <linux/types.h>
#include <linux/dcache.h>

#define OPC_OP_INVALID 0
#define OPC_OP_EXEC 1
#define OPC_OP_WRITE 2

#define OPC_RESULT_ALLOWED 0
#define OPC_RESULT_DENIED 1

struct opcache_ctx {
    int op;
    int pid;
    int uid;
    int euid;
    u64 ino;
    dev_t dev;
    struct dentry* dentry;
};

int opcache_is_op_allowed(const struct opcache_ctx* ctx);

int opcache_init(void);
int opcache_exit(void);
