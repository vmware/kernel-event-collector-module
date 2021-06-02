/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/// @file    usercomm.h
///
/// @brief   Declarations of macros/functions/types required for communications
///          with the usermode deamon.
///
/// @copyright (c) 2019 Carbon Black, Inc. All rights reserved.
///

#pragma once
#include "opcache.h"

// Channel number for DYNSEC generic socket.  Should be braneded by each one
#ifndef NETLINK_DYNSEC
#define NETLINK_DYNSEC 27
#endif

int usercomm_is_op_allowed(const struct opcache_ctx* ctx);
bool user_connected(void);
int usercomm_init(void);
int usercomm_exit(void);


