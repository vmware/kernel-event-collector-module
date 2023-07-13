/* Copyright 2023 VMware Inc.  All rights reserved. */
/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

#pragma once

struct file_notify_bpf;


// Helper independent from file_notify_bpf object
extern int file_notify__bpf_lsm_enabled(void);


// Example ways to ban by file path or file descriptor
// we could also ban by file handle as well.

extern int file_notify__ban_fd(const struct file_notify_bpf *skel, int fd);

extern int file_notify__ban_dfd_filepath(const struct file_notify_bpf *skel,
                                         int dfd, const char *filepath);

extern int file_notify__ban_filepath(const struct file_notify_bpf *skel,
                                     const char *filepath);

