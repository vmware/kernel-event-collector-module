/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2021 VMware, Inc. All rights reserved.

#pragma once

extern bool dynsec_path_utils_init(void);

extern bool dynsec_current_chrooted(void);

extern char *dynsec_dentry_path(const struct dentry *dentry, char *buf, int buflen);

extern char *dynsec_d_path(const struct path *path, char *buf, int buflen);

extern char *dynsec_path_safeish(const struct path *path, char *buf, int buflen);

