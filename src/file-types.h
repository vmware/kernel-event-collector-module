/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#pragma once

#define MAX_FILE_BYTES_TO_DETERMINE_TYPE 68

void determine_file_type(char *buffer, uint32_t bytes_read, CB_FILE_TYPE *pFileType, bool determineDataFiles);
char *file_type_str(CB_FILE_TYPE fileType);
