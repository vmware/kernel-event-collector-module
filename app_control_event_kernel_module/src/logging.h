/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2021 VMware, Inc. All rights reserved.
#pragma once

#define DS_ERROR 3
#define DS_INFO 6
#define DS_VERBOSE 9

#ifndef DEFAULT_DS_LOG_LEVEL
#define DEFAULT_DS_LOG_LEVEL DS_INFO
#endif

#define DS_LOG(LEVEL, format, ...) \
{ \
   if (LEVEL <= DEFAULT_DS_LOG_LEVEL) {\
      pr_info( #format, ##__VA_ARGS__ );\
   }\
}
