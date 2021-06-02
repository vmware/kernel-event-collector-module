/// @file    logging.h
///
/// @brief   Declarations of macros usefule for logging
///
/// @copyright (c) 2019 Carbon Black, Inc. All rights reserved.
///

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
      printk( #format, ##__VA_ARGS__ );\
   }\
}
