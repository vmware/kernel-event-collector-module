# Copyright 2018 Carbon Black Inc.  All rights reserved.

cmake_minimum_required(VERSION 2.8.7)
project (KernelEventCollectorModule)

FIND_PACKAGE(CbUtil REQUIRED)
FIND_PACKAGE(CbKernelUtil REQUIRED)

file (GLOB SRC_FILES
        RELATIVE ${CMAKE_SOURCE_DIR}
        include/*.h
        src/*.h
        src/*.c
        )

cb_check_kernel_files(
        SOURCE_DIR          ${CMAKE_SOURCE_DIR}
        IGNORE_TAGS         CODE_INDENT
                            CONSTANT_COMPARISON
                            LEADING_SPACE
                            LINUX_VERSION_CODE
                            NEW_TYPEDEFS
                            OPEN_BRACE
                            SPDX_LICENSE_TAG
                            SUSPECT_CODE_INDENT
                            TRAILING_STATEMENTS
        SOURCE_FILES        ${SRC_FILES}
)
