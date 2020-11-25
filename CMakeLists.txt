# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
# Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

cmake_minimum_required(VERSION 3.12.3)
# CMake 2.x (the default in CentOS7) does not grok 'cmake_parse_arguments'.
# CMake3 is available for CentOS7 as:
#   sudo yum install epel-release
#   sudo yum install cmake3
#   sudo yum remove cmake
#   sudo ln -s /usr/bin/cmake3 /usr/bin/cmake
#   sudo ln -s /usr/bin/cpack3 /usr/bin/cpack
#   sudo ln -s /usr/bin/ctest3 /usr/bin/ctest

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
                            SUSPECT_CODE_INDENT
                            TRAILING_STATEMENTS
        # checkpatch.pl does not like new typedefs.  We possibly should list all the typedefs we add here, but for now
        #  I am only listing the ones that are giving me issues.
        #  If you get the error `need consistent spacing around "*"` then add the type here.
        NEW_TYPES           CB_FILE_TYPE
                            ProcessContext
        SOURCE_FILES        ${SRC_FILES}
)
