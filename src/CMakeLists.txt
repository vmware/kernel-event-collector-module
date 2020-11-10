# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
# Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

cmake_minimum_required(VERSION 2.8.7)
project (KernelEventCollectorModule)

# Include the CbKernelUtil helpers
set(ROOT_DIR "${CMAKE_SOURCE_DIR}/..")
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${ROOT_DIR}/cmake")
find_package(CbKernelUtil REQUIRED)

# LOCAL_BUILD defines if the build will be performed with configuration options
# provided directly in this CMake file, or if the CB build utility will \
# substitute values in.
if(NOT DEFINED LOCAL_BUILD)
    set(LOCAL_BUILD no)
endif()

# Common variable definitions
set(INCLUDE_DIR ${ROOT_DIR}/include)

set(CBSENSOR_AFLAGS "")
set(CBSENSOR_AFLAGS "${CBSENSOR_AFLAGS} -I${CMAKE_CURRENT_SOURCE_DIR}")
set(CBSENSOR_AFLAGS "${CBSENSOR_AFLAGS} -I${INCLUDE_DIR}")

set(CBSENSOR_FLAGS "")
set(CBSENSOR_FLAGS "${CBSENSOR_FLAGS} -Wall")
set(CBSENSOR_FLAGS "${CBSENSOR_FLAGS} -Wformat")
set(CBSENSOR_FLAGS "${CBSENSOR_FLAGS} -Werror")
set(CBSENSOR_FLAGS "${CBSENSOR_FLAGS} -include \"version.h\"")
set(CBSENSOR_FLAGS "${CBSENSOR_FLAGS} -I${CMAKE_CURRENT_SOURCE_DIR}")
set(CBSENSOR_FLAGS "${CBSENSOR_FLAGS} -I${ROOT_DIR}/include")
set(CBSENSOR_FLAGS "${CBSENSOR_FLAGS} -I${CONAN_INCLUDE_DIRS_EVENTCOLLECTOR}")
set(CBSENSOR_FLAGS "${CBSENSOR_FLAGS} ${VERACODE_FLAGS}")
set(CBSENSOR_FLAGS "${CBSENSOR_FLAGS} -DPRODVER=${NAME_SFX}")

# Variables determined from build type
if (${LOCAL_BUILD})
    message("Building using variables defined locally in this CMake")
    if(NOT KERNEL_NAME)
        message(FATAL_ERROR "You must specify the kernel version to build for with:\n"
                "    -DKERNEL_NAME=<version>.\n"
                "See the README for officially supported kernel versions.\n"
                "To build for the current distribution, use:\n"
                "    -DKERNEL_NAME=$(uname -r)\n")
    endif()

    # Derived from conanfile.py
    set(API_VERSION CB_EVENT_API_2_1)
    set(DEBUG_PREFIX EventCollector)
    set(MEM_CACHE_PREFIX ec_)
    set(MODULE_BASE_NAME )
    set(MODULE_VERSION_SUFFIX 2_0_0)
    set(MODULE_NAME event_collector)
    set(PROC_DIR event_collector)
    set(VERBOSE 1)

    set(KERNEL_LIST "${KERNEL_NAME}")
else()
    message("Building using variables provided by CB build utility")
    find_package(CbUtil REQUIRED)
    cb_configure_flags(ENABLE_FORTIFY "ON"
                       ENABLE_EXTRA_WARNINGS "ON")
    cb_conan_setup(TARGETS
                   CONAN_INCLUDE ${ROOT_DIR}/conanbuildinfo.cmake)
endif()

# Prepare source files (and remove configured files from a previous build)
set(CONFIGURED_VERSION_FILE ${INCLUDE_DIR}/version.h)
set(CONFIGURED_STATE_EXPORT_FILE ${CMAKE_CURRENT_SOURCE_DIR}/cb-module-state-export.c)
set(CONFIGURED_KBUILD_FILE ${CMAKE_CURRENT_SOURCE_DIR}/Kbuild)

file(REMOVE ${CONFIGURED_VERSION_FILE}
            ${CONFIGURED_STATE_EXPORT_FILE}
            ${CONFIGURED_KBUILD_FILE})

set(MODULE_NAME ${MODULE_NAME}_${MODULE_VERSION_SUFFIX})

configure_file(${INCLUDE_DIR}/version.h.in ${CONFIGURED_VERSION_FILE})
configure_file(cb-module-state-export.c.in ${CONFIGURED_STATE_EXPORT_FILE})

set(SOURCE_FILES drvmain.c
        hook-tracking.c
        findsyms.c
        page-helpers.c
        path-buffers.c
        mem-cache.c
        rbtree-helper.c
        file-helper.c
        file-hooks.c
        logger.c
        lsm.c
        modules.c
        cb-spinlock.c
        net-helper.c
        net-hooks.c
        process-hooks.c
        task-helper.c
        fops-comm.c
        process-tracking.c
        process-tracking-sorted.c
        process-tracking-discovery.c
        process-tracking-show.c
        process-tracking-helpers.c
        process-tracking-file-cache.c
        cb-isolation.c
        cb-banning.c
        netfilter.c
        hash-table-generic.c
        file-process-tracking.c
        syscall_init.c
        file-types.c
        cb-stats.c
        module-hooks.c
        event-factory.c
        cb-module-state-export.c
        tests/run-tests.c
        tests/hashtabl-tests.c
        tests/process-tracking-tests.c
        tests/module-state-tests.c)

message("Building kernel module for target kernel(s): ${KERNEL_LIST}")
foreach(kernel_name ${KERNEL_LIST})
    if(${LOCAL_BUILD})
        set(KERNEL_VERSION "${kernel_name}")
        set(KERNEL_BUILD_DIR "/lib/modules/${kernel_name}/build")
        set(KERNEL_BUILD_PATH ${CMAKE_BINARY_DIR}/kernel-builds)
    else()
        set(KERNEL_VERSION "${CONAN_USER_${kernel_name}_version}")
        set(KERNEL_BUILD_DIR "${CONAN_RES_DIRS_${kernel_name}}")
        set(KERNEL_BUILD_PATH ${ROOT_DIR}/kernel-builds)
    endif()
    cb_add_kernel_module(
            NAME                ${MODULE_NAME}
            KERNEL_NAME         ${kernel_name}
            KERNEL_VERSION      ${KERNEL_VERSION}
            OUTPUT_PATH         ${KERNEL_BUILD_PATH}
            MODULE_SOURCE_DIR   ${CMAKE_PROJECT_SOURCE_DIR}
            KERNEL_BUILD_DIR    ${KERNEL_BUILD_DIR}
            FLAGS               ${CBSENSOR_FLAGS}
            AFLAGS              ${CBSENSOR_AFLAGS}
            VERBOSE             ${VERBOSE}
            SOURCE_FILES        ${SOURCE_FILES}
            USE_NATIVE_COMPILER)
endforeach()
