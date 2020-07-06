# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
# Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

cmake_minimum_required(VERSION 2.8.7)
project (KernelEventCollectorModule)

FIND_PACKAGE(CbUtil REQUIRED)
FIND_PACKAGE(CbKernelUtil REQUIRED)

set(ROOT_DIR "${CMAKE_SOURCE_DIR}/..")

cb_configure_flags(ENABLE_FORTIFY "ON"
                   ENABLE_EXTRA_WARNINGS "ON")
cb_conan_setup(TARGETS
               CONAN_INCLUDE ${ROOT_DIR}/conanbuildinfo.cmake)

set(KERNEL_BUILD_PATH ${ROOT_DIR}/kernel-builds)

set(CBSENSOR_AFLAGS "")
set(CBSENSOR_FLAGS "")

set(INCLUDE_DIR ${PROJECT_SOURCE_DIR}/../include)

set(CBSENSOR_AFLAGS "${CBSENSOR_AFLAGS} -I${CMAKE_CURRENT_SOURCE_DIR}")
set(CBSENSOR_AFLAGS "${CBSENSOR_AFLAGS} -I${INCLUDE_DIR}")

set(CBSENSOR_FLAGS "${CBSENSOR_FLAGS} -Wall")
set(CBSENSOR_FLAGS "${CBSENSOR_FLAGS} -Wformat")
set(CBSENSOR_FLAGS "${CBSENSOR_FLAGS} -Werror")
set(CBSENSOR_FLAGS "${CBSENSOR_FLAGS} -include \"version.h\"")
set(CBSENSOR_FLAGS "${CBSENSOR_FLAGS} -I${CMAKE_CURRENT_SOURCE_DIR}")
set(CBSENSOR_FLAGS "${CBSENSOR_FLAGS} -I${ROOT_DIR}/include")
set(CBSENSOR_FLAGS "${CBSENSOR_FLAGS} -I${CONAN_INCLUDE_DIRS_EVENTCOLLECTOR}")
set(CBSENSOR_FLAGS "${CBSENSOR_FLAGS} ${VERACODE_FLAGS}")
set(CBSENSOR_FLAGS "${CBSENSOR_FLAGS} -DPRODVER=${NAME_SFX}")

#if("${CMAKE_BUILD_TYPE}" STREQUAL "Veracode" )
#    set(VERACODE_FLAGS ${CMAKE_C_FLAGS_VERACODE})
#endif()

set (MODULE_NAME ${MODULE_NAME}_${MODULE_VERSION_SUFFIX})

configure_file(${INCLUDE_DIR}/version.h.in ${INCLUDE_DIR}/version.h)

configure_file(cb-module-state-export.c.in ${CMAKE_CURRENT_SOURCE_DIR}/cb-module-state-export.c)

foreach(kernel_name ${KERNEL_LIST})
    cb_add_kernel_module(
        NAME                ${MODULE_NAME}
        KERNEL_NAME         ${kernel_name}
        KERNEL_VERSION      ${CONAN_USER_${kernel_name}_version}
        OUTPUT_PATH         ${KERNEL_BUILD_PATH}
        MODULE_SOURCE_DIR   ${CMAKE_PROJECT_SOURCE_DIR}
        KERNEL_BUILD_DIR    ${CONAN_RES_DIRS_${kernel_name}}
        FLAGS               ${CBSENSOR_FLAGS}
        AFLAGS              ${CBSENSOR_AFLAGS}
        VERBOSE             ${VERBOSE}
        SOURCE_FILES        drvmain.c
                            hook-tracking.c
                            findsyms.c
                            page-helpers.c
                            path-buffers.c
                            mem-cache.c
                            rbtree-helper.c
                            file-helper.c
                            file-hooks.c
                            patch-sched.c
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
        USE_NATIVE_COMPILER)
endforeach()
