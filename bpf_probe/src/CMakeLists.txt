# Copyright 2021 VMware Inc.  All rights reserved.
# SPDX-License-Identifier: GPL-2.0
cmake_minimum_required(VERSION 2.8.7)

project(bpf_probe)

if(NOT DEFINED LOCAL_BUILD)
    set(LOCAL_BUILD no)
endif()
if (${LIBBPF})

endif()
if (NOT ${LOCAL_BUILD})
    message("Project will be built using CB build utility")
    FIND_PACKAGE(CbUtil REQUIRED)
    cb_configure_flags()
    cb_conan_setup(TARGETS)
else()
    message("Project will be built using local system libraries")
    add_definitions(-DLOCAL_BUILD)
endif()

set(CMAKE_CXX_STANDARD 11)

# Tell cmake where to find BpfObject module
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/3party/libbpf-bootstrap/tools/cmake/)

# Build vendored libbpf
include(ExternalProject)
ExternalProject_Add(libbpf
  PREFIX libbpf
  SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/3party/libbpf/src
  CONFIGURE_COMMAND ""
  BUILD_COMMAND make
    BUILD_STATIC_ONLY=1
    OBJDIR=${CMAKE_CURRENT_BINARY_DIR}/libbpf/libbpf
    DESTDIR=${CMAKE_CURRENT_BINARY_DIR}/libbpf
    INCLUDEDIR=
    LIBDIR=
    UAPIDIR=
    install
  BUILD_IN_SOURCE TRUE
  INSTALL_COMMAND ""
  STEP_TARGETS build
)

#[[
ExternalProject_Add(bpftool
  PREFIX bpftool
  SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/3party/bpftool/src
  CONFIGURE_COMMAND ""
  BUILD_COMMAND make
    OUTPUT=${CMAKE_CURRENT_BINARY_DIR}/bpftool/
  BUILD_IN_SOURCE TRUE
  INSTALL_COMMAND ""
  STEP_TARGETS build
)

]]
# Set BpfObject input parameters -- note this is usually not necessary unless
# you're in a highly vendored environment (like libbpf-bootstrap)
#[[
set(BPFOBJECT_BPFTOOL_EXE ${CMAKE_CURRENT_BINARY_DIR}/bpftool/bpftool)
set(BPFOBJECT_VMLINUX_H ${CMAKE_CURRENT_SOURCE_DIR}/3party/libbpf-bootstrap/vmlinux/vmlinux.h)
set(LIBBPF_INCLUDE_DIRS ${CMAKE_CURRENT_BINARY_DIR}/libbpf)
set(LIBBPF_LIBRARIES ${CMAKE_CURRENT_BINARY_DIR}/libbpf/libbpf.a)
find_package(BpfObject REQUIRED)

# Build object skeleton and depend skeleton on libbpf build
bpf_object(sensor sensor.bpf.c)
add_dependencies(sensor_skel libbpf-build bpftool-build)
]]

# We shouldn't need this but without out we lose -g. It's probably because LLVM cmake stuff is overriding flags
set(CMAKE_BUILD_TYPE RelWithDebInfo)

set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -static-libstdc++")


message("libbpf bin dir: ${CMAKE_CURRENT_BINARY_DIR}")
include_directories(${PROJECT_SOURCE_DIR}/../include ${CMAKE_CURRENT_BINARY_DIR}/libbpf ${CMAKE_CURRENT_BINARY_DIR}/boost)

# set(EPBF_PROG_CPP ${CMAKE_CURRENT_BINARY_DIR}/cb_ebpfprog.cpp)
# set(EBPF_PPRG_SRC ${PROJECT_SOURCE_DIR}/bcc_sensor.c)
# set(GENERATE_SH   ${PROJECT_SOURCE_DIR}/generate.sh)

# # generate bcc string file
# add_custom_command(
#         OUTPUT ${EPBF_PROG_CPP}
#         COMMAND chmod a+x ${GENERATE_SH}
#         COMMAND ${GENERATE_SH} ${EBPF_PPRG_SRC} ${EPBF_PROG_CPP}
#         DEPENDS ${GENERATE_SH} ${EBPF_PPRG_SRC}
#         COMMENT "Generating BPF Program ${EPBF_PROG_CPP}"
# )
#set(BPFTOOL bpftool)

#add_custom_target(bcc_prog ALL DEPENDS ${EPBF_PROG_CPP})

add_library(bpf-probe STATIC
        LibbpfApi.cpp
        BpfProgram.cpp)
add_dependencies(bpf-probe libbpf-build)
set_property(TARGET bpf-probe PROPERTY POSITION_INDEPENDENT_CODE 1)

if (NOT ${LOCAL_BUILD})
    target_link_libraries(bpf-probe
            #CONAN_PKG::bcc
            CONAN_PKG::libbpf
            #libbpf
            #-Wl,--whole-archive
            #CONAN_PKG::llvm
            CONAN_LIB::elfutils_elf
            -Wl,--no-whole-archive
            CONAN_PKG::Boost

            z rt dl pthread m
            )
else()
    target_link_libraries(bpf-probe
#        sensor_skel
        #${LIBBPF_LIBRARIES}
        #bcc
        #-Wl,--whole-archive
        #/usr/lib/x86_64-linux-gnu/libelf.so
        #/usr/lib/x86_64-linux-gnu/libz.so
    )
endif()

add_executable(check_probe check_probe.cpp)
add_dependencies(check_probe bpf-probe)
target_link_libraries(check_probe
        CONAN_PKG::libbpf
        bpf-probe 
)

# add_subdirectory(tests)

include(constants.cmake)

install(TARGETS check_probe PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE DESTINATION .)


set(CPACK_OUTPUT_FILE_PREFIX $ENV{BUILD_DIR}/install-packages/$ENV{CMAKE_SYSTEM_PROCESSOR})
set(CPACK_GENERATOR "TGZ")
set(CPACK_PACKAGE_FILE_NAME ${CHECK_PROBE_KIT_FILE})
set(CPACK_PACKAGE_DIRECTORY ${PROJECT_BINARY_DIR})

include(CPack)
