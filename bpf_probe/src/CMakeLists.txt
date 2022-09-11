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
set(BPF_C_FILE ${PROJECT_SOURCE_DIR}/sensor.bpf.c)
set(BPF_ELF_FILE ${CMAKE_CURRENT_BINARY_DIR}/sensor.bpf.o)
set(BPF_ELF_FILE_UNSTRIP ${BPF_ELF_FILE}.unstripped)
set(BPF_SKEL_FILE ${CMAKE_CURRENT_BINARY_DIR}/sensor.skel.h)
set(CLANG ${CONAN_BIN_DIRS_LLVM}/clang)
set(LLMV_STRIP ${CONAN_BIN_DIRS_LLVM}/llvm-strip)
set(BPFTOOL ${CONAN_BIN_DIRS_BPFTOOL}/bpftool)

set(ARCH x86)
set(VMLINUX_INCLUDE ${PROJECT_SOURCE_DIR}/../include/vmlinux/${ARCH})
set(TARGET_ARCH __TARGET_ARCH_${ARCH})

message("CONAN_BIN_DIRS_LLVM: ${CONAN_BIN_DIRS_LLVM}")
message("CONAN_BIN_DIRS_BPFTOOL: ${CONAN_BIN_DIRS_BPFTOOL}")

add_custom_command(
        OUTPUT ${BPF_ELF_FILE} ${BPF_SKEL_FILE}
        COMMAND ${CLANG} -g -O2 -Wall
        -target bpf
        -D${TARGET_ARCH}
        -I${CONAN_INCLUDE_DIRS_LIBBPF}
        -I${VMLINUX_INCLUDE}
        -c ${BPF_C_FILE}
        -o ${BPF_ELF_FILE_UNSTRIP}
        COMMAND ${LLMV_STRIP} -g ${BPF_ELF_FILE_UNSTRIP} -o ${BPF_ELF_FILE}
        COMMAND ${BPFTOOL} gen skeleton ${BPF_ELF_FILE} > ${BPF_SKEL_FILE}
        DEPENDS ${BPF_C_FILE}
)
add_custom_target(bpf_skel ALL DEPENDS ${BPF_ELF_FILE} ${BPF_SKEL_FILE})

# We shouldn't need this but without out we lose -g. It's probably because LLVM cmake stuff is overriding flags
set(CMAKE_BUILD_TYPE RelWithDebInfo)

set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -static-libstdc++")


message("libbpf bin dir: ${CMAKE_CURRENT_BINARY_DIR}")
include_directories(${PROJECT_SOURCE_DIR}/../include ${CMAKE_CURRENT_BINARY_DIR}/libbpf ${CMAKE_CURRENT_BINARY_DIR}/boost ${CMAKE_CURRENT_BINARY_DIR})

add_library(bpf-probe STATIC
        LibbpfApi.cpp
        BpfProgram.cpp)
add_dependencies(bpf-probe bpf_skel)
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
