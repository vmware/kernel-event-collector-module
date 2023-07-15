# Copyright 2023 VMware Inc.  All rights reserved.
# SPDX-License-Identifier: GPL-2.0
cmake_minimum_required(VERSION 2.8.7)

project(bpf_file_notify)


message("Project will be built using CB build utility")
FIND_PACKAGE(CbUtil REQUIRED)
cb_configure_flags()
cb_conan_setup(TARGETS)

set(CMAKE_CXX_STANDARD 11)

# We shouldn't need this but without out we lose -g. It's probably because LLVM cmake stuff is overriding flags
set(CMAKE_BUILD_TYPE RelWithDebInfo)

set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -static-libstdc++")

include_directories(${PROJECT_SOURCE_DIR}/../include)


set(BPF_C_FILE ${PROJECT_SOURCE_DIR}/file_notify.bpf.c)
set(BPF_ELF_FILE ${CMAKE_CURRENT_BINARY_DIR}/file_notify.bpf.o)
set(BPF_ELF_FILE_UNSTRIP ${BPF_ELF_FILE}.unstripped)
set(BPF_SKEL_FILE ${CMAKE_CURRENT_BINARY_DIR}/file_notify.skel.h)

set(CLANG $ENV{HOST_COMMAND_PREFIX} ${CONAN_BIN_DIRS_LLVM}/clang)
set(LLVM_STRIP $ENV{HOST_COMMAND_PREFIX} ${CONAN_BIN_DIRS_LLVM}/llvm-strip)
set(BPFTOOL $ENV{HOST_COMMAND_PREFIX} ${CONAN_BIN_DIRS_BPFTOOL}/bpftool)

set(ARCH x86)
if ("$ENV{CMAKE_SYSTEM_PROCESSOR}" MATCHES "aarch64")
set(ARCH arm64)
endif()
set(VMLINUX_INCLUDE ${PROJECT_SOURCE_DIR}/../include/vmlinux/${ARCH})
set(TARGET_ARCH __TARGET_ARCH_${ARCH})

message("CONAN_BIN_DIRS_LLVM: ${CONAN_BIN_DIRS_LLVM}")
message("CONAN_BIN_DIRS_BPFTOOL: ${CONAN_BIN_DIRS_BPFTOOL}")
message("CONAN_INCLUDE_DIRS_LIBBPF: ${CONAN_INCLUDE_DIRS_LIBBPF}")

add_custom_command(
    OUTPUT ${BPF_ELF_FILE} ${BPF_SKEL_FILE}
    COMMAND ${CLANG} -v -g -O2 -Wall
        -target bpf
        -D${TARGET_ARCH}
        -I${CONAN_INCLUDE_DIRS_LIBBPF}
        -I${VMLINUX_INCLUDE}
        -I${PROJECT_SOURCE_DIR}/../include
        -c ${BPF_C_FILE}
        -o ${BPF_ELF_FILE_UNSTRIP}
    COMMAND ${LLVM_STRIP} -g ${BPF_ELF_FILE_UNSTRIP} -o ${BPF_ELF_FILE}
    COMMAND ${BPFTOOL} gen skeleton ${BPF_ELF_FILE} > ${BPF_SKEL_FILE}
    DEPENDS ${BPF_C_FILE}
)
add_custom_target(bpf_skel ALL DEPENDS ${BPF_ELF_FILE} ${BPF_SKEL_FILE})

# Helper C Library
add_library(file-notify STATIC
            file_notify.c
)
# set_property(TARGET file-notify PROPERTY POSITION_INDEPENDENT_CODE 1)
target_include_directories(file-notify PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
add_dependencies(file-notify bpf_skel)
target_link_libraries(file-notify
                      CONAN_PKG::libbpf
                      CONAN_LIB::elfutils_elf
)

# Toy Test Program
add_executable(test_file_notify test_file_notify.c)
target_include_directories(test_file_notify PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(test_file_notify file-notify)

install(FILES ${BPF_SKEL_FILE} DESTINATION include/bpf_file_notify)
install(FILES ${BPF_ELF_FILE} ${BPF_ELF_FILE_UNSTRIP} DESTINATION lib)
