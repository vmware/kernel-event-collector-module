# Copyright 2021 VMware Inc.  All rights reserved.
# SPDX-License-Identifier: GPL-2.0
cmake_minimum_required(VERSION 2.8.7)

project(bpf_probe)

if(NOT DEFINED LOCAL_BUILD)
    set(LOCAL_BUILD no)
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

# We shouldn't need this but without out we lose -g. It's probably because LLVM cmake stuff is overriding flags
set(CMAKE_BUILD_TYPE RelWithDebInfo)

set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -static-libstdc++")

include_directories(${PROJECT_SOURCE_DIR}/../include)

set(EPBF_PROG_CPP ${CMAKE_CURRENT_BINARY_DIR}/cb_ebpfprog.cpp)
set(TRANSPORT_HDR ${PROJECT_SOURCE_DIR}/../include/transport.h)
set(EBPF_PPRG_SRC ${PROJECT_SOURCE_DIR}/bcc_sensor.c)
set(SENSOR_BPF_SRC ${PROJECT_SOURCE_DIR}/sensor.bpf.c)
set(SENSOR_BPF_SRC_R ${CMAKE_CURRENT_BINARY_DIR}/sensor.bpf.h)
set(GENERATE_SH   ${PROJECT_SOURCE_DIR}/generate.sh)

add_custom_command(
        OUTPUT ${EPBF_PROG_CPP} ${SENSOR_BPF_SRC_R}
        COMMAND chmod a+x ${GENERATE_SH}
        COMMAND ${GENERATE_SH} ${EBPF_PPRG_SRC} ${TRANSPORT_HDR} ${EPBF_PROG_CPP} ${SENSOR_BPF_SRC}
        DEPENDS ${GENERATE_SH} ${EBPF_PPRG_SRC}
        COMMENT "Generating BPF Program ${EPBF_PROG_CPP}"
)

add_custom_target(bcc_prog ALL DEPENDS ${EPBF_PROG_CPP})

add_library(bpf-probe STATIC
        BpfApi.cpp
        BpfProgram.cpp
        ${EPBF_PROG_CPP})
add_dependencies(bpf-probe bcc_prog)
set_property(TARGET bpf-probe PROPERTY POSITION_INDEPENDENT_CODE 1)
target_include_directories(bpf-probe PUBLIC ${CONAN_INCLUDE_DIRS_LIBBPF})


if (NOT ${LOCAL_BUILD})
    target_link_libraries(bpf-probe
            CONAN_PKG::bcc

            -Wl,--whole-archive
            CONAN_PKG::llvm
            CONAN_LIB::elfutils_elf
            -Wl,--no-whole-archive
            CONAN_PKG::Boost
    )
else()
    target_link_libraries(bpf-probe
        bcc
        boost
    )
endif()
target_link_libraries(bpf-probe z rt dl pthread m)
add_dependencies(bpf-probe bpf_skel)
target_include_directories(bpf-probe PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
#target_include_directories(check_probe PUBLIC ${CONAN_INCLUDE_DIRS_LIBBPF})


set(BPF_C_FILE ${PROJECT_SOURCE_DIR}/sensor.bpf.c)
set(BPF_ELF_FILE ${CMAKE_CURRENT_BINARY_DIR}/sensor.bpf.o)
set(BPF_ELF_FILE_UNSTRIP ${BPF_ELF_FILE}.unstripped)
set(BPF_SKEL_FILE ${CMAKE_CURRENT_BINARY_DIR}/sensor.skel.h)
set(CLANG $ENV{HOST_COMMAND_PREFIX} ${CONAN_BIN_DIRS_LLVM}/clang)
set(LLVM_STRIP $ENV{HOST_COMMAND_PREFIX} ${CONAN_BIN_DIRS_LLVM}/llvm-strip)
set(BPFTOOL $ENV{HOST_COMMAND_PREFIX} ${CONAN_BIN_DIRS_BPFTOOL}/bpftool)

set(ARCH x86)
if ("${CMAKE_SYSTEM_PROCESSOR}" MATCHES "aarch64")
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

add_executable(check_probe ../check_probe/src/check_probe.cpp)
target_link_libraries(check_probe
        bpf-probe
        z rt dl pthread m
)
add_dependencies(check_probe bpf_skel)
target_include_directories(check_probe PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_include_directories(check_probe PUBLIC ${CONAN_INCLUDE_DIRS_LIBBPF})

add_subdirectory(tests)

include(constants.cmake)

install(TARGETS check_probe PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE DESTINATION .)
install(FILES ${BPF_SKEL_FILE} DESTINATION include)
install(FILES ${BPF_ELF_FILE} ${BPF_ELF_FILE_UNSTRIP} DESTINATION lib)

set(CPACK_OUTPUT_FILE_PREFIX $ENV{BUILD_DIR}/install-packages/${CMAKE_SYSTEM_PROCESSOR})
set(CPACK_GENERATOR "TGZ")
set(CPACK_PACKAGE_FILE_NAME ${CHECK_PROBE_KIT_FILE})
set(CPACK_PACKAGE_DIRECTORY ${PROJECT_BINARY_DIR})

include(CPack)
