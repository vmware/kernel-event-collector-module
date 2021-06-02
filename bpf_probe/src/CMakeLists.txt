cmake_minimum_required(VERSION 2.8.7)

project(bpf_probe)

FIND_PACKAGE(CbUtil REQUIRED)
cb_configure_flags()
cb_conan_setup(TARGETS)

set(CMAKE_CXX_STANDARD 11)

# We shouldn't need this but without out we lose -g. It's probably because LLVM cmake stuff is overriding flags
set(CMAKE_BUILD_TYPE RelWithDebInfo)

set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -static-libstdc++")

include_directories(${PROJECT_SOURCE_DIR}/../include)

set(EPBF_PROG_CPP ${CMAKE_CURRENT_BINARY_DIR}/cb_ebpfprog.cpp)
set(EBPF_PPRG_SRC ${PROJECT_SOURCE_DIR}/bcc_sensor.c)
set(GENERATE_SH   ${PROJECT_SOURCE_DIR}/generate.sh)

add_custom_command(
        OUTPUT ${EPBF_PROG_CPP}
        COMMAND chmod a+x ${GENERATE_SH}
        COMMAND ${GENERATE_SH} ${EBPF_PPRG_SRC} ${EPBF_PROG_CPP}
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

target_link_libraries(bpf-probe
        CONAN_PKG::bcc

        -Wl,--whole-archive
        CONAN_PKG::llvm
        CONAN_LIB::elfutils_elf
        -Wl,--no-whole-archive

        z rt dl pthread m
        )

add_executable(check_probe check_probe.cpp)
target_link_libraries(check_probe
        bpf-probe
        z rt dl pthread m)

add_subdirectory(tests)
