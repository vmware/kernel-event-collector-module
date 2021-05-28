cmake_minimum_required(VERSION 2.8.7)

project(bpf_probe)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

FIND_PACKAGE(CbUtil REQUIRED)
cb_configure_flags()
cb_conan_setup(TARGETS)

set(CMAKE_CXX_STANDARD 11)

# We shouldn't need this but without out we lose -g. It's probably because LLVM cmake stuff is overriding flags
set(CMAKE_BUILD_TYPE RelWithDebInfo)

include(CMakeDependentOption)
include(GNUInstallDirs)
include(CheckCXXCompilerFlag)
include(FindCompilerFlag)

set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -static-libstdc++")

find_package(LLVM REQUIRED CONFIG)
message(STATUS "Found LLVM: ${LLVM_INCLUDE_DIRS} ${LLVM_PACKAGE_VERSION}")
# TODO - Remove this and utilize cmake configs similar to how bcc does it.
# This will make cross compiling more flexible.
execute_process(COMMAND "${LLVM_INCLUDE_DIRS}/../bin/llvm-config" --libnames
        OUTPUT_VARIABLE LLVM_LIBS_RAW OUTPUT_STRIP_TRAILING_WHITESPACE)
string(REPLACE " " ";" LLVM_LIBS ${LLVM_LIBS_RAW})
message(STATUS "llvm-config --libnames ${LLVM_LIBS}")

find_package(LibElf REQUIRED)

link_directories(${BCC_LIBRARY_PATHS})
link_directories(${LLVM_LIBRARY_DIRS})

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
        ${EPBF_PROG_CPP})
add_dependencies(bpf-probe bcc_prog)

set_property(TARGET bpf-probe PROPERTY POSITION_INDEPENDENT_CODE 1)
target_link_libraries(bpf-probe
        libapi-static.a
        libbcc-loader-static.a
        libbcc.a
        libbcc_bpf.a
        libb_frontend.a
        libclang_frontend.a

        -Wl,--whole-archive
        clangFrontend.a
        clangSerialization.a
        clangDriver.a
        clangASTMatchers.a
        clangParse.a
        clangSema.a
        clangCodeGen.a
        clangAnalysis.a
        clangRewrite.a
        clangEdit.a
        clangAST.a
        clangLex.a
        clangBasic.a

        ${LLVM_LIBS}

        ${LIBELF_LIBRARIES}

        -Wl,--no-whole-archive

        z
        )
