

cmake_minimum_required(VERSION 3.12)
project (DynSecExamples)

message(STATUS "PROJECT_SOURCE_DIR: ${PROJECT_SOURCE_DIR}")
message(STATUS "PROJECT_BINARY_DIR: ${PROJECT_BINARY_DIR}")

# Currently still uses the includes intended for kmod build.

# For dynsec.h
include_directories(${PROJECT_SOURCE_DIR}/../../include)
# For auto-generated version.h
include_directories(${PROJECT_BINARY_DIR}/..)

add_executable(dynsec_dev dynsec_dev.c)

