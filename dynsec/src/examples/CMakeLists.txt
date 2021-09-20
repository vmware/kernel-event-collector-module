

cmake_minimum_required(VERSION 3.12)
project (DynSec)

include_directories(${PROJECT_SOURCE_DIR}/../../include)

add_executable(dynsec_dev dynsec_dev.c)

