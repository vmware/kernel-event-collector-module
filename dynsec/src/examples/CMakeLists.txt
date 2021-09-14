

cmake_minimum_required(VERSION 3.12)
project (DynSec)

find_package(Threads)

include_directories(${PROJECT_SOURCE_DIR}/../../include)

add_executable(dynsec_dev dynsec_dev.c)
target_link_libraries(dynsec_dev ${CMAKE_THREAD_LIBS_INIT})

