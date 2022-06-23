cmake_minimum_required(VERSION 2.8)

project(netkit)

set(EXECUTABLE_OUTPUT_PATH .)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3 -Wall -Wno-unused -m64 -fPIC")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -Wall -Wno-unused -m64 -fPIC -std=c++2a")
set(CMAKE_BUILD_TYPE "Release")

include_directories(..)

add_library(netkit STATIC ./http/context.cpp ./http/cors_filter.cpp)
