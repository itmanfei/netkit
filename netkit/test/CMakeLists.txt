cmake_minimum_required(VERSION 2.8)

project(test)

set(third_party_libs libnetkit.a libboost_json.a)
set(system_libs pthread ssl crypto dl)

set(EXECUTABLE_OUTPUT_PATH .)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2 -Wall -Wno-unused -m64 -fPIC")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2 -Wall -Wno-unused -m64 -fPIC -std=c++2a")
set(CMAKE_BUILD_TYPE "Release")

include_directories(. ../..)

link_directories(${CMAKE_CURRENT_SOURCE_DIR}/..)

add_executable(test test_http_router.cpp test_tcp_listener.cpp test_http_server.cpp test_http_client.cpp main.cpp)
target_link_libraries(test ${third_party_libs} ${system_libs})
