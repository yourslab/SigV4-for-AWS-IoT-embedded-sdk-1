project(HailMary)
cmake_minimum_required(VERSION 3.20)

set(CMAKE_BUILD_TYPE "Debug")
set(CMAKE_C_FLAGS "-Wall -Wextra -O0 -ggdb")

find_package(OpenSSL REQUIRED)

include(sigv4FilePaths.cmake)

add_executable(
    run_demo
        "main.c"
        ${SIGV4_SOURCES}
)

target_link_libraries(run_demo OpenSSL::SSL)

target_compile_definitions(
    run_demo
    PUBLIC
        SIGV4_DO_NOT_USE_CUSTOM_CONFIG
)

target_include_directories(
    run_demo
    PUBLIC
        ${SIGV4_INCLUDE_PUBLIC_DIRS}
)