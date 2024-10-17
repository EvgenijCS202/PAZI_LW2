cmake_minimum_required(VERSION 3.10)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "-Wno-deprecated-declarations")
project(lw2)

set(SOURCES
src/main.cpp
)

add_executable(lw2 ${SOURCES})
find_package(OpenSSL REQUIRED)
target_link_libraries(lw2 OpenSSL::Crypto)