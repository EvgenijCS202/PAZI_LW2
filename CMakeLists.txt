cmake_minimum_required(VERSION 3.10)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -w")
project(lw2)

set(SOURCES
src/main.c
)

add_executable(lw2 ${SOURCES})