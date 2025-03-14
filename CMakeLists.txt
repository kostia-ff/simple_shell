cmake_minimum_required(VERSION 3.15)

project(shell LANGUAGES C)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -pedantic")
set(CMAKE_BUILD_TYPE Release)

add_executable(shell_march src/main.c)
