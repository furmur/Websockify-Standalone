cmake_minimum_required (VERSION 2.8)

project(websockify)
set(BIN_NAME websockify)

file(GLOB_RECURSE SRCS src/*.cpp src/*.c)
add_executable (${BIN_NAME} ${SRCS})
