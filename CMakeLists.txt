cmake_minimum_required (VERSION 2.8)

project(websockify)

if(EXISTS ${CMAKE_SOURCE_DIR}/.git)
    find_package(Git)
    if(GIT_FOUND)
        execute_process(
            COMMAND "${GIT_EXECUTABLE}" describe --tags --abbrev=0
            WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
            RESULT_VARIABLE GIT_RESULT
            ERROR_VARIABLE GIT_ERROR
            OUTPUT_VARIABLE APP_VERSION
            OUTPUT_STRIP_TRAILING_WHITESPACE
        )
        if(NOT GIT_RESULT EQUAL 0)
            message(FATAL_ERROR "git describe error: " ${GIT_ERROR})
        endif()
        message(STATUS "version from git tags: " ${APP_VERSION})
    else(GIT_FOUND)
        MESSAGE(FATAL_ERROR "can't find Git package")
    endif(GIT_FOUND)
else(EXISTS ${CMAKE_SOURCE_DIR}/.git)
    message(FATAL_ERROR "git repository required")
endif(EXISTS ${CMAKE_SOURCE_DIR}/.git)

add_subdirectory(src)
