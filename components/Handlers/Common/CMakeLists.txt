cmake_minimum_required(VERSION 3.10.2)
project(NtaHandlersCommon LANGUAGES CXX)

set(LIB_INC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)

file(GLOB_RECURSE H_FILES "${LIB_INC_DIR}/*.h")

add_library(${PROJECT_NAME} INTERFACE ${H_FILES})

target_include_directories(${PROJECT_NAME} INTERFACE ${LIB_INC_DIR})
