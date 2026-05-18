cmake_minimum_required(VERSION 3.10.2)

include(FindPkgConfig)
find_package(PkgConfig)

project(NtaHandlerDpdk LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Nlohmann
find_package(nlohmann_json REQUIRED)

if(NOT nlohmann_json_FOUND)
  message(FATAL_ERROR "${PROJECT_NAME}: nlohmann_json library not found!")
endif()

# DPDK
set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
find_package(dpdk REQUIRED)

# Handler cpp files
file(GLOB_RECURSE CPP_FILES "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")
add_library(${PROJECT_NAME} OBJECT ${CPP_FILES})

target_link_libraries(
  ${PROJECT_NAME}
  PRIVATE NtaHandlersCommon
          NtaUtil
          NtaNetDecoder
          NtaDevice
          nlohmann_json::nlohmann_json
          -lnuma
          -Wl,--whole-archive
          dpdk::dpdk
          -Wl,--no-whole-archive)

target_include_directories(
  ${PROJECT_NAME}
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
         $<INSTALL_INTERFACE:include/${PROJECT_NAME}>)

# It's needed for compile DPDK with our project
target_compile_options(${PROJECT_NAME} PRIVATE "-mssse3")
