cmake_minimum_required(VERSION 3.10.2)

include(FindPkgConfig)
find_package(PkgConfig)

project(NtaHandlerDpdk LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# PcapPlusPlus
find_package(PcapPlusPlus REQUIRED)

# Nlohmann
find_package(nlohmann_json REQUIRED)

# Handler cpp files
file(GLOB_RECURSE CPP_FILES "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")
add_library(${PROJECT_NAME} OBJECT ${CPP_FILES})

target_link_libraries(
  ${PROJECT_NAME}
  PRIVATE NtaHandlersCommon NtaUtil NtaNetDecoder nlohmann_json::nlohmann_json
          pcapplusplus::pcapplusplus)

target_include_directories(
  ${PROJECT_NAME}
  PRIVATE ${PcapPlusPlus_INCLUDE_DIR}
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
         $<INSTALL_INTERFACE:include/${PROJECT_NAME}>)

# It's needed for compile DPDK with our project
target_compile_options(${PROJECT_NAME} PRIVATE "-mssse3")
