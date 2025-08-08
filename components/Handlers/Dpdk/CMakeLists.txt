cmake_minimum_required(VERSION 3.10.2)

include(FindPkgConfig)
find_package(PkgConfig)

project(NtaHandlerDpdk LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# DPDK
pkg_check_modules(DPDK "libdpdk")

if(NOT DPDK_FOUND)
  message(FATAL_ERROR "DPDK wansn't found!")
else()
  message(STATUS "DPDK was found: ${DPDK_LIBRARY_DIRS}")
endif()

set(DPDK_STATIC_LIBRARIES_GENERATED "")
foreach(DPDK_LIB_SO_FULL_PATH ${DPDK_LINK_LIBRARIES})
  string(REGEX REPLACE "[.]so" ".a" TMP_LIB ${DPDK_LIB_SO_FULL_PATH})
  list(APPEND DPDK_STATIC_LIBRARIES_GENERATED ${TMP_LIB})
  message(DEBUG "IN: ${DPDK_LIB_SO_FULL_PATH}")
  message(DEBUG "OUT: ${TMP_LIB}\n")
endforeach()

# PcapPlusPlus
pkg_check_modules(PCPP "PcapPlusPlus")

if(NOT PCPP_FOUND)
  message(FATAL_ERROR "PcapPlusPlus not found!")
endif()

ExternalProject_Get_Property(PcapPlusPlus INSTALL_DIR)
set(PCPP_INSTALL_DIR ${INSTALL_DIR})

file(GLOB_RECURSE CPP_FILES "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")
add_library(${PROJECT_NAME} OBJECT ${CPP_FILES})

target_link_libraries(
  ${PROJECT_NAME}
  PRIVATE NtaHandlersCommon
          NtaUtil
          NtaNetDecoder
          nlohmann_json
          # Pcap++
          ${PCPP_INSTALL_DIR}/lib/libPcap++.a
          ${PCPP_INSTALL_DIR}/lib/libPacket++.a
          ${PCPP_INSTALL_DIR}/lib/libCommon++.a
          ${PCAP_LIBRARIES}
          ${DPDK_STATIC_LIBRARIES_GENERATED})        

target_include_directories(
  ${PROJECT_NAME}
  PRIVATE ${PCAP_INCLUDE_DIRS} ${NTA_DPDK_INCLUDE_PATH}
          ${NTA_DPDK_INCLUDE_PATH}/pcapplusplus
  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

# It's needed for compile DPDK with our project
target_compile_options(${PROJECT_NAME} PRIVATE "-mssse3")
