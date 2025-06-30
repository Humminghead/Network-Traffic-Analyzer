cmake_minimum_required(VERSION 3.10.2)

include(FindPkgConfig)
find_package(PkgConfig)

project(NtaHandlerDpdk LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

pkg_check_modules(DPDK "libdpdk")

set(DPDK_STATIC_LIBRARIES_GENERATED "")
foreach(DPDK_LIB_SO_FULL_PATH ${DPDK_LINK_LIBRARIES})
  string(REGEX REPLACE "[.]so" ".a" TMP_LIB ${DPDK_LIB_SO_FULL_PATH})
  list(APPEND DPDK_STATIC_LIBRARIES_GENERATED ${TMP_LIB})
  message(DEBUG "IN: ${DPDK_LIB_SO_FULL_PATH}")
  message(DEBUG "OUT: ${TMP_LIB}\n")
endforeach()

file(GLOB_RECURSE CPP_FILES "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")
add_library(${PROJECT_NAME} OBJECT ${CPP_FILES})

target_link_libraries(
  ${PROJECT_NAME}
  PRIVATE NtaHandlersCommon
          NtaUtil
          NtaNetDecoder
          nlohmann_json
          Pcap++
          ${PCAP_LIBRARIES}
          ${DPDK_STATIC_LIBRARIES_GENERATED})

# message(----->${DPDK_STATIC_LIBRARIES_GENERATED})

target_include_directories(
  ${PROJECT_NAME}
  PRIVATE ${PCAP_INCLUDE_DIRS} ${DPDK_INCLUDE_DIRS}
  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
