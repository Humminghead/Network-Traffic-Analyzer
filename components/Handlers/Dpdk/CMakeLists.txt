cmake_minimum_required(VERSION 3.10.2)

include(FindPkgConfig)
find_package(PkgConfig)

project(NtaHandlerDpdk LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

pkg_check_modules(DPDK "libdpdk")

file(GLOB_RECURSE CPP_FILES "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")

add_library(${PROJECT_NAME} OBJECT ${CPP_FILES})

target_link_libraries(${PROJECT_NAME} PRIVATE ${PCAP_LIBRARIES} NtaHandlersCommon NtaUtil nlohmann_json Pcap++ ${DPDK_LIBRARIES})

target_include_directories(
  ${PROJECT_NAME}
  PRIVATE ${PCAP_INCLUDE_DIRS}
  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
