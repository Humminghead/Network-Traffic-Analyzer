cmake_minimum_required(VERSION 3.10.2)
project(NtaHandlers LANGUAGES CXX)

# Pcap
include(FindPCAP)

if(NOT PCAP_FOUND)
  message(FATAL_ERROR "libpcap can not found")
endif()

file(GLOB_RECURSE CPP_FILES "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")

add_library(${PROJECT_NAME} OBJECT ${CPP_FILES})

target_link_libraries(${PROJECT_NAME} PRIVATE ${PCAP_LIBRARIES} NtaUtil)

target_include_directories(
  ${PROJECT_NAME}
  PRIVATE ${PCAP_INCLUDE_DIRS}
  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
