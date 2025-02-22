cmake_minimum_required(VERSION 3.10.2)
project(NtaHandlers LANGUAGES CXX)

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/Pcap)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/Dpdk)

