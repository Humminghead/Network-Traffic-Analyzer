cmake_minimum_required(VERSION 3.20)

project(NetWorkAnalyzer VERSION 0.0.0 LANGUAGES CXX)
###############################################################################
#                         Cmake additional scripts
###############################################################################

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/components/handlers/pcap/cmake/FindPCAP.cmake")

###############################################################################
#                            Global variables
###############################################################################

# set(VAR "VALUE")

###############################################################################
#                               Common
###############################################################################

add_subdirectory(${CMAKE_SOURCE_DIR}/components/netdecoder)
add_subdirectory(${CMAKE_SOURCE_DIR}/components/handlers/pcap)


###############################################################################
#                             Applications
###############################################################################

add_subdirectory(analysers/demo)


###############################################################################
#                              Unit test
###############################################################################

add_subdirectory(${CMAKE_SOURCE_DIR}/tests/components/netdecoder)
