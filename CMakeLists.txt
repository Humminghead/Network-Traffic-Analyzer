cmake_minimum_required(VERSION 3.20)

###############################################################################
#                              CMake extensions
###############################################################################
include (FetchContent)

###############################################################################
#                              Project
###############################################################################
project(NetWorkAnalyzer VERSION 0.0.0 LANGUAGES CXX)

###############################################################################
#                         Cmake additional scripts
###############################################################################
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/components/handlers/cmake/FindPCAP.cmake")

###############################################################################
#                               3rdParty
###############################################################################
FetchContent_Declare(
  ThriftPfrSerializer
  GIT_REPOSITORY https://github.com/Humminghead/ThriftPfrSerializer.git
  GIT_TAG 1.0.3
)

FetchContent_Declare(
    Poco
    GIT_REPOSITORY https://github.com/pocoproject/poco.git
    GIT_TAG main
)

FetchContent_MakeAvailable(
    ThriftPfrSerializer
    Poco)

###############################################################################
#                            Global variables
###############################################################################
list(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)

###############################################################################
#                               Common
###############################################################################
add_subdirectory(${CMAKE_SOURCE_DIR}/components/Netdecoder)
add_subdirectory(${CMAKE_SOURCE_DIR}/components/Handlers)
add_subdirectory(${CMAKE_SOURCE_DIR}/components/Util)

###############################################################################
#                             Applications
###############################################################################
# add_subdirectory(analysers/demo)
add_subdirectory(applications/capture)

###############################################################################
#                              Unit test
###############################################################################
add_subdirectory(${CMAKE_SOURCE_DIR}/tests/components/netdecoder)
