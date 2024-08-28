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
file(GLOB CMAKE_FILES ${CMAKE_SOURCE_DIR}/cmake/*.cmake)
foreach(ARG ${CMAKE_FILES})
    list(APPEND CMAKE_MODULE_PATH "${ARG}")
endforeach()

###############################################################################
#                               3rdParty
###############################################################################
FetchContent_Declare(
  TPfr
  GIT_REPOSITORY https://github.com/Humminghead/ThriftPfrSerializer.git
  # GIT_TAG 1.0.4
  GIT_TAG 29562dc2bd15039f8c8e230cd1aface68c2f31bd
)

FetchContent_Declare(
    Poco
    GIT_REPOSITORY https://github.com/pocoproject/poco.git
    GIT_TAG main
)

FetchContent_MakeAvailable(
    TPfr
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
add_subdirectory(${CMAKE_SOURCE_DIR}/models)

###############################################################################
#                             Applications
###############################################################################
# add_subdirectory(analysers/demo)
add_subdirectory(applications/capture)

###############################################################################
#                              Unit test
###############################################################################
add_subdirectory(${CMAKE_SOURCE_DIR}/tests/components/netdecoder)
