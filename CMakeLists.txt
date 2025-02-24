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
  GIT_TAG a53eb6d166ec910ae61a18a3b3a125440a8700d6
)

FetchContent_Declare(
    Poco
    GIT_REPOSITORY https://github.com/pocoproject/poco.git
    GIT_TAG main
)

FetchContent_Declare(
    Nlohmann
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG v3.11.3
)

FetchContent_Declare(
    PcapPlusPlus
    GIT_REPOSITORY https://github.com/seladb/PcapPlusPlus.git
    GIT_TAG dev
)

# FetchContent_Declare(
#     Thrift
#     GIT_REPOSITORY https://github.com/apache/thrift.git
#     GIT_TAG master
# )

FetchContent_MakeAvailable(    
    PcapPlusPlus
    Poco
    # Thrift
    TPfr
    Nlohmann
)
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
FILE(GLOB_RECURSE TESTS_PROJECTS ${CMAKE_SOURCE_DIR}/tests/*/CMakeLists.txt)
foreach(TEST ${TESTS_PROJECTS})
    string(REGEX REPLACE "\/CMakeLists.+" "" PATH ${TEST})
    add_subdirectory(${PATH})
endforeach()


