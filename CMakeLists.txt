cmake_minimum_required(VERSION 3.20)

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
#                            Global variables
###############################################################################
list(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)

###############################################################################
#                               3rdParty
###############################################################################
add_subdirectory(${CMAKE_SOURCE_DIR}/3rdparty)

###############################################################################
#                               Common
###############################################################################
#add_subdirectory(${CMAKE_SOURCE_DIR}/components/Netdecoder)
#add_subdirectory(${CMAKE_SOURCE_DIR}/components/Handlers)
#add_subdirectory(${CMAKE_SOURCE_DIR}/components/Util)
#add_subdirectory(${CMAKE_SOURCE_DIR}/models)

###############################################################################
#                             Applications
###############################################################################
# add_subdirectory(analysers/demo)
#add_subdirectory(applications/capture)

###############################################################################
#                              Unit test
###############################################################################
#FILE(GLOB_RECURSE TESTS_PROJECTS ${CMAKE_SOURCE_DIR}/tests/*/CMakeLists.txt)
#foreach(TEST ${TESTS_PROJECTS})
#    string(REGEX REPLACE "\/CMakeLists.+" "" PATH ${TEST})
#    add_subdirectory(${PATH})
#endforeach()


