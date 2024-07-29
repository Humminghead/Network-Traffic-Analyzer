cmake_minimum_required(VERSION 3.10.2)
project(netdecoder_test LANGUAGES CXX)

find_package(GTest)

link_libraries(
    GTest::GTest GTest::Main Threads::Threads
    netdecoder
)

###############################################################################
#                               Tests
###############################################################################

#Full
set (TARGET_NAME netdecoder_complete_test)
add_executable(${TARGET_NAME} netdecoder_complete_test.cpp)
# GenerateXml(${TARGET_NAME})

#IP4
set (TARGET_NAME netdecoder_ip4handler_test)
add_executable(${TARGET_NAME} ip/ip4handler_test.cpp)
# GenerateXml(${TARGET_NAME})

#IP6
set (TARGET_NAME netdecoder_ip6parser_test)
add_executable(${TARGET_NAME} ip/ip6parser_test.cpp ip/samples_ip6_packets.h)
# GenerateXml(${TARGET_NAME})

#IP assembly
# set (TARGET_NAME netdecoder_ipassembler_test)
# add_executable(${TARGET_NAME} ip/ipassembler_test.cpp)
# GenerateXml(${TARGET_NAME})
