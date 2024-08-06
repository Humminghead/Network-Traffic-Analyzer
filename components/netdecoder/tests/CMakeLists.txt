cmake_minimum_required(VERSION 3.10.2)
project(netdecoder_test LANGUAGES CXX)

link_libraries(GTest::GTest GTest::Main Threads::Threads)

# ###
set(TARGET_NAME netdecoder_complete_test)
add_executable(${TARGET_NAME} ${CMAKE_SOURCE_DIR}/netdecoder_complete_test.cpp)
GenerateReport(${TARGET_NAME})

# ###
set(TARGET_NAME netdecoder_ip4parser_test)
# add_executable(${TARGET_NAME} ip/ip4parser_test.cpp ip/samples_ip4_packets.h )
GenerateReport(${TARGET_NAME})

# ###
set(TARGET_NAME netdecoder_ip6parser_test)
# add_executable(${TARGET_NAME} ip/ip6parser_test.cpp ip/samples_ip6_packets.h)
GenerateReport(${TARGET_NAME})

# ###
set(TARGET_NAME netdecoder_ipassembler_test)
add_executable(${TARGET_NAME} ip/ipassembler_test.cpp)
GenerateReport(${TARGET_NAME})

if(WITH_DEBUG_SIGNAL)
  add_compile_definitions(DEBUG_SIGNAL)
endif()
