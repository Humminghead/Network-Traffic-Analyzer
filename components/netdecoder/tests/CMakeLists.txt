cmake_minimum_required(VERSION 3.10.2)
project(osidecoder_test LANGUAGES CXX)

link_libraries(GTest::GTest GTest::Main Threads::Threads
    # osidecoder utils
)

# ###
set (TARGET_NAME osidecoder_complete_test)
add_executable(${TARGET_NAME} ${CMAKE_SOURCE_DIR}/osidecoder_complete_test.cpp)
# GenerateXml(${TARGET_NAME})

# ###
set (TARGET_NAME osidecoder_ip4parser_test)
# add_executable(${TARGET_NAME} ip/ip4parser_test.cpp ip/samples_ip4_packets.h )
# GenerateXml(${TARGET_NAME})

# ###
set (TARGET_NAME osidecoder_ip6parser_test)
# add_executable(${TARGET_NAME} ip/ip6parser_test.cpp ip/samples_ip6_packets.h)
# GenerateXml(${TARGET_NAME})

# ###
set (TARGET_NAME osidecoder_ipassembler_test)
# add_executable(${TARGET_NAME} ip/ipassembler_test.cpp)
# GenerateXml(${TARGET_NAME})

if (WITH_DEBUG_SIGNAL)
    add_compile_definitions(DEBUG_SIGNAL)
endif()

