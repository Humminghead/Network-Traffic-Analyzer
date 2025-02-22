cmake_minimum_required(VERSION 3.11)

project(nta_capture LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

file(GLOB_RECURSE CPP_FILES "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")

#find_package(tpfrserializer REQUIRED)
find_package(Thrift 0.13.0 REQUIRED)
# find_package(Thrift-z 0.13.0 REQUIRED)
# find_package(Boost 1.86.0 REQUIRED)

add_executable(${PROJECT_NAME} ${CPP_FILES})
target_link_libraries(
  ${PROJECT_NAME}
  PRIVATE Poco::Util
          NtaUtil
          Pcap
          NtaNetDecoder
          tpfrserializer
          ${Thrift_LIB}
          ${Thrift_Z_LIB}
          models
          nlohmann_json
          # boost_pfr
          # boost_numeric_conversion
          # boost_cobalt
          # boost_asio
          # boost_system
          # boost_circular_buffer
          # boost_intrusive
          # boost_smart_ptr
          # boost_lockfree
          z
      )
