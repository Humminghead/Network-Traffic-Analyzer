cmake_minimum_required(VERSION 3.11)

project(nta_capture LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

file(GLOB_RECURSE CPP_FILES "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")

find_package(tpfr REQUIRED)
find_package(Poco REQUIRED COMPONENTS Util Foundation)
find_package(nlohmann_json REQUIRED)
find_package(dpdk REQUIRED)

add_executable(${PROJECT_NAME} ${CPP_FILES})
target_link_libraries(
  ${PROJECT_NAME}
  PRIVATE poco::poco
          libPocoUtil.a
          libPocoFoundation.a
          NtaUtil
          NtaHandlersCommon
          NtaHandlerPcap
          NtaHandlerDpdk
          NtaNetDecoder
          tpfr::tpfr
          ${Thrift_LIB}
          ${Thrift_Z_LIB}
          models
          nlohmann_json::nlohmann_json
          numa
          dpdk::dpdk
          z)
