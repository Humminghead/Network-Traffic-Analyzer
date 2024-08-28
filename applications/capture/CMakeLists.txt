cmake_minimum_required(VERSION 3.11)

project(nta_capture LANGUAGES C CXX)

file(GLOB_RECURSE CPP_FILES "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")

find_package(tpfrserializer REQUIRED)
find_package(Thrift 0.13.0 REQUIRED)

add_executable(${PROJECT_NAME} ${CPP_FILES})
target_link_libraries(${PROJECT_NAME} PRIVATE Poco::Util NtaUtil NtaHandlers NtaNetDecoder tpfrserializer ${Thrift_LIB} models)
