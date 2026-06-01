cmake_minimum_required(VERSION 3.11)

include(CheckSymbolExists)

project(nta_capture LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

file(GLOB_RECURSE CPP_FILES "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")

find_package(tpfr REQUIRED)
find_package(Poco REQUIRED COMPONENTS Util-debug Foundation-debug)
find_package(nlohmann_json REQUIRED)

add_executable(${PROJECT_NAME} ${CPP_FILES})
target_link_libraries(
  ${PROJECT_NAME}
  PRIVATE poco::poco
          nlohmann_json::nlohmann_json
          tpfr::tpfr
          ${Thrift_LIB}
          ${Thrift_Z_LIB}
          $<IF:$<CONFIG:Debug>,libPocoUtild.a,libPocoUtil.a>
          $<IF:$<CONFIG:Debug>,libPocoFoundationd.a,libPocoFoundation.a>
          NtaUtil
          NtaHandlersCommon
          NtaHandlerPcap
          NtaHandlerDpdk
          NtaNetDecoder
          models          
        )

# libbsd
check_symbol_exists(strlcpy "string.h" STRLCPY_IN_LIBC)

if(NOT STRLCPY_IN_LIBC)
  find_library(LBSD_LIBS NAMES bsd REQUIRED)
  target_link_libraries(${PROJECT_NAME} PRIVATE ${LBSD_LIBS})
endif()
