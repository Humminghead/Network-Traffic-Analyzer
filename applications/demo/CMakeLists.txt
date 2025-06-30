cmake_minimum_required(VERSION 3.11)

project(nta_demo LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

file(GLOB_RECURSE CPP_FILES "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")

#find_package(tpfrserializer REQUIRED)
#find_package(Thrift 0.13.0 REQUIRED)
# find_package(Thrift-z 0.13.0 REQUIRED)
# find_package(Boost 1.86.0 REQUIRED)

# message(------------------->>>>>>>>>>>${CMAKE_PREFIX_PATH})

# # Try to find DPDK with pkg-config first!
# find_package(PkgConfig)
# if(PKG_CONFIG_FOUND)
#   pkg_check_modules(DPDK IMPORTED_TARGET libdpdk>=18.11)
# endif()

# # We found using Pkg-Config!
# if(DPDK_FOUND)
#   message("DPDK found with pkg-config")
# endif()

add_executable(${PROJECT_NAME} ${CPP_FILES})
target_link_libraries(
 ${PROJECT_NAME}
 PRIVATE
         # Poco::Util
         # NtaUtil
         # NtaHandlersCommon
         # NtaHandlerPcap
         # NtaHandlerDpdk
         # NtaNetDecoder
         # models
         # z
         # Pcap++
         # PcapPlusPlus
     )
