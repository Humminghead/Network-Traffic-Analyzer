cmake_minimum_required(VERSION 3.11)

include(FindPkgConfig)
find_package(PkgConfig)

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
# list(APPEND CMAKE_PREFIX_PATH ${CMAKE_BINARY_DIR}/3rdparty/inst/lib/cmake/pcapplusplus)

# find_package(PcapPlusPlus)
# if(PCAP_PLUS_PLUS_FOUND)
#   message("!!!!found with pkg-config!!!!")
# endif()

# pkg_check_modules(PCAP_PP "libPcap++")

# message(zzzzzzzzzzzzzzzzzz--->>${PCAP_PP_LINK_LIBRARIES})

#PcapPlusPlus
pkg_check_modules(PCPP "PcapPlusPlus")

ExternalProject_Get_Property(PcapPlusPlus INSTALL_DIR)
set(PCPP_INSTALL_DIR ${INSTALL_DIR})
# message(--------->>>>${PCPP_INSTALL_DIR})

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
#          PcapPlusPlus
#          Pcap++
        ${PCPP_INSTALL_DIR}/lib/libPacket++.a
        ${PCPP_INSTALL_DIR}/lib/libCommon++.a
        ${PCPP_INSTALL_DIR}/lib/libPcap++.a
         # ${PCAP_PP_INSTALL_PREFIX}/lib/libPcap++.a
     )

 target_include_directories(
   ${PROJECT_NAME}
   PRIVATE ${PCPP_INSTALL_DIR}/include)
