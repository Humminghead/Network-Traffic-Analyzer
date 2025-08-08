# ##############################################################################
# CMake extensions
# ##############################################################################
include(FetchContent)

# ############################# Global env's ###################################
set(NTA_3RD_PARTY_INSTALL_PREFIX ${CMAKE_BINARY_DIR}/3rdparty/inst)
set(NTA_3RD_PARTY_INSTALL_DIR ${NTA_3RD_PARTY_INSTALL_PREFIX}/usr/local)
set(NTA_DPDK_INCLUDE_PATH ${NTA_3RD_PARTY_INSTALL_PREFIX}/usr/local/include CACHE PATH "Projects dpdk libraries path")
set(FETCHCONTENT_BASE_DIR ${CMAKE_BINARY_DIR}/3rdparty/_deps)

message(STATUS NTA_3RD_PARTY_INSTALL_PREFIX:${NTA_3RD_PARTY_INSTALL_PREFIX})
message(STATUS NTA_3RD_PARTY_INSTALL_DIR:${NTA_3RD_PARTY_INSTALL_DIR})
message(STATUS NTA_DPDK_INCLUDE_PATH:${NTA_DPDK_INCLUDE_PATH})

set(ENV{PKG_CONFIG_SYSROOT_DIR} ${NTA_3RD_PARTY_INSTALL_PREFIX})
set(ENV{PKG_CONFIG_PATH} ${NTA_3RD_PARTY_INSTALL_DIR}/lib/x86_64-linux-gnu/pkgconfig:${NTA_3RD_PARTY_INSTALL_DIR}/lib/pkgconfig)

message(STATUS Modified PKG_CONFIG_PATH variable:$ENV{PKG_CONFIG_PATH})

# ############################# PcapPlusPlus ###################################
list(APPEND NTA_PCPP_CXX_FLAGS "")

if(NTA_USE_CUSTOM_DPDK_PATH)
    list(APPEND NTA_PCPP_CXX_FLAGS -I${NTA_DPDK_INCLUDE_PATH})
endif()

message(STATUS NTA_PCPP_CXX_FLAGS:${NTA_PCPP_CXX_FLAGS})

ExternalProject_Add(
  PcapPlusPlus
  GIT_REPOSITORY https://github.com/seladb/PcapPlusPlus.git
  GIT_TAG dev
  CMAKE_ARGS -DCMAKE_PREFIX_PATH=${NTA_3RD_PARTY_INSTALL_DIR}
             -DCMAKE_INSTALL_PREFIX=${NTA_3RD_PARTY_INSTALL_DIR}
             -DCMAKE_CXX_FLAGS=${NTA_PCPP_CXX_FLAGS}
             -DPCAPPP_USE_DPDK=ON
             -DPCAPPP_BUILD_EXAMPLES=OFF
             -DPCAPPP_BUILD_TESTS=OFF
  INSTALL_DIR ${NTA_3RD_PARTY_INSTALL_DIR})

# ################################# TPfr #######################################
FetchContent_Declare(
  TPfr
  GIT_REPOSITORY https://github.com/Humminghead/ThriftPfrSerializer.git
  GIT_TAG a53eb6d166ec910ae61a18a3b3a125440a8700d6)

# ################################# Poco #######################################
 FetchContent_Declare( Poco
     GIT_REPOSITORY https://github.com/pocoproject/poco.git
     GIT_TAG poco-1.14.2-release)

# ############################### Nlohmann #####################################
FetchContent_Declare(
  Nlohmann
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG v3.11.3)

FetchContent_MakeAvailable(
     Poco
     TPfr
     Nlohmann)
