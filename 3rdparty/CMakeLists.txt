###############################################################################
#                              CMake extensions
###############################################################################
include (FetchContent)
include (ExternalProject)

###############################################################################
#                               Project extensions
###############################################################################
include (FindNuma)

###############################################################################
#                           Project requred executables
###############################################################################
find_program(NINJA NAMES ninja REQUIRED)
find_program(MESON NAMES meson REQUIRED)

#Try to find pyelftools
find_package(Python3 REQUIRED)
execute_process(COMMAND ${CMAKE_SOURCE_DIR}/scripts/FindPyElfTools.sh OUTPUT_VARIABLE PYELFTOOLS)
if(NOT ${PYELFTOOLS} MATCHES "pyelftools.+")
    message(FATAL_ERROR "Pyelftools not found. Try: sudo apt install python3-pyelftools")
endif()

#FAQ:
#apt install ninja-build
#apt install libnuma1 libnuma-dev
#apt install python3-pyelftools

ExternalProject_Add(
    Dpdk
    GIT_REPOSITORY https://github.com/DPDK/dpdk.git
    GIT_TAG v25.03
    PREFIX ${CMAKE_BINARY_DIR}/3rdparty/
    CONFIGURE_COMMAND meson setup ${CMAKE_BINARY_DIR}/3rdparty/src/Dpdk ${CMAKE_BINARY_DIR}/3rdparty/src/Dpdk-build --buildtype=debug -Dexamples=skeleton -Ddebug=true -Doptimization=0 -Dtests=false -Ddisable_drivers=common/mvep,common/mlx5,net/intel/ipn3ke,net/mana,net/mlx4,net/mlx5,net/mvneta,net/mvpp2,net/nfb,raw/ifpga,crypto/armv8,crypto/ipsec_mb,crypto/mlx5,crypto/mvsam,crypto/uadk,compress/isal,compress/mlx5,compress/uadk,regex/mlx5,vdpa/mlx5,gpu/cuda,power/amd_uncore
    BUILD_COMMAND cd ${CMAKE_BINARY_DIR}/3rdparty/src/Dpdk-build && ninja
    INSTALL_COMMAND cd ${CMAKE_BINARY_DIR}/3rdparty/src/Dpdk-inst && export DESTDIR=${CMAKE_BINARY_DIR}/3rdparty/inst && meson install
)

set(ENV{PKG_CONFIG_SYSROOT_DIR} ${CMAKE_BINARY_DIR}/3rdparty/inst)
set(ENV{PKG_CONFIG_PATH} ${CMAKE_BINARY_DIR}/3rdparty/inst/usr/local/lib/x86_64-linux-gnu/pkgconfig)
# pkg_check_modules(DPDK "libdpdk")

#FetchContent_Declare(
#  TPfr
#  GIT_REPOSITORY https://github.com/Humminghead/ThriftPfrSerializer.git
#  # GIT_TAG 1.0.4
#  GIT_TAG a53eb6d166ec910ae61a18a3b3a125440a8700d6
#)

#FetchContent_Declare(
#    Poco
#    GIT_REPOSITORY https://github.com/pocoproject/poco.git
#    GIT_TAG main
#)

#FetchContent_Declare(
#    Nlohmann
#    GIT_REPOSITORY https://github.com/nlohmann/json.git
#    GIT_TAG v3.11.3
#)

#FetchContent_Declare(
#    PcapPlusPlus
#    GIT_REPOSITORY https://github.com/seladb/PcapPlusPlus.git
#    GIT_TAG dev
#)

#FetchContent_MakeAvailable(
#    PcapPlusPlus
#    Poco
#    # Thrift
#    TPfr
#    Nlohmann
#)


message("--------------->${DPDK_LIBRARIES}")
