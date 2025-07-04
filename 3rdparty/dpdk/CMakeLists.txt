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

########################### Build and install #################################

configure_file(${CMAKE_SOURCE_DIR}/scripts/BuildDpdk.sh.in ${CMAKE_BINARY_DIR}/scripts/BuildDpdk.sh @ONLY NEWLINE_STYLE UNIX)
configure_file(${CMAKE_SOURCE_DIR}/scripts/InstallDpdk.sh.in ${CMAKE_BINARY_DIR}/scripts/InstallDpdk.sh @ONLY NEWLINE_STYLE UNIX)

string(APPEND DPDK_BUILD_DIR "${CMAKE_BINARY_DIR}/3rdparty/src/Dpdk-build")
string(APPEND DPDK_BUILD_TYPE "debug")
string(APPEND DPDK_EXAMPLES "skeleton")
string(APPEND DPDK_BUILD_OPTIONS "-Dtests=false")
string(APPEND DPDK_DISABLED_DRV "common/mvep,common/mlx5,net/intel/ipn3ke,net/mana,net/mlx4,net/mlx5,net/mvneta,net/mvpp2,net/nfb,raw/ifpga,crypto/armv8,crypto/ipsec_mb,crypto/mlx5,crypto/mvsam,crypto/uadk,compress/isal,compress/mlx5,compress/uadk,regex/mlx5,vdpa/mlx5,gpu/cuda,power/amd_uncore")
string(APPEND DPDK_BUILD_SYSTEM "meson")
string(APPEND DPDK_INSTALL_COMMAND "rm -rf ${CMAKE_BINARY_DIR}/3rdparty/inst && cd ${CMAKE_BINARY_DIR}/3rdparty/src/Dpdk-build && export DESTDIR=${CMAKE_BINARY_DIR}/3rdparty/inst && meson install")

ExternalProject_Add(
    Dpdk
    GIT_REPOSITORY https://github.com/DPDK/dpdk.git
    GIT_TAG v25.03
    PREFIX ${CMAKE_BINARY_DIR}/3rdparty/
    CONFIGURE_COMMAND ${DPDK_BUILD_SYSTEM} setup --default-library=static --default-both-libraries=static ${CMAKE_BINARY_DIR}/3rdparty/src/Dpdk ${CMAKE_BINARY_DIR}/3rdparty/src/Dpdk-build --buildtype=${DPDK_BUILD_TYPE} -Dexamples=${DPDK_EXAMPLES} ${DPDK_BUILD_OPTIONS} -Ddisable_drivers=${DPDK_DISABLED_DRV}
    UPDATE_COMMAND ${DPDK_BUILD_SYSTEM} setup --reconfigure --default-library=static --default-both-libraries=static ${CMAKE_BINARY_DIR}/3rdparty/src/Dpdk ${CMAKE_BINARY_DIR}/3rdparty/src/Dpdk-build --buildtype=${DPDK_BUILD_TYPE} -Dexamples=${DPDK_EXAMPLES} ${DPDK_BUILD_OPTIONS} -Ddisable_drivers=${DPDK_DISABLED_DRV}
    BUILD_COMMAND ${CMAKE_BINARY_DIR}/scripts/BuildDpdk.sh
    INSTALL_COMMAND ${CMAKE_BINARY_DIR}/scripts/InstallDpdk.sh    
)

set(ENV{PKG_CONFIG_SYSROOT_DIR} ${CMAKE_BINARY_DIR}/3rdparty/inst)
set(ENV{PKG_CONFIG_PATH} ${CMAKE_BINARY_DIR}/3rdparty/inst/usr/local/lib/x86_64-linux-gnu/pkgconfig)
set(ENV{PKG_CONFIG_PATH} ${CMAKE_BINARY_DIR}/3rdparty/inst/lib/pkgconfig)
