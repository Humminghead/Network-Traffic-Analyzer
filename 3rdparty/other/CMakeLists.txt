###############################################################################
#                              CMake extensions
###############################################################################
include (FetchContent)

############################## PcapPlusPlus ###################################
ExternalProject_Add(
   PcapPlusPlus
   GIT_REPOSITORY https://github.com/seladb/PcapPlusPlus.git
   GIT_TAG dev
   CMAKE_ARGS -DCMAKE_PREFIX_PATH=${CMAKE_BINARY_DIR}/3rdparty/inst/usr/local -DPCAPPP_USE_DPDK=ON -DPCAPPP_BUILD_EXAMPLES=OFF -DPCAPPP_BUILD_TESTS=OFF -DCMAKE_INSTALL_PREFIX=${CMAKE_BINARY_DIR}/3rdparty/inst
   PREFIX ${CMAKE_BINARY_DIR}/3rdparty/
   INSTALL_DIR ${CMAKE_BINARY_DIR}/3rdparty/inst
)


# ################################## TPfr #######################################
# FetchContent_Declare(
#  TPfr
#  GIT_REPOSITORY https://github.com/Humminghead/ThriftPfrSerializer.git
#  # GIT_TAG 1.0.4
#  GIT_TAG a53eb6d166ec910ae61a18a3b3a125440a8700d6
# )

# ################################## Poco #######################################
# FetchContent_Declare(
#    Poco
#    GIT_REPOSITORY https://github.com/pocoproject/poco.git
#    GIT_TAG main
# )

# ################################ Nlohmann #####################################
# FetchContent_Declare(
#    Nlohmann
#    GIT_REPOSITORY https://github.com/nlohmann/json.git
#    GIT_TAG v3.11.3
# )

FetchContent_MakeAvailable(
   # PcapPlusPlus
   # Poco
   # Thrift
   # TPfr
   # Nlohmann
)
