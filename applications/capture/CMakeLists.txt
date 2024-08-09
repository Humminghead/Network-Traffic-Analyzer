cmake_minimum_required(VERSION 3.11)

project(nta_capture LANGUAGES C CXX)

add_executable(${PROJECT_NAME} main.cpp)
target_link_libraries(${PROJECT_NAME} PRIVATE Poco::Util )

# set_target_properties (${PROJECT_NAME} PROPERTIES
#     INTERFACE_COMPILE_FEATURES "c_std_99")

# target_compile_features(${PROJECT_NAME} INTERFACE c_std_17 cxx_std_17)

#------------------------------------------------------------------
#
#------------------------------------------------------------------

include(GNUInstallDirs)
install(TARGETS ${PROJECT_NAME}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
