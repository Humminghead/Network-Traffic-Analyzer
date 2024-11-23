cmake_minimum_required(VERSION 3.10.2)

###############################################################################
#                            Project setup
###############################################################################

include(GenerateReport)

project(models_test LANGUAGES CXX)

find_package(Thrift 0.13.0 REQUIRED)

find_package(GTest)
link_libraries(
    GTest::GTest GTest::Main Threads::Threads
    tpfrserializer
    ${Thrift_LIB}
)

###############################################################################
#                               Tests
###############################################################################

#Capture model
set (TARGET_NAME capture_model_test)
add_executable(${TARGET_NAME} CaptureModelTest.cpp)
GenerateReport(${TARGET_NAME})
