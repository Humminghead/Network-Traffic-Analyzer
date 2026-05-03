cmake_minimum_required(VERSION 3.10.2)

project(models LANGUAGES CXX)

find_package(tpfr REQUIRED)

add_library(${PROJECT_NAME} INTERFACE)

target_include_directories(${PROJECT_NAME} 
    INTERFACE
    ${PROJECT_SOURCE_DIR}/include
    tpfr::tprf
    )    
