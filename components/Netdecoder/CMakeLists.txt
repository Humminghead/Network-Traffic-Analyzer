cmake_minimum_required(VERSION 3.10.2)
project(NtaNetDecoder LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

file(GLOB_RECURSE CPP_FILES "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp")

add_library(${PROJECT_NAME} OBJECT ${CPP_FILES})

target_include_directories(${PROJECT_NAME} 
  PRIVATE 
    # ${CMAKE_CURRENT_SOURCE_DIR}/include/ip
    ${CMAKE_CURRENT_SOURCE_DIR}/include/pppoe
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
