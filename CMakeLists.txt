cmake_minimum_required(VERSION 3.15)
project(FORKET VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(include)

file(GLOB SOURCES "src/*.cpp")

add_executable(antivirus ${SOURCES})

find_library(CORESERVICES_LIB CoreServices)
target_link_libraries(antivirus ${CORESERVICES_LIB})