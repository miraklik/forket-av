cmake_minimum_required(VERSION 3.15)
project(FORKET VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(include)

set(SOURCES 
    src/main.cpp 
    src/scanner.cpp 
    src/utils.cpp
    src/hash.cpp
    src/realtime_monitoring.cpp
)

if (APPLE)
    list(APPEND SOURCES src/mach_o.cpp)
    find_library(CORESERVICES_LIB CoreServices)
endif()

if (WIN32)
    list(APPEND SOURCES src/pe_analyzer.cpp)
endif()

add_executable(forket ${SOURCES})

if (APPLE)
    target_link_libraries(forket ${CORESERVICES_LIB})
endif()