cmake_minimum_required(VERSION 3.24)

project(Veritas LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(VERITAS_BUILD_LIB "Build libveritas library" ON)
option(VERITAS_BUILD_SERVICES "Build backend services" ON)
option(VERITAS_BUILD_PROTOCOL "Build protocol artifacts" ON)

include(CTest)

if(VERITAS_BUILD_PROTOCOL)
  add_subdirectory(protocol)
endif()

if(VERITAS_BUILD_LIB)
  add_subdirectory(libveritas)
endif()

if(VERITAS_BUILD_SERVICES)
  add_subdirectory(services)
endif()

if(BUILD_TESTING)
  add_subdirectory(tests)
endif()
