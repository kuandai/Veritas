if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  cmake_minimum_required(VERSION 3.24)
  project(libveritas LANGUAGES CXX)

  set(CMAKE_CXX_STANDARD 20)
  set(CMAKE_CXX_STANDARD_REQUIRED ON)
  set(CMAKE_CXX_EXTENSIONS OFF)
endif()

file(GLOB_RECURSE LIBVERITAS_SOURCES CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/src/*.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cc"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cxx"
)

if(LIBVERITAS_SOURCES)
  add_library(veritas ${LIBVERITAS_SOURCES})
else()
  add_library(veritas INTERFACE)
endif()

target_include_directories(veritas
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_compile_features(veritas PUBLIC cxx_std_20)

find_package(OpenSSL REQUIRED)
find_package(libsodium REQUIRED CONFIG)
find_package(cyrus-sasl REQUIRED CONFIG)
find_package(libsecret REQUIRED CONFIG)

if(NOT TARGET veritas_protocol AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../protocol/CMakeLists.txt")
  add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../protocol protocol)
endif()

if(TARGET veritas_protocol)
  target_link_libraries(veritas PUBLIC veritas_protocol)
endif()

target_link_libraries(veritas
  PUBLIC
    OpenSSL::SSL
    OpenSSL::Crypto
    libsodium::libsodium
    cyrus-sasl::cyrus-sasl
    libsecret::libsecret
)

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/ DESTINATION include)

get_target_property(VERITAS_TARGET_TYPE veritas TYPE)
if(NOT VERITAS_TARGET_TYPE STREQUAL "INTERFACE_LIBRARY")
  install(TARGETS veritas
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
  )
endif()
