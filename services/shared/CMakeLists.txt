file(GLOB_RECURSE VERITAS_SHARED_SOURCES CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/src/*.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cc"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cxx"
)

if(VERITAS_SHARED_SOURCES)
  add_library(veritas_shared STATIC ${VERITAS_SHARED_SOURCES})
else()
  add_library(veritas_shared INTERFACE)
endif()

target_include_directories(veritas_shared
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)

target_compile_features(veritas_shared PUBLIC cxx_std_20)
