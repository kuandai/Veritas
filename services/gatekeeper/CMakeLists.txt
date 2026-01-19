file(GLOB_RECURSE GATEKEEPER_SOURCES CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/src/*.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cc"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cxx"
)

if(GATEKEEPER_SOURCES)
  add_executable(veritas_gatekeeper ${GATEKEEPER_SOURCES})
  target_link_libraries(veritas_gatekeeper PRIVATE veritas_shared)
  target_compile_features(veritas_gatekeeper PRIVATE cxx_std_20)
endif()
