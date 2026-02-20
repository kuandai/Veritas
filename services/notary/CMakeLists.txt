file(GLOB_RECURSE NOTARY_SOURCES CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/src/*.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cc"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cxx"
)

if(NOTARY_SOURCES)
  find_package(OpenSSL REQUIRED)
  find_package(protobuf REQUIRED CONFIG)
  find_package(gRPC REQUIRED CONFIG)
  add_executable(veritas_notary ${NOTARY_SOURCES})
  target_include_directories(veritas_notary
    PRIVATE
      ${CMAKE_CURRENT_SOURCE_DIR}/src
      ${CMAKE_BINARY_DIR}/protocol
  )
  target_link_libraries(veritas_notary
    PRIVATE
      veritas_shared
      veritas_protocol
      protobuf::libprotobuf
      gRPC::grpc++
      OpenSSL::Crypto
  )
  target_compile_features(veritas_notary PRIVATE cxx_std_20)
endif()
