find_package(GTest REQUIRED)
find_package(OpenSSL REQUIRED)

option(VERITAS_ENABLE_PROTO_TESTS "Enable protobuf/gRPC-dependent tests" OFF)

set(VERITAS_TEST_SOURCES
  main.cpp
  gatekeeper/fake_salt_test.cpp
  gatekeeper/config_test.cpp
  gatekeeper/rate_limiter_test.cpp
  gatekeeper/session_cache_test.cpp
  gatekeeper/tls_utils_test.cpp
  gatekeeper/token_store_test.cpp
  gatekeeper/token_utils_test.cpp
  ${CMAKE_SOURCE_DIR}/services/gatekeeper/src/config.cpp
  ${CMAKE_SOURCE_DIR}/services/gatekeeper/src/fake_salt.cpp
  ${CMAKE_SOURCE_DIR}/services/gatekeeper/src/rate_limiter.cpp
  ${CMAKE_SOURCE_DIR}/services/gatekeeper/src/secure_erase.cpp
  ${CMAKE_SOURCE_DIR}/services/gatekeeper/src/session_cache.cpp
  ${CMAKE_SOURCE_DIR}/services/gatekeeper/src/tls_utils.cpp
  ${CMAKE_SOURCE_DIR}/services/gatekeeper/src/token_store.cpp
  ${CMAKE_SOURCE_DIR}/services/gatekeeper/src/token_utils.cpp
)

if(VERITAS_ENABLE_PROTO_TESTS)
  find_package(protobuf REQUIRED CONFIG)
  find_package(gRPC REQUIRED CONFIG)
  list(APPEND VERITAS_TEST_SOURCES
    gatekeeper/sasl_server_test.cpp
    ${CMAKE_BINARY_DIR}/protocol/gatekeeper.pb.cc
    ${CMAKE_SOURCE_DIR}/services/gatekeeper/src/sasl_server.cpp
    ${CMAKE_SOURCE_DIR}/services/gatekeeper/src/session_cache.cpp
    ${CMAKE_SOURCE_DIR}/services/gatekeeper/src/token_store.cpp
  )
endif()

add_executable(veritas_gatekeeper_tests ${VERITAS_TEST_SOURCES})

target_include_directories(veritas_gatekeeper_tests
  PRIVATE
    ${CMAKE_SOURCE_DIR}/services/gatekeeper/src
    ${CMAKE_BINARY_DIR}/protocol
)

target_link_libraries(veritas_gatekeeper_tests
  PRIVATE
    GTest::gtest
    OpenSSL::Crypto
)

if(VERITAS_ENABLE_PROTO_TESTS)
  target_link_libraries(veritas_gatekeeper_tests
    PRIVATE
      protobuf::libprotobuf
      gRPC::grpc++
  )
endif()

target_compile_features(veritas_gatekeeper_tests PRIVATE cxx_std_20)

target_compile_definitions(veritas_gatekeeper_tests
  PRIVATE
    VERITAS_DISABLE_SASL
    VERITAS_DISABLE_REDIS
)

add_dependencies(veritas_gatekeeper_tests veritas_protocol)

add_test(NAME veritas_gatekeeper_tests COMMAND veritas_gatekeeper_tests)
