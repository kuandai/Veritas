find_package(GTest REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(cyrus-sasl REQUIRED CONFIG)
find_package(redis-plus-plus REQUIRED CONFIG)

add_executable(veritas_gatekeeper_tests
  gatekeeper/fake_salt_test.cpp
  gatekeeper/rate_limiter_test.cpp
  gatekeeper/sasl_server_test.cpp
  gatekeeper/token_utils_test.cpp
  ${CMAKE_SOURCE_DIR}/services/gatekeeper/src/fake_salt.cpp
  ${CMAKE_SOURCE_DIR}/services/gatekeeper/src/rate_limiter.cpp
  ${CMAKE_SOURCE_DIR}/services/gatekeeper/src/sasl_server.cpp
  ${CMAKE_SOURCE_DIR}/services/gatekeeper/src/secure_erase.cpp
  ${CMAKE_SOURCE_DIR}/services/gatekeeper/src/session_cache.cpp
  ${CMAKE_SOURCE_DIR}/services/gatekeeper/src/token_store.cpp
  ${CMAKE_SOURCE_DIR}/services/gatekeeper/src/token_utils.cpp
)

target_include_directories(veritas_gatekeeper_tests
  PRIVATE
    ${CMAKE_SOURCE_DIR}/services/gatekeeper/src
    ${CMAKE_BINARY_DIR}/protocol
)

target_link_libraries(veritas_gatekeeper_tests
  PRIVATE
    GTest::gtest_main
    OpenSSL::Crypto
    cyrus-sasl::cyrus-sasl
    redis-plus-plus::redis-plus-plus
    veritas_protocol
)

target_compile_features(veritas_gatekeeper_tests PRIVATE cxx_std_20)

add_dependencies(veritas_gatekeeper_tests veritas_protocol)

add_test(NAME veritas_gatekeeper_tests COMMAND veritas_gatekeeper_tests)
