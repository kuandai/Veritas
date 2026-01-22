find_package(GTest REQUIRED)
find_package(OpenSSL REQUIRED)

add_executable(veritas_gatekeeper_tests
  gatekeeper/fake_salt_test.cpp
  gatekeeper/token_utils_test.cpp
  ${CMAKE_SOURCE_DIR}/services/gatekeeper/src/fake_salt.cpp
  ${CMAKE_SOURCE_DIR}/services/gatekeeper/src/token_utils.cpp
)

target_include_directories(veritas_gatekeeper_tests
  PRIVATE
    ${CMAKE_SOURCE_DIR}/services/gatekeeper/src
)

target_link_libraries(veritas_gatekeeper_tests
  PRIVATE
    GTest::gtest_main
    OpenSSL::Crypto
)

target_compile_features(veritas_gatekeeper_tests PRIVATE cxx_std_20)

add_test(NAME veritas_gatekeeper_tests COMMAND veritas_gatekeeper_tests)
