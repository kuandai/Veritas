find_package(GTest REQUIRED)
find_package(OpenSSL REQUIRED)

option(VERITAS_ENABLE_PROTO_TESTS "Enable protobuf/gRPC-dependent tests" OFF)
option(VERITAS_ENABLE_REDIS_INTEGRATION_TESTS
  "Enable Redis TLS integration tests requiring an external Redis endpoint" OFF)

set(VERITAS_TEST_SOURCES
  main.cpp
  gatekeeper/auth_metrics_test.cpp
  gatekeeper/fake_salt_test.cpp
  gatekeeper/config_test.cpp
  gatekeeper/log_utils_test.cpp
  gatekeeper/rate_limiter_test.cpp
  gatekeeper/session_cache_test.cpp
  gatekeeper/tls_utils_test.cpp
  gatekeeper/token_store_test.cpp
  gatekeeper/token_utils_test.cpp
  ${CMAKE_SOURCE_DIR}/services/gatekeeper/src/auth_metrics.cpp
  ${CMAKE_SOURCE_DIR}/services/gatekeeper/src/config.cpp
  ${CMAKE_SOURCE_DIR}/services/gatekeeper/src/fake_salt.cpp
  ${CMAKE_SOURCE_DIR}/services/gatekeeper/src/log_utils.cpp
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
  find_package(cyrus-sasl REQUIRED CONFIG)
  list(APPEND VERITAS_TEST_SOURCES
    gatekeeper/sasl_server_test.cpp
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
      veritas_protocol
      protobuf::libprotobuf
      gRPC::grpc++
  )
endif()

target_compile_features(veritas_gatekeeper_tests PRIVATE cxx_std_20)

target_compile_definitions(veritas_gatekeeper_tests
  PRIVATE
    VERITAS_DISABLE_SASL
    VERITAS_DISABLE_REDIS
    VERITAS_ENABLE_TEST_AUTH_BYPASS
)

add_dependencies(veritas_gatekeeper_tests veritas_protocol)

add_test(NAME veritas_gatekeeper_tests COMMAND veritas_gatekeeper_tests)

if(VERITAS_ENABLE_PROTO_TESTS)
  set(VERITAS_INTEGRATION_TEST_SOURCES
    main.cpp
    gatekeeper/sasl_integration_test.cpp
    ${CMAKE_SOURCE_DIR}/services/gatekeeper/src/fake_salt.cpp
    ${CMAKE_SOURCE_DIR}/services/gatekeeper/src/sasl_server.cpp
    ${CMAKE_SOURCE_DIR}/services/gatekeeper/src/secure_erase.cpp
    ${CMAKE_SOURCE_DIR}/services/gatekeeper/src/session_cache.cpp
    ${CMAKE_SOURCE_DIR}/services/gatekeeper/src/token_store.cpp
    ${CMAKE_SOURCE_DIR}/services/gatekeeper/src/token_utils.cpp
  )

  add_executable(veritas_gatekeeper_integration_tests
    ${VERITAS_INTEGRATION_TEST_SOURCES}
  )

  target_include_directories(veritas_gatekeeper_integration_tests
    PRIVATE
      ${CMAKE_SOURCE_DIR}/services/gatekeeper/src
      ${CMAKE_BINARY_DIR}/protocol
  )

  target_link_libraries(veritas_gatekeeper_integration_tests
    PRIVATE
      GTest::gtest
      OpenSSL::Crypto
      veritas_protocol
      protobuf::libprotobuf
      gRPC::grpc++
      cyrus-sasl::cyrus-sasl
  )

  target_compile_features(veritas_gatekeeper_integration_tests
    PRIVATE
      cxx_std_20
  )

  target_compile_definitions(veritas_gatekeeper_integration_tests
    PRIVATE
      VERITAS_DISABLE_REDIS
  )

  add_dependencies(veritas_gatekeeper_integration_tests veritas_protocol)
  add_test(NAME veritas_gatekeeper_integration_tests
           COMMAND veritas_gatekeeper_integration_tests)

  set(VERITAS_LIBVERITAS_TEST_SOURCES
    main.cpp
    libveritas/secure_string_test.cpp
    libveritas/gatekeeper_client_test.cpp
    libveritas/sasl_client_test.cpp
    libveritas/auth_flow_integration_test.cpp
    libveritas/token_store_test.cpp
    ${CMAKE_SOURCE_DIR}/services/gatekeeper/src/auth_metrics.cpp
    ${CMAKE_SOURCE_DIR}/services/gatekeeper/src/fake_salt.cpp
    ${CMAKE_SOURCE_DIR}/services/gatekeeper/src/gatekeeper_service.cpp
    ${CMAKE_SOURCE_DIR}/services/gatekeeper/src/log_utils.cpp
    ${CMAKE_SOURCE_DIR}/services/gatekeeper/src/rate_limiter.cpp
    ${CMAKE_SOURCE_DIR}/services/gatekeeper/src/sasl_server.cpp
    ${CMAKE_SOURCE_DIR}/services/gatekeeper/src/secure_erase.cpp
    ${CMAKE_SOURCE_DIR}/services/gatekeeper/src/session_cache.cpp
    ${CMAKE_SOURCE_DIR}/services/gatekeeper/src/token_store.cpp
    ${CMAKE_SOURCE_DIR}/services/gatekeeper/src/token_utils.cpp
  )

  add_executable(veritas_libveritas_tests ${VERITAS_LIBVERITAS_TEST_SOURCES})

  target_include_directories(veritas_libveritas_tests
    PRIVATE
      ${CMAKE_SOURCE_DIR}/libveritas/src
      ${CMAKE_SOURCE_DIR}/services/gatekeeper/src
      ${CMAKE_BINARY_DIR}/protocol
  )

  target_link_libraries(veritas_libveritas_tests
    PRIVATE
      veritas
      GTest::gtest
      OpenSSL::Crypto
      protobuf::libprotobuf
      gRPC::grpc++
      cyrus-sasl::cyrus-sasl
  )

  target_compile_features(veritas_libveritas_tests
    PRIVATE
      cxx_std_20
  )

  target_compile_definitions(veritas_libveritas_tests
    PRIVATE
      VERITAS_DISABLE_REDIS
  )

  add_dependencies(veritas_libveritas_tests veritas_protocol)
  add_test(NAME veritas_libveritas_tests COMMAND veritas_libveritas_tests)

  if(VERITAS_ENABLE_REDIS_INTEGRATION_TESTS)
    find_package(redis++ REQUIRED CONFIG)

    set(REDIS_CPP_TARGET "")
    if(TARGET redis++::redis++_static)
      set(REDIS_CPP_TARGET redis++::redis++_static)
    elseif(TARGET redis++::redis++)
      set(REDIS_CPP_TARGET redis++::redis++)
    endif()

    if(NOT REDIS_CPP_TARGET)
      message(FATAL_ERROR "redis++ C++ target not found in current toolchain")
    endif()

    add_executable(veritas_gatekeeper_redis_integration_tests
      main.cpp
      gatekeeper/redis_tls_integration_test.cpp
      ${CMAKE_SOURCE_DIR}/services/gatekeeper/src/token_store.cpp
    )

    target_include_directories(veritas_gatekeeper_redis_integration_tests
      PRIVATE
        ${CMAKE_SOURCE_DIR}/services/gatekeeper/src
    )

    target_link_libraries(veritas_gatekeeper_redis_integration_tests
      PRIVATE
        GTest::gtest
        OpenSSL::Crypto
        ${REDIS_CPP_TARGET}
    )

    target_compile_features(veritas_gatekeeper_redis_integration_tests
      PRIVATE
        cxx_std_20
    )

    add_test(NAME veritas_gatekeeper_redis_integration_tests
             COMMAND veritas_gatekeeper_redis_integration_tests)
  endif()
endif()
