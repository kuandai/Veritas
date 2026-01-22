file(GLOB_RECURSE GATEKEEPER_SOURCES CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/src/*.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cc"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cxx"
)

if(GATEKEEPER_SOURCES)
  find_package(OpenSSL REQUIRED)
  find_package(gRPC QUIET CONFIG)
  if(NOT gRPC_FOUND)
    find_package(grpc QUIET CONFIG)
  endif()
  if(NOT gRPC_FOUND AND NOT grpc_FOUND)
    message(FATAL_ERROR "gRPC package not found; verify Conan gRPC installation.")
  endif()

  find_package(redis-plus-plus QUIET CONFIG)
  if(NOT redis-plus-plus_FOUND)
    message(FATAL_ERROR "redis-plus-plus package not found; verify Conan installation.")
  endif()

  set(GRPC_CPP_TARGET "")
  if(TARGET gRPC::grpc++)
    set(GRPC_CPP_TARGET gRPC::grpc++)
  elseif(TARGET grpc::grpc++)
    set(GRPC_CPP_TARGET grpc::grpc++)
  endif()

  if(NOT GRPC_CPP_TARGET)
    message(FATAL_ERROR "gRPC C++ target not found in the current toolchain.")
  endif()

  set(REDIS_CPP_TARGET "")
  if(TARGET redis-plus-plus::redis-plus-plus)
    set(REDIS_CPP_TARGET redis-plus-plus::redis-plus-plus)
  endif()

  if(NOT REDIS_CPP_TARGET)
    message(FATAL_ERROR "redis-plus-plus C++ target not found in the current toolchain.")
  endif()

  add_executable(veritas_gatekeeper ${GATEKEEPER_SOURCES})
  target_include_directories(veritas_gatekeeper
    PRIVATE
      ${CMAKE_CURRENT_SOURCE_DIR}/src
  )
  target_link_libraries(veritas_gatekeeper
    PRIVATE
      veritas_shared
      veritas_protocol
      ${GRPC_CPP_TARGET}
      ${REDIS_CPP_TARGET}
      OpenSSL::Crypto
  )
  target_compile_features(veritas_gatekeeper PRIVATE cxx_std_20)
endif()
