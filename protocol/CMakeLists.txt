set(VERITAS_PROTO_FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/identity.proto
  ${CMAKE_CURRENT_SOURCE_DIR}/gatekeeper.proto
  ${CMAKE_CURRENT_SOURCE_DIR}/notary.proto
)

find_package(protobuf REQUIRED CONFIG)
find_package(gRPC QUIET CONFIG)
if(NOT gRPC_FOUND)
  find_package(grpc QUIET CONFIG)
endif()
if(NOT gRPC_FOUND AND NOT grpc_FOUND)
  message(FATAL_ERROR "gRPC package not found; verify Conan gRPC installation.")
endif()

add_library(veritas_protocol)
target_include_directories(veritas_protocol
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
)

set(GRPC_CPP_TARGET "")
if(TARGET gRPC::grpc++)
  set(GRPC_CPP_TARGET gRPC::grpc++)
elseif(TARGET grpc::grpc++)
  set(GRPC_CPP_TARGET grpc::grpc++)
endif()

if(NOT GRPC_CPP_TARGET)
  message(FATAL_ERROR "gRPC C++ target not found in the current toolchain.")
endif()

target_link_libraries(veritas_protocol
  PUBLIC
    protobuf::libprotobuf
    ${GRPC_CPP_TARGET}
)

set(PROTOC_BIN "")
if(DEFINED protobuf_PACKAGE_FOLDER_DEBUG)
  set(PROTOC_BIN "${protobuf_PACKAGE_FOLDER_DEBUG}/bin/protoc${CMAKE_EXECUTABLE_SUFFIX}")
elseif(DEFINED protobuf_PACKAGE_FOLDER_RELEASE)
  set(PROTOC_BIN "${protobuf_PACKAGE_FOLDER_RELEASE}/bin/protoc${CMAKE_EXECUTABLE_SUFFIX}")
endif()

if(NOT PROTOC_BIN OR NOT EXISTS "${PROTOC_BIN}")
  find_program(PROTOC_BIN protoc)
endif()

if(NOT PROTOC_BIN)
  message(FATAL_ERROR "protoc executable not found; verify Conan protobuf installation.")
endif()

set(GRPC_CPP_PLUGIN "")
if(DEFINED grpc_PACKAGE_FOLDER_DEBUG)
  set(GRPC_CPP_PLUGIN "${grpc_PACKAGE_FOLDER_DEBUG}/bin/grpc_cpp_plugin${CMAKE_EXECUTABLE_SUFFIX}")
elseif(DEFINED grpc_PACKAGE_FOLDER_RELEASE)
  set(GRPC_CPP_PLUGIN "${grpc_PACKAGE_FOLDER_RELEASE}/bin/grpc_cpp_plugin${CMAKE_EXECUTABLE_SUFFIX}")
elseif(DEFINED gRPC_PACKAGE_FOLDER_DEBUG)
  set(GRPC_CPP_PLUGIN "${gRPC_PACKAGE_FOLDER_DEBUG}/bin/grpc_cpp_plugin${CMAKE_EXECUTABLE_SUFFIX}")
elseif(DEFINED gRPC_PACKAGE_FOLDER_RELEASE)
  set(GRPC_CPP_PLUGIN "${gRPC_PACKAGE_FOLDER_RELEASE}/bin/grpc_cpp_plugin${CMAKE_EXECUTABLE_SUFFIX}")
endif()

if(NOT GRPC_CPP_PLUGIN OR NOT EXISTS "${GRPC_CPP_PLUGIN}")
  find_program(GRPC_CPP_PLUGIN grpc_cpp_plugin)
endif()

if(NOT GRPC_CPP_PLUGIN)
  message(FATAL_ERROR "grpc_cpp_plugin not found; verify Conan gRPC installation.")
endif()

set(PROTO_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR})
get_target_property(PROTOBUF_INCLUDE_DIRS protobuf::libprotobuf INTERFACE_INCLUDE_DIRECTORIES)
if(PROTOBUF_INCLUDE_DIRS)
  list(APPEND PROTO_INCLUDE_DIRS ${PROTOBUF_INCLUDE_DIRS})
endif()

set(PROTO_INCLUDE_ARGS "")
foreach(PROTO_DIR IN LISTS PROTO_INCLUDE_DIRS)
  list(APPEND PROTO_INCLUDE_ARGS -I ${PROTO_DIR})
endforeach()

set(VERITAS_PROTO_SRCS)
set(VERITAS_PROTO_HDRS)
foreach(PROTO_FILE IN LISTS VERITAS_PROTO_FILES)
  get_filename_component(PROTO_ABS ${PROTO_FILE} ABSOLUTE)
  get_filename_component(PROTO_NAME ${PROTO_FILE} NAME_WE)
  set(GEN_CC ${CMAKE_CURRENT_BINARY_DIR}/${PROTO_NAME}.pb.cc)
  set(GEN_H ${CMAKE_CURRENT_BINARY_DIR}/${PROTO_NAME}.pb.h)
  set(GEN_GRPC_CC ${CMAKE_CURRENT_BINARY_DIR}/${PROTO_NAME}.grpc.pb.cc)
  set(GEN_GRPC_H ${CMAKE_CURRENT_BINARY_DIR}/${PROTO_NAME}.grpc.pb.h)

  add_custom_command(
    OUTPUT ${GEN_CC} ${GEN_H} ${GEN_GRPC_CC} ${GEN_GRPC_H}
    COMMAND ${PROTOC_BIN}
    ARGS
      --cpp_out ${CMAKE_CURRENT_BINARY_DIR}
      --grpc_out ${CMAKE_CURRENT_BINARY_DIR}
      --plugin=protoc-gen-grpc=${GRPC_CPP_PLUGIN}
      ${PROTO_INCLUDE_ARGS}
      ${PROTO_ABS}
    DEPENDS ${PROTO_ABS} ${PROTOC_BIN} ${GRPC_CPP_PLUGIN}
    COMMENT "Generating ${PROTO_NAME}.pb.cc/.grpc.pb.cc"
    VERBATIM
  )

  list(APPEND VERITAS_PROTO_SRCS ${GEN_CC} ${GEN_GRPC_CC})
  list(APPEND VERITAS_PROTO_HDRS ${GEN_H} ${GEN_GRPC_H})
endforeach()

target_sources(veritas_protocol PRIVATE ${VERITAS_PROTO_SRCS} ${VERITAS_PROTO_HDRS})
