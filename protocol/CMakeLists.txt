set(VERITAS_PROTO_FILES
  ${CMAKE_CURRENT_SOURCE_DIR}/identity.proto
)

find_package(protobuf REQUIRED CONFIG)

add_library(veritas_protocol)
target_include_directories(veritas_protocol
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
)

target_link_libraries(veritas_protocol PUBLIC protobuf::libprotobuf)

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

set(VERITAS_PROTO_SRCS)
set(VERITAS_PROTO_HDRS)
foreach(PROTO_FILE IN LISTS VERITAS_PROTO_FILES)
  get_filename_component(PROTO_ABS ${PROTO_FILE} ABSOLUTE)
  get_filename_component(PROTO_NAME ${PROTO_FILE} NAME_WE)
  set(GEN_CC ${CMAKE_CURRENT_BINARY_DIR}/${PROTO_NAME}.pb.cc)
  set(GEN_H ${CMAKE_CURRENT_BINARY_DIR}/${PROTO_NAME}.pb.h)

  add_custom_command(
    OUTPUT ${GEN_CC} ${GEN_H}
    COMMAND ${PROTOC_BIN}
    ARGS --cpp_out ${CMAKE_CURRENT_BINARY_DIR} -I ${CMAKE_CURRENT_SOURCE_DIR} ${PROTO_ABS}
    DEPENDS ${PROTO_ABS} ${PROTOC_BIN}
    COMMENT "Generating ${PROTO_NAME}.pb.cc/.pb.h"
    VERBATIM
  )

  list(APPEND VERITAS_PROTO_SRCS ${GEN_CC})
  list(APPEND VERITAS_PROTO_HDRS ${GEN_H})
endforeach()

target_sources(veritas_protocol PRIVATE ${VERITAS_PROTO_SRCS} ${VERITAS_PROTO_HDRS})
