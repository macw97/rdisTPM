set(PROTO_FILE ${CMAKE_CURRENT_SOURCE_DIR}/../../proto/ssh_context.proto)

find_package(Protobuf REQUIRED)
find_package(gRPC REQUIRED)

get_target_property(PB protobuf::libprotobuf LOCATION)
message(STATUS "PROTOBUF USED: ${PB}")

get_target_property(GRPC_CPP_PLUGIN gRPC::grpc_cpp_plugin LOCATION)
get_filename_component(PROTO_DIR "${PROTO_FILE}" DIRECTORY)

set(PROTO_SRCS "${CMAKE_CURRENT_SOURCE_DIR}/ssh_context.pb.cc")
set(PROTO_HDRS "${CMAKE_CURRENT_SOURCE_DIR}/ssh_context.pb.h")
set(GRPC_SRCS "${CMAKE_CURRENT_SOURCE_DIR}/ssh_context.grpc.pb.cc")
set(GRPC_HDRS "${CMAKE_CURRENT_SOURCE_DIR}/ssh_context.grpc.pb.h")

message(STATUS "PROTOC USED: ${Protobuf_PROTOC_EXECUTABLE}")

add_custom_command(
    OUTPUT ${PROTO_SRCS} ${PROTO_HDRS} ${GRPC_SRCS} ${GRPC_HDRS}
    COMMAND ${Protobuf_PROTOC_EXECUTABLE}
    ARGS --cpp_out=${CMAKE_CURRENT_SOURCE_DIR} --grpc_out ${CMAKE_CURRENT_SOURCE_DIR} -I ${PROTO_DIR}
    --plugin=protoc-gen-grpc=${GRPC_CPP_PLUGIN} ${PROTO_FILE}
    DEPENDS ${PROTO_FILE}
)

add_library(ssh_service SHARED ${PROTO_SRCS} ${PROTO_HDRS} ${GRPC_SRCS} ${GRPC_HDRS})
target_include_directories(ssh_service PUBLIC "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>")
target_link_libraries(ssh_service
    PUBLIC
        protobuf::libprotobuf
        gRPC::grpc++
)
