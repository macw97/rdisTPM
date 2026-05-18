set(PROTO_FILE ${CMAKE_CURRENT_SOURCE_DIR}/../../proto/ssh_context.proto)

find_package(Protobuf CONFIG REQUIRED)
find_package(gRPC CONFIG REQUIRED)

add_library(ssh_service OBJECT ${PROTO_FILE})

target_link_libraries(ssh_service
    PUBLIC
        protobuf::libprotobuf
        gRPC::grpc++
)

target_include_directories(ssh_service PUBLIC "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>")

protobuf_generate(TARGET ssh_service IMPORT_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/../../proto PROTOC_OUT_DIR "${CMAKE_CURRENT_SOURCE_DIR}")

protobuf_generate(TARGET ssh_service
        LANGUAGE grpc
        PLUGIN "protoc-gen-grpc=\$<TARGET_FILE:gRPC::grpc_cpp_plugin>"
        GENERATE_EXTENSIONS .grpc.pb.h .grpc.pb.cc
        IMPORT_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/../../proto
        PROTOC_OUT_DIR "${CMAKE_CURRENT_SOURCE_DIR}"
)
