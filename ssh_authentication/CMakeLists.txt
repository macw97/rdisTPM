cmake_minimum_required(VERSION 3.20)
project(ssh_authentication)

find_package(tss2-esys QUIET)

if (NOT tss2-esys_FOUND)
    message(INFO " CMake tss2-esys library not found")
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(TSS2_ESYS REQUIRED tss2-esys)
    pkg_check_modules(TSS2_TCTILDR REQUIRED tss2-tctildr)
    pkg_check_modules(TSS2_MU REQUIRED tss2-mu)
endif()

set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(SOURCE_FILES
    src/tpm_auth.cpp
    src/ssh_context_client.cpp
)

set(HEADER_FILES
    include/ssh_context_client.hpp
)

add_subdirectory(ssh_service)
add_executable(ssh_authentication ${SOURCE_FILES})

target_include_directories(ssh_authentication PRIVATE include ${TSS2_ESYS_INCLUDE_DIRS} ${TSS2_TCTILDR_INCLUDE_DIRS} ${TSS2_MU_INCLUDE_DIRS})

target_link_libraries(ssh_authentication
    PUBLIC
        ${TSS2_ESYS_LIBRARIES}
        ${TSS2_TCTILDR_LIBRARIES}
        ${TSS2_MU_LIBRARIES}
    PRIVATE
        ssh_service
)