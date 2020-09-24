#  Copyright 2020 Raphael Beck
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

cmake_minimum_required(VERSION 3.7)
project(qryptext C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake" ${CMAKE_MODULE_PATH})

set(${PROJECT_NAME}_MAJOR 0)
set(${PROJECT_NAME}_MINOR 4)
set(${PROJECT_NAME}_PATCH 1)
set(${PROJECT_NAME}_VERSION_STRING "${${PROJECT_NAME}_MAJOR}.${${PROJECT_NAME}_MINOR}.${${PROJECT_NAME}_PATCH}")

# Qryptext Options
option(${PROJECT_NAME}_ENABLE_TESTS "Build qryptext tests." OFF)
option(${PROJECT_NAME}_ENABLE_PROGRAMS "Build CLI programs." OFF)
option(${PROJECT_NAME}_ENABLE_EXAMPLES "Build examples." OFF)
option(${PROJECT_NAME}_DLL "Use as a DLL." OFF)
option(${PROJECT_NAME}_BUILD_DLL "Build as a DLL." OFF)
option(${PROJECT_NAME}_PACKAGE "Build the library and package it into a .tar.gz after successfully building." OFF)

if (${${PROJECT_NAME}_BUILD_DLL})
    add_compile_definitions("QRYPTEXT_BUILD_DLL=1")
    set(${PROJECT_NAME}_DLL ON)
endif ()

if (${${PROJECT_NAME}_DLL})
    add_compile_definitions("QRYPTEXT_DLL=1")
endif ()

# OQS Options
option(OQS_USE_OPENSSL "Build OQS with OpenSSL support." OFF)
option(OQS_BUILD_ONLY_LIB "Build OQS without tests, docs, etc..." ON)
option(OQS_ENABLE_KEM_KYBER "Build OQS with KYBER support." ON)
option(OQS_ENABLE_SIG_FALCON "Build OQS with FALCON signing support." ON)

if (NOT OQS_ENABLE_KEM_KYBER)
    message(FATAL_ERROR "Please build OQS with KEM-Kyber-1024 support!")
endif ()

if (NOT OQS_ENABLE_SIG_FALCON)
    message(FATAL_ERROR "Please build OQS with Falcon1024 signing support!")
endif ()

# MbedTLS Options
option(ENABLE_TESTING "Build MbedTLS tests." OFF)
option(ENABLE_PROGRAMS "Build MbedTLS example programs." OFF)

set(${PROJECT_NAME}_TARGET_INCLUDE_DIRS
        PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include
        PUBLIC ${CMAKE_CURRENT_BINARY_DIR}/lib/oqs/include
        PUBLIC ${CMAKE_CURRENT_LIST_DIR}/lib/mbedtls/include
        PUBLIC ${CMAKE_CURRENT_LIST_DIR}/lib/oqs/src/kem/kyber
        PUBLIC ${CMAKE_CURRENT_LIST_DIR}/lib/oqs/src/sig/falcon
        )

set(${PROJECT_NAME}_HEADERS
        ${CMAKE_CURRENT_LIST_DIR}/include/qryptext/constants.h
        ${CMAKE_CURRENT_LIST_DIR}/include/qryptext/types.h
        ${CMAKE_CURRENT_LIST_DIR}/include/qryptext/guid.h
        ${CMAKE_CURRENT_LIST_DIR}/include/qryptext/util.h
        ${CMAKE_CURRENT_LIST_DIR}/include/qryptext/keygen.h
        ${CMAKE_CURRENT_LIST_DIR}/include/qryptext/decrypt.h
        ${CMAKE_CURRENT_LIST_DIR}/include/qryptext/encrypt.h
        ${CMAKE_CURRENT_LIST_DIR}/include/qryptext/sign.h
        ${CMAKE_CURRENT_LIST_DIR}/include/qryptext/verify.h
        )

set(${PROJECT_NAME}_SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/src/util.c
        ${CMAKE_CURRENT_LIST_DIR}/src/guid.c
        ${CMAKE_CURRENT_LIST_DIR}/src/keygen.c
        ${CMAKE_CURRENT_LIST_DIR}/src/decrypt.c
        ${CMAKE_CURRENT_LIST_DIR}/src/encrypt.c
        ${CMAKE_CURRENT_LIST_DIR}/src/sign.c
        ${CMAKE_CURRENT_LIST_DIR}/src/verify.c
        )

if (NOT TARGET mbedtls)
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/lib/mbedtls mbedtls)
endif ()

if (NOT TARGET oqs)
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/lib/oqs)
endif ()

add_library(${PROJECT_NAME}
        ${${PROJECT_NAME}_HEADERS}
        ${${PROJECT_NAME}_SOURCES}
        )

if (${${PROJECT_NAME}_BUILD_DLL} OR BUILD_SHARED_LIBS)
    set_property(TARGET oqs PROPERTY POSITION_INDEPENDENT_CODE ON)
    set_property(TARGET mbedtls PROPERTY POSITION_INDEPENDENT_CODE ON)
    set_property(TARGET mbedx509 PROPERTY POSITION_INDEPENDENT_CODE ON)
    set_property(TARGET mbedcrypto PROPERTY POSITION_INDEPENDENT_CODE ON)
    set_target_properties(${PROJECT_NAME} PROPERTIES
            VERSION ${${PROJECT_NAME}_VERSION_STRING}
            SOVERSION ${${PROJECT_NAME}_MAJOR}
            )
endif ()

if (${${PROJECT_NAME}_PACKAGE})
    set_target_properties(${PROJECT_NAME} PROPERTIES
            ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/bin"
            LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/bin"
            RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/bin"

            ARCHIVE_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/bin/debug"
            LIBRARY_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/bin/debug"
            RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/bin/debug"

            ARCHIVE_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/bin/release"
            LIBRARY_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/bin/release"
            RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/bin/release"
            )

    add_custom_command(TARGET ${PROJECT_NAME}
            POST_BUILD COMMAND ${CMAKE_COMMAND}
            -E copy ${CMAKE_CURRENT_LIST_DIR}/NOTICE "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/NOTICE"
            )

    add_custom_command(TARGET ${PROJECT_NAME}
            POST_BUILD COMMAND ${CMAKE_COMMAND}
            -E copy_directory ${CMAKE_CURRENT_LIST_DIR}/include "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}/include"
            )

    string(TOLOWER "${PROJECT_NAME}-${${PROJECT_NAME}_VERSION_STRING}-${CMAKE_SYSTEM_NAME}-${CMAKE_HOST_SYSTEM_PROCESSOR}.tar.gz" ${PROJECT_NAME}_OUTPUT_ARCHIVE_FILENAME)

    add_custom_command(TARGET ${PROJECT_NAME}
            POST_BUILD COMMAND ${CMAKE_COMMAND}
            -E tar "czvf" ${${PROJECT_NAME}_OUTPUT_ARCHIVE_FILENAME} ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}
            )
endif ()

target_link_libraries(${PROJECT_NAME}
        PUBLIC mbedtls
        PUBLIC mbedx509
        PUBLIC mbedcrypto
        PUBLIC oqs
        )

if (UNIX AND NOT APPLE)
    target_link_libraries(${PROJECT_NAME} PRIVATE -luuid -lm)
endif ()

if (WIN32)
    target_link_libraries(${PROJECT_NAME} PUBLIC bcrypt)
endif ()

target_include_directories(oqs
        PUBLIC ${CMAKE_CURRENT_BINARY_DIR}/lib/oqs/include
        PUBLIC ${CMAKE_CURRENT_LIST_DIR}/lib/oqs/src/kem/kyber
        PUBLIC ${CMAKE_CURRENT_LIST_DIR}/lib/oqs/src/sig/falcon
        )

target_include_directories(${PROJECT_NAME} ${${PROJECT_NAME}_TARGET_INCLUDE_DIRS})

get_target_property(${PROJECT_NAME}_DEPS_TARGETS ${PROJECT_NAME} LINK_LIBRARIES)

if (${${PROJECT_NAME}_ENABLE_EXAMPLES})
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/examples examples)
endif ()

if (${${PROJECT_NAME}_ENABLE_PROGRAMS_ENABLE_PROGRAMS})
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/programs programs)
endif ()

if (${${PROJECT_NAME}_ENABLE_TESTS})

    add_executable(run_tests
            ${CMAKE_CURRENT_LIST_DIR}/tests/tests.c
            )

    target_link_libraries(run_tests
            PUBLIC ${PROJECT_NAME}
            PUBLIC ${${PROJECT_NAME}_DEPS_TARGETS}
            )

    target_include_directories(run_tests
            PUBLIC ${cmocka_INCLUDE_DIR}
            ${${PROJECT_NAME}_TARGET_INCLUDE_DIRS}
            )
    target_include_directories(run_tests
            ${${PROJECT_NAME}_TARGET_INCLUDE_DIRS}
            PUBLIC ${CMAKE_CURRENT_LIST_DIR}/lib/acutest/include
            )

    if (ENABLE_COVERAGE)
        find_package(codecov)
        add_coverage(${PROJECT_NAME})
        add_coverage(run_tests)
        coverage_evaluate()
    endif ()
endif ()
