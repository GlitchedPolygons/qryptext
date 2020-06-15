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

cmake_minimum_required(VERSION 3.15)
project(qryptext C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake" ${CMAKE_MODULE_PATH})

# Qryptext Options
option(QRYPTEXT_ENABLE_TESTS "Build qryptext tests." OFF)

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

set(${PROJECT_NAME}_HEADERS
        ${CMAKE_CURRENT_LIST_DIR}/include/qryptext/constants.h
        ${CMAKE_CURRENT_LIST_DIR}/include/qryptext/types.h
        ${CMAKE_CURRENT_LIST_DIR}/include/qryptext/guid.h
        ${CMAKE_CURRENT_LIST_DIR}/include/qryptext/util.h
        ${CMAKE_CURRENT_LIST_DIR}/include/qryptext/decrypt.h
        ${CMAKE_CURRENT_LIST_DIR}/include/qryptext/encrypt.h
        ${CMAKE_CURRENT_LIST_DIR}/include/qryptext/sign.h
        ${CMAKE_CURRENT_LIST_DIR}/include/qryptext/verify.h
        )

set(${PROJECT_NAME}_SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/src/util.c
        ${CMAKE_CURRENT_LIST_DIR}/src/guid.c
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

target_link_libraries(${PROJECT_NAME}
        PUBLIC mbedtls
        PUBLIC mbedx509
        PUBLIC mbedcrypto
        PUBLIC oqs
        )

if (UNIX AND NOT APPLE)
    target_link_libraries(${PROJECT_NAME} PRIVATE -luuid -lm)
endif ()

target_include_directories(oqs
        PUBLIC ${CMAKE_CURRENT_BINARY_DIR}/lib/oqs/include
        PUBLIC ${CMAKE_CURRENT_LIST_DIR}/lib/oqs/src/kem/kyber
        PUBLIC ${CMAKE_CURRENT_LIST_DIR}/lib/oqs/src/sig/falcon
        )

target_include_directories(${PROJECT_NAME}
        PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include
        PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/lib/oqs/include
        PRIVATE ${CMAKE_CURRENT_LIST_DIR}/lib/mbedtls/include
        PRIVATE ${CMAKE_CURRENT_LIST_DIR}/lib/oqs/src/kem/kyber
        PRIVATE ${CMAKE_CURRENT_LIST_DIR}/lib/oqs/src/sig/falcon
        )

get_target_property(${PROJECT_NAME}_DEPS_TARGETS ${PROJECT_NAME} LINK_LIBRARIES)

if (QRYPTEXT_ENABLE_TESTS)

    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/lib/cmocka cmocka)

    add_executable(run_tests
            ${CMAKE_CURRENT_LIST_DIR}/tests/tests.c
            ${${PROJECT_NAME}_HEADERS}
            ${${PROJECT_NAME}_SOURCES}
            )

    target_include_directories(run_tests
            PUBLIC ${cmocka_INCLUDE_DIR}
            PUBLIC ${${PROJECT_NAME}_INCLUDE_DIR}
            )

    target_link_libraries(run_tests
            PUBLIC ${${PROJECT_NAME}_DEPS_TARGETS}
            PUBLIC cmocka
            )

    if (ENABLE_COVERAGE)
        find_package(codecov)
        add_coverage(${PROJECT_NAME})
        add_coverage(run_tests)
        coverage_evaluate()
    endif ()
endif ()
