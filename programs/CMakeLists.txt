#  Copyright 2020 Raphael Beck
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

cmake_minimum_required(VERSION 3.1)
set(CMAKE_C_STANDARD 11)
project(qryptext_programs C)

add_executable(qryptext_kyber1024_keygen ${CMAKE_CURRENT_LIST_DIR}/qryptext_kyber1024_keygen.c ${qryptext_HEADERS} ${qryptext_SOURCES})
target_include_directories(qryptext_kyber1024_keygen PRIVATE ${qryptext_TARGET_INCLUDE_DIRS})
target_link_libraries(qryptext_kyber1024_keygen PRIVATE ${qryptext_DEPS_TARGETS})

add_executable(qryptext_falcon1024_keygen ${CMAKE_CURRENT_LIST_DIR}/qryptext_falcon1024_keygen.c ${qryptext_HEADERS} ${qryptext_SOURCES})
target_include_directories(qryptext_falcon1024_keygen PRIVATE ${qryptext_TARGET_INCLUDE_DIRS})
target_link_libraries(qryptext_falcon1024_keygen PRIVATE ${qryptext_DEPS_TARGETS})

add_executable(qryptext_encrypt ${CMAKE_CURRENT_LIST_DIR}/qryptext_encrypt.c ${qryptext_HEADERS} ${qryptext_SOURCES})
target_include_directories(qryptext_encrypt PRIVATE ${qryptext_TARGET_INCLUDE_DIRS})
target_link_libraries(qryptext_encrypt PRIVATE ${qryptext_DEPS_TARGETS})

add_executable(qryptext_decrypt ${CMAKE_CURRENT_LIST_DIR}/qryptext_decrypt.c ${qryptext_HEADERS} ${qryptext_SOURCES})
target_include_directories(qryptext_decrypt PRIVATE ${qryptext_TARGET_INCLUDE_DIRS})
target_link_libraries(qryptext_decrypt PRIVATE ${qryptext_DEPS_TARGETS})

add_executable(qryptext_sign ${CMAKE_CURRENT_LIST_DIR}/qryptext_sign.c ${qryptext_HEADERS} ${qryptext_SOURCES})
target_include_directories(qryptext_sign PRIVATE ${qryptext_TARGET_INCLUDE_DIRS})
target_link_libraries(qryptext_sign PRIVATE ${qryptext_DEPS_TARGETS})

add_executable(qryptext_verify ${CMAKE_CURRENT_LIST_DIR}/qryptext_verify.c ${qryptext_HEADERS} ${qryptext_SOURCES})
target_include_directories(qryptext_verify PRIVATE ${qryptext_TARGET_INCLUDE_DIRS})
target_link_libraries(qryptext_verify PRIVATE ${qryptext_DEPS_TARGETS})

list(APPEND qryptext_PROGRAM_TARGETS_LIST qryptext_kyber1024_keygen qryptext_falcon1024_keygen qryptext_encrypt qryptext_decrypt qryptext_sign qryptext_verify)
set(qryptext_PROGRAM_TARGETS ${qryptext_PROGRAM_TARGETS_LIST} PARENT_SCOPE)
