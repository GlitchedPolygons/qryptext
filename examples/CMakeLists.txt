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
project(qryptext_examples C)

add_executable(qryptext_example_01 ${CMAKE_CURRENT_LIST_DIR}/example01.c)
target_link_libraries(qryptext_example_01 PRIVATE qryptext)

add_executable(qryptext_example_02 ${CMAKE_CURRENT_LIST_DIR}/example02.c)
target_link_libraries(qryptext_example_02 PRIVATE qryptext)

add_executable(qryptext_example_03 ${CMAKE_CURRENT_LIST_DIR}/example03.c)
target_link_libraries(qryptext_example_03 PRIVATE qryptext)

add_executable(qryptext_example_04 ${CMAKE_CURRENT_LIST_DIR}/example04.c)
target_link_libraries(qryptext_example_04 PRIVATE qryptext)

add_executable(qryptext_example_05 ${CMAKE_CURRENT_LIST_DIR}/example05.c)
target_link_libraries(qryptext_example_05 PRIVATE qryptext)

add_executable(qryptext_example_06 ${CMAKE_CURRENT_LIST_DIR}/example06.c)
target_link_libraries(qryptext_example_06 PRIVATE qryptext)