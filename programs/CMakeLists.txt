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

add_executable(qryptext_kyber1024_keygen ${CMAKE_CURRENT_LIST_DIR}/qryptext_kyber1024_keygen.c)
target_link_libraries(qryptext_kyber1024_keygen PRIVATE qryptext)

add_executable(qryptext_falcon1024_keygen ${CMAKE_CURRENT_LIST_DIR}/qryptext_falcon1024_keygen.c)
target_link_libraries(qryptext_falcon1024_keygen PRIVATE qryptext)