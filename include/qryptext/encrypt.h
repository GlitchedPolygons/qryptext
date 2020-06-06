/*
   Copyright 2020 Raphael Beck

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#ifndef QRYPTEXT_CONSTANTS_H
#define QRYPTEXT_CONSTANTS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

int qryptext_encrypt(uint8_t* data, size_t data_length, uint8_t* output_buffer, size_t output_buffer_size, size_t* output_length, uint8_t* public_key, size_t public_key_length);

int qryptext_encrypt_malloc(uint8_t* data, size_t data_length, uint8_t** output, size_t* output_length, uint8_t* public_key, size_t public_key_length);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // QRYPTEXT_CONSTANTS_H
