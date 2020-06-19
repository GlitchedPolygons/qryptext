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

/**
 *  @file sign.h
 *  @author Raphael Beck
 *  @brief Sign data using Falcon1024 (which within OQS uses SHAKE256 hashing internally).
 */

#ifndef QRYPTEXT_SIGN_H
#define QRYPTEXT_SIGN_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/**
 * Signs a given byte array (message) using Falcon-1024 (which within OQS uses SHAKE256 hashing internally).
 * @param data The data to sign.
 * @param data_length Length of the \p data array.
 * @param output_buffer Where to write the signature into.
 * @param output_buffer_size How big the signature output buffer is. Make sure to allocate at least \p OQS_SIG_falcon_1024_length_signature bytes!
 * @param output_length [OPTIONAL] How many bytes were written into the output buffer. If all went well, this is always gonna be \p OQS_SIG_falcon_1024_length_signature, so you can also omit this by passing <c>NULL</c>...
 * @param output_base64 Should the output signature bytes be base64-encoded for you? If you pass <c>true</c>, make sure to allocate at least qryptext_calc_base64_length(OQS_SIG_falcon_1024_length_signature) bytes! If you pass <c>false</c>, the raw signature bytes are written into the \p output_buffer!
 * @return <c>0</c> on success; error codes as defined in constants.h otherwise.
 */
int qryptext_sign(uint8_t* data, size_t data_length, uint8_t* output_buffer, size_t output_buffer_size, size_t* output_length, bool output_base64);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // QRYPTEXT_SIGN_H
