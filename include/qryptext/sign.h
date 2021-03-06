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
#include "types.h"

/**
 * Signs a given byte array (message) using Falcon-1024 (which within OQS uses SHAKE256 hashing internally).
 * @param data The data to sign.
 * @param data_length Length of the \p data array.
 * @param output_buffer Where to write the signature into.
 * @param output_buffer_size How big the signature output buffer is. Make sure to allocate at least \p OQS_SIG_falcon_1024_length_signature bytes!
 * @param output_length How many bytes were written into the output buffer.
 * @param output_base64 Should the output signature bytes be base64-encoded for you? Pass a non-zero value for <c>true</c>. If you pass <c>true</c>, make sure to allocate at least qryptext_calc_base64_length(OQS_SIG_falcon_1024_length_signature) bytes! If you pass <c>false</c>, the raw signature bytes are written into the \p output_buffer!
 * @param secret_falcon1024_key The Falcon-1024 secret key to use for signing.
 * @return <c>0</c> on success; error codes as defined in constants.h otherwise.
 */
QRYPTEXT_API int qryptext_sign(const uint8_t* data, size_t data_length, uint8_t* output_buffer, size_t output_buffer_size, size_t* output_length, uint8_t output_base64, qryptext_falcon1024_secret_key secret_falcon1024_key);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // QRYPTEXT_SIGN_H
