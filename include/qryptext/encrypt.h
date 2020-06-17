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
 *  @file encrypt.h
 *  @author Raphael Beck
 *  @brief Encrypt data using Kyber1024 KEM + AES256-GCM.
 */

#ifndef QRYPTEXT_ENCRYPT_H
#define QRYPTEXT_ENCRYPT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include "qryptext/types.h"

/**
 * Encrypts a given byte array of data using AES256-CBC, Kyber1024 and (optionally) RSA.
 * @param data The data to encrypt.
 * @param data_length Length of the data array.
 * @param output_buffer Where to write the encrypted ciphertext into. Make sure that this is allocated sufficiently big! If you're unsure about how much to allocate, you can use util.h's qryptext_calc_ciphertext_length() function.
 * @param output_buffer_size How big the output buffer is (use qryptext_calc_ciphertext_length() for allocation size guideline).
 * @param output_length Where to write the number of bytes written to the output buffer into (will be left untouched in case of a failure).
 * @param public_kyber1024_key The Kyber1024 public key with which to encrypt the AES key.
 * @return The status code: <c>0</c> if encryption succeeded, all other status codes can be found inside the various qryptext header files.
 */
int qryptext_encrypt(const uint8_t* data, size_t data_length, uint8_t* output_buffer, size_t output_buffer_size, size_t* output_length, qryptext_kyber1024_public_key public_kyber1024_key);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // QRYPTEXT_ENCRYPT_H
