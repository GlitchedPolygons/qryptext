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
 *  @file decrypt.h
 *  @author Raphael Beck
 *  @brief Decrypt data that was encrypted using qryptext_encrypt() (Kyber1024 KEM + AES256-GCM).
 */

#ifndef QRYPTEXT_DECRYPT_H
#define QRYPTEXT_DECRYPT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include "qryptext/types.h"

/**
 * Decrypts a given byte array of data that was encrypted using qryptext_encrypt().
 * @param encrypted_data The data to decrypt.
 * @param encrypted_data_length Length of the data array.
 * @param encrypted_data_base64 Is the encrypted data a base64-encoded string?
 * @param output_buffer Where to write the decrypted data into (make sure that this is allocated sufficiently big!).
 * @param output_buffer_size How big the output buffer is (usually, when unsure, allocate the same size as the encrypted data length; that's guaranteed to be sufficiently big).
 * @param output_length Where to write the number of bytes written to the output buffer into (will be left untouched in case of a failure).
 * @param secret_kyber1024_key The Kyber1024 private key with which to decrypt the AES key.
 * @return The status code: <c>0</c> for success, all other status codes can be found inside the various qryptext header files.
 */
int qryptext_decrypt(uint8_t* encrypted_data, size_t encrypted_data_length, bool encrypted_data_base64, uint8_t* output_buffer, size_t output_buffer_size, size_t* output_length, qryptext_kyber1024_secret_key secret_kyber1024_key);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // QRYPTEXT_DECRYPT_H
