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

#define QRYPTEXT_ENCRYPTION_ERROR_NULL_ARG 1000
#define QRYPTEXT_ENCRYPTION_ERROR_INSUFFICIENT_OUTPUT_BUFFER_SIZE 1001
#define QRYPTEXT_ENCRYPTION_ERROR_INVALID_KYBER_KEY_FORMAT 1002
#define QRYPTEXT_ENCRYPTION_ERROR_INVALID_RSA_KEY_FORMAT 1003
#define QRYPTEXT_ENCRYPTION_ERROR_OUT_OF_MEMORY 1004

/**
 * Encrypts a given byte array of data using AES256-CBC, Kyber1024 and (optionally) RSA.
 * @param data The data to encrypt.
 * @param data_length Length of the data array.
 * @param output_buffer Where to write the encrypted ciphertext into (make sure that this is allocated sufficiently big!).
 * @param output_buffer_size How big the output buffer is (use qryptext_calc_ciphertext_length() for allocation size guideline).
 * @param output_length Where to write the number of bytes written to the output buffer into (will be left untouched in case of a failure).
 * @param public_kyber1024_key The Kyber1024 public key with which to encrypt the AES key.
 * @param public_kyber1024_key_length The length of the public_kyber1024_key array.
 * @param public_rsa_key [OPTIONAL] RSA public key (PEM-formatted string) with which to additionally encrypt the AES key (can be left <c>NULL</c> if you want Kyber-only).
 * @param public_rsa_key_length [OPTIONAL] Length of the public_rsa_key string (this is ignored if public_rsa_key is <c>NULL</c>).
 * @return The status code: <c>0</c> if encryption succeeded, all other status codes can be found inside the various qryptext header files.
 */
int qryptext_encrypt(uint8_t* data, size_t data_length, uint8_t* output_buffer, size_t output_buffer_size, size_t* output_length, uint8_t* public_kyber1024_key, size_t public_kyber1024_key_length, uint8_t* public_rsa_key, size_t public_rsa_key_length);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // QRYPTEXT_CONSTANTS_H
