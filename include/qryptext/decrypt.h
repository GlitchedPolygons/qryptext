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

#ifndef QRYPTEXT_DECRYPT_H
#define QRYPTEXT_DECRYPT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

#define QRYPTEXT_DECRYPTION_ERROR_NULL_ARG 2000
#define QRYPTEXT_DECRYPTION_ERROR_INVALID_ARG 2001
#define QRYPTEXT_DECRYPTION_ERROR_INSUFFICIENT_OUTPUT_BUFFER_SIZE 2002
#define QRYPTEXT_DECRYPTION_ERROR_INVALID_KYBER_KEY_FORMAT 2003
#define QRYPTEXT_DECRYPTION_ERROR_INVALID_RSA_KEY_FORMAT 2004
#define QRYPTEXT_DECRYPTION_ERROR_OUT_OF_MEMORY 2005

/**
 * Decrypts a given byte array of data that was encrypted using qryptext_encrypt().
 * @param data The data to decrypt.
 * @param data_length Length of the data array.
 * @param output_buffer Where to write the decrypted data into (make sure that this is allocated sufficiently big!).
 * @param output_buffer_size How big the output buffer is (usually the same size as the encrypted data length, since plaintext will be smaller in most cases).
 * @param output_length Where to write the number of bytes written to the output buffer into (will be left untouched in case of a failure).
 * @param private_kyber1024_key The Kyber1024 private key with which to decrypt the AES key.
 * @param private_kyber1024_key_length The length of the private_kyber1024_key array.
 * @param private_rsa_key [OPTIONAL] RSA private key (PEM-formatted string) with which to decrypt the AES key (can be left <c>NULL</c> if the data was encrypted Kyber-only).
 * @param private_rsa_key_length [OPTIONAL] Length of the private_rsa_key string (this is ignored if private_rsa_key is <c>NULL</c>).
 * @return The status code: <c>0</c> for success, all other status codes can be found inside the various qryptext header files.
 */
int qryptext_decrypt(uint8_t* data, size_t data_length, uint8_t* output_buffer, size_t output_buffer_size, size_t* output_length, uint8_t* private_kyber1024_key, size_t private_kyber1024_key_length, uint8_t* private_rsa_key, size_t private_rsa_key_length);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // QRYPTEXT_DECRYPT_H
