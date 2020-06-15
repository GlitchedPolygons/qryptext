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

#ifndef QRYPTEXT_TYPES_H
#define QRYPTEXT_TYPES_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include <pqclean_kyber1024_clean/api.h>

typedef struct qryptext_kyber1024_secret_key
{
    uint8_t bytes[PQCLEAN_KYBER1024_CLEAN_CRYPTO_SECRETKEYBYTES];
} qryptext_kyber1024_secret_key;

typedef struct qryptext_kyber1024_public_key
{
    uint8_t bytes[PQCLEAN_KYBER1024_CLEAN_CRYPTO_PUBLICKEYBYTES];
} qryptext_kyber1024_public_key;

typedef struct qryptext_kyber1024_keypair
{
    qryptext_kyber1024_public_key public_key;
    qryptext_kyber1024_secret_key secret_key;
} qryptext_kyber1024_keypair;

/**
 * @brief Struct containing the output from a call to the qryptext_new_guid() function. <p>
 * 36 characters (only 32 if you chose to omit the hyphens) + 1 NUL terminator.
 */
typedef struct qryptext_guid
{
    /** NUL-terminated string containing the GUID. */
    char string[36 + 1];
} qryptext_guid;

#ifdef __cplusplus
} // extern "C"
#endif

#endif // QRYPTEXT_TYPES_H
