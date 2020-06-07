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

#ifndef QRYPTEXT_UTIL_H
#define QRYPTEXT_UTIL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include <kem_kyber.h>
#include <pqclean_kyber1024_clean/api.h>

/**
 * Calculates the final output size of a ciphertext that would result from the qryptext_encrypt() function (based on a given plaintext length).
 * @param plaintext_length The amount of bytes to encrypt.
 * @return The final output size of the ciphertext if you encrypt data that is plaintext_length long with qryptext_encrypt().
 */
static inline size_t qryptext_calc_ciphertext_length(const size_t plaintext_length)
{
    return plaintext_length + 32 - (plaintext_length % 16) + OQS_KEM_kyber_1024_length_ciphertext;
}

/**
 * Gets a random 12-digit integer (ergo between <c>100000000000</c> and <c>999999999999</c>).
 * @return Random 12-digit integer
 */
static inline uint64_t get_random_big_int()
{
    srand(time(NULL) * time(NULL));
    const uint64_t min = 100000000000;
    const uint64_t max = 999999999999;
    return min + rand() / (RAND_MAX / (max - min + 1) + 1);
}

#ifdef __cplusplus
} // extern "C"
#endif

#endif // QRYPTEXT_UTIL_H
