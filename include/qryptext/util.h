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
 *  @file util.h
 *  @author Raphael Beck
 *  @brief Useful utility functions for qryptext.
 */

#ifndef QRYPTEXT_UTIL_H
#define QRYPTEXT_UTIL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <time.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef _WIN32
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <bcrypt.h>
#endif

#include <oqs/kem_kyber.h>
#include <pqclean_kyber1024_clean/api.h>

/**
 * <c>x < y ? x : y</c>
 */
#define QRYPTEXT_MIN(x, y) (((x) < (y)) ? (x) : (y))

/**
 * <c>x > y ? x : y</c>
 */
#define QRYPTEXT_MAX(x, y) (((x) > (y)) ? (x) : (y))

/**
 * Calculates the final output size of a ciphertext that would result from the qryptext_encrypt() function (based on a given plaintext length).
 * @param plaintext_length The amount of bytes to encrypt.
 * @return The final output size of the ciphertext if you encrypt data that is plaintext_length bytes long with qryptext_encrypt().
 */
static inline size_t qryptext_calc_ciphertext_length(const size_t plaintext_length)
{
    return plaintext_length + 32 - (plaintext_length % 16) + OQS_KEM_kyber_1024_length_ciphertext;
}

/**
 * (Tries to) read from <c>/dev/urandom</c> (or Windows equivalent, yeah...) filling the given \p output_buffer with \p output_buffer_size random bytes.
 * @param output_buffer Where to write the random bytes into.
 * @param output_buffer_size How many random bytes to write into \p output_buffer
 */
static inline void qryptext_dev_urandom(uint8_t* output_buffer, const size_t output_buffer_size)
{
    if (output_buffer != NULL && output_buffer_size > 0)
    {
#ifdef _WIN32
        BCryptGenRandom(NULL, output_buffer, output_buffer_size, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
#else
        FILE* rnd = fopen("/dev/urandom", "r");
        if (rnd != NULL)
        {
            fread(output_buffer, sizeof(uint8_t), output_buffer_size, rnd);
            fclose(rnd);
        }
#endif
    }
}

/**
 * Gets a random big integer. This only features very limited randomness due to usage of <c>rand()</c>! <p>
 * **DO NOT USE THIS FOR ANY TYPE OF KEY GENERATION!** <p>
 * Current usage is for adding some lightweight additional entropy to the MbedTLS mbedtls_ctr_drbg_seed() function,
 * which only gives the advantage of having a slightly different per-app starting point for the seed (as stated in the MbedTLS documentation).
 * @return Random big number
 */
static inline unsigned long long int qryptext_get_random_big_integer()
{
    srand(time(NULL) * time(NULL));
    return rand() * rand() * rand() * rand();
}

#ifdef __cplusplus
} // extern "C"
#endif

#endif // QRYPTEXT_UTIL_H
