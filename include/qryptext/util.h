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

#include <mbedtls/base64.h>
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
    size_t r;
    mbedtls_base64_encode(NULL, 0, &r, NULL, 16 + 32 + 16 + OQS_KEM_kyber_1024_length_ciphertext + plaintext_length);
    return r;
}

/**
 * Converts a hex string to binary array. <p>
 * A NUL-terminator is appended at the end of the output buffer, so make sure to allocate at least <c>(hexstr_length / 2) + 1</c> bytes!
 * @param hexstr The hex string to convert.
 * @param hexstr_length Length of the \p hexstr
 * @param output Where to write the converted binary data into.
 * @param output_size Size of the output buffer (make sure to allocate at least <c>(hexstr_length / 2) + 1</c> bytes!).
 * @param output_length [OPTIONAL] Where to write the output array length into. This is always gonna be <c>hexstr_length / 2</c>, but you can still choose to write it out just to be sure. If you want to omit this: no problem.. just pass <c>NULL</c>!
 * @return <c>0</c> if conversion succeeded. <c>1</c> if one or more required arguments were <c>NULL</c> or invalid. <c>2</c> if the hexadecimal string is in an invalid format (e.g. not divisible by 2). <c>3</c> if output buffer size was insufficient (needs to be at least <c>(hexstr_length / 2) + 1</c> bytes).
 */
int qryptext_hexstr2bin(const char* hexstr, size_t hexstr_length, uint8_t* output, size_t output_size, size_t* output_length);

/**
 * Converts a byte array to a hex string. <p>
 * A NUL-terminator is appended at the end of the output buffer, so make sure to allocate at least <c>(bin_length * 2) + 1</c> bytes!
 * @param bin The binary data to convert into hex string.
 * @param bin_length Length of the \p bin array.
 * @param output Where to write the hex string into.
 * @param output_size Maximum capacity of the \p output buffer. Make sure to allocate at least <c>(bin_length * 2) + 1</c> bytes!
 * @param output_length [OPTIONAL] Where to write the output string length into. This is always gonna be <c>bin_length * 2</c>, but you can still choose to write it out just to be sure. If you want to omit this: no problem.. just pass <c>NULL</c>!
 * @param uppercase Should the \p output string characters be UPPER- or lowercase?
 * @return <c>0</c> if conversion succeeded. <c>1</c> if one or more required arguments were <c>NULL</c> or invalid. <c>2</c> if the output buffer size is insufficient: please allocate at least <c>(bin_length * 2) + 1</c> bytes!
 */
int qryptext_bin2hexstr(const uint8_t* bin, size_t bin_length, char* output, size_t output_size, size_t* output_length, bool uppercase);

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
static inline uint64_t qryptext_get_random_big_integer()
{
    srand(time(NULL) * time(NULL));
    return rand() * rand() * rand() * rand();
}

/**
 * Checks whether qryptext's fprintf is enabled (whether errors are fprintfed into stderr).
 * @return Whether errors are fprintfed into stderr or not.
 */
bool qryptext_is_fprintf_enabled();

/**
 * Like fprintf() except it doesn't do anything. Like printing into <c>/dev/null</c> :D lots of fun!
 * @param stream [IGNORED]
 * @param format [IGNORED]
 * @param ... [IGNORED]
 * @return <c>0</c>
 */
static inline int qryptext_printvoid(FILE* stream, const char* format, ...)
{
    return 0;
}

/** @private */
extern int (*_qryptext_fprintf_fptr)(FILE* stream, const char* format, ...);

/**
 * Enables qryptext's use of fprintf().
 */
void qryptext_enable_fprintf();

/**
 * Disables qryptext's use of fprintf().
 */
void qryptext_disable_fprintf();

/** @private */
#define qryptext_fprintf _qryptext_fprintf_fptr

#ifdef __cplusplus
} // extern "C"
#endif

#endif // QRYPTEXT_UTIL_H
