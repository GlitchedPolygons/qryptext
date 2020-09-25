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
 *  @file constants.h
 *  @author Raphael Beck
 *  @brief Qryptext constants.
 */

#ifndef QRYPTEXT_CONSTANTS_H
#define QRYPTEXT_CONSTANTS_H

#ifdef __cplusplus
extern "C" {
#endif

// Qryptext constants:

#define QRYPTEXT_VERSION 100
#define QRYPTEXT_VERSION_STR "1.0.0"

#define QRYPTEXT_ERROR_NULL_ARG 1000
#define QRYPTEXT_ERROR_INVALID_ARG 1001
#define QRYPTEXT_ERROR_OUT_OF_MEMORY 1002
#define QRYPTEXT_ERROR_INSUFFICIENT_OUTPUT_BUFFER_SIZE 1003

// These are taken from <pqclean_kyber1024_clean/api.h> and <pqclean_falcon-1024_clean/api.h> respectively:
#define PQCLEAN_KYBER1024_CLEAN_CRYPTO_SECRETKEYBYTES 3168
#define PQCLEAN_KYBER1024_CLEAN_CRYPTO_PUBLICKEYBYTES 1568
#define PQCLEAN_FALCON1024_CLEAN_CRYPTO_SECRETKEYBYTES 2305
#define PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES 1793

#ifdef __cplusplus
} // extern "C"
#endif

#endif // QRYPTEXT_CONSTANTS_H
