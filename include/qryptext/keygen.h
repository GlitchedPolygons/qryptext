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
 *  @file keygen.h
 *  @author Raphael Beck
 *  @brief Kyber-1024 and Falcon-1024 key generator functions.
 */

#ifndef QRYPTEXT_KEYGEN_H
#define QRYPTEXT_KEYGEN_H

#ifdef __cplusplus
extern "C" {
#endif

#include "qryptext/types.h"

/**
 * Generates a fresh Kyber-1024 keypair to use for the KEM functionalities.
 * @param output qryptext_kyber1024_keypair instance into which to write the keypair.
 * @return
 */
QRYPTEXT_API int qryptext_kyber1024_generate_keypair(qryptext_kyber1024_keypair* output);

/**
 * Generates a fresh Falcon-1024 keypair to use for signing and verifying.
 * @param output qryptext_kyber1024_keypair instance into which to write the keypair.
 * @return
 */
QRYPTEXT_API int qryptext_falcon1024_generate_keypair(qryptext_falcon1024_keypair* output);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // QRYPTEXT_KEYGEN_H
