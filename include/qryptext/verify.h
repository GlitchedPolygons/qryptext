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
 *  @file verify.h
 *  @author Raphael Beck
 *  @brief Verify signatures that were made using qryptext_sign() (Falcon1024).
 */

#ifndef QRYPTEXT_VERIFY_H
#define QRYPTEXT_VERIFY_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "qryptext/types.h"

/**
 * Verifies a data set's signature using Falcon-1024.
 * @param data The data whose signature you want to verify.
 * @param data_length Length of the \p data array.
 * @param signature The signature to verify. Can be raw bytes or base64-encoded string.
 * @param signature_length Length of the \p signature array.
 * @param signature_base64 Is the \p signature a base64-encoded string that needs to be decoded first before verification?
 * @param public_falcon1024_key The public Falcon-1024 key with which to verify the signature.
 * @return <c>0</c> if the signature is valid and could be verified successfully; anything else if something failed (according to the return codes defined inside constants.h or directly by the involved OQS function).
 */
int qryptext_verify(uint8_t* data, size_t data_length, uint8_t* signature, size_t signature_length, bool signature_base64, qryptext_falcon1024_public_key public_falcon1024_key);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // QRYPTEXT_VERIFY_H
