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

#include <string.h>
#include <mbedtls/pk.h>
#include <mbedtls/aes.h>
#include <mbedtls/entropy.h>
#include <mbedtls/platform.h>
#include <mbedtls/ctr_drbg.h>
#include <pqclean_kyber1024_clean/api.h>
#include "qryptext/util.h"
#include "qryptext/encrypt.h"

int qryptext_encrypt(const uint8_t* data, const size_t data_length, uint8_t* output_buffer, const size_t output_buffer_size, size_t* output_length, const uint8_t* public_kyber1024_key, const size_t public_kyber1024_key_length, const uint8_t* public_rsa_key, const size_t public_rsa_key_length)
{
    int ret = 1;

    if (data == NULL || output_buffer == NULL || output_length == NULL || public_kyber1024_key == NULL || public_rsa_key == NULL)
    {
        return QRYPTEXT_ENCRYPTION_ERROR_NULL_ARG;
    }

    if (data_length == 0 || public_kyber1024_key_length == 0)
    {
        return QRYPTEXT_ENCRYPTION_ERROR_INVALID_ARG;
    }

    const size_t ctlen = qryptext_calc_ciphertext_length(data_length);

    if (output_buffer_size < ctlen)
    {
        return QRYPTEXT_ENCRYPTION_ERROR_INSUFFICIENT_OUTPUT_BUFFER_SIZE;
    }

    mbedtls_pk_context pk;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    char pers[32];
    memset(pers, 0x00, sizeof(pers));

    unsigned char aes256key[64];
    memset(aes256key, 0x00, sizeof(aes256key));

    mbedtls_pk_init(&pk);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    snprintf(pers, sizeof(pers), "qryptext_#!-$/.+@3#0%ull", get_random_big_int());

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char*)pers, sizeof pers);
    if (ret != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

exit:
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return (ret);
}