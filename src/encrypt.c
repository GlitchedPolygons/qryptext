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
#include <mbedtls/gcm.h>
#include <mbedtls/entropy.h>
#include <mbedtls/platform.h>
#include <mbedtls/ctr_drbg.h>
#include <pqclean_kyber1024_clean/api.h>

#include "qryptext/util.h"
#include <qryptext/guid.h>
#include "qryptext/encrypt.h"
#include "qryptext/constants.h"

int qryptext_encrypt(const uint8_t* data, const size_t data_length, uint8_t* output_buffer, const size_t output_buffer_size, size_t* output_length, const qryptext_kyber1024_public_key public_kyber1024_key)
{
    int ret = 1;

    if (data == NULL || output_buffer == NULL || output_length == NULL)
    {
        return QRYPTEXT_ERROR_NULL_ARG;
    }

    if (data_length == 0)
    {
        return QRYPTEXT_ERROR_INVALID_ARG;
    }

    const size_t ctlen = qryptext_calc_ciphertext_length(data_length);

    if (output_buffer_size < ctlen)
    {
        return QRYPTEXT_ERROR_INSUFFICIENT_OUTPUT_BUFFER_SIZE;
    }

    mbedtls_pk_context pk;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_gcm_context aes_ctx;
    mbedtls_md_context_t md_ctx;

    uint8_t pers[256];
    qryptext_dev_urandom(pers, 128);
    snprintf((char*)(pers + 128), 128, "qryptext_#!-7$\\\"/.+@34..#0%llu%s", qryptext_get_random_big_integer(), qryptext_new_guid(false, true).string);

    uint8_t aes256key[32];
    memset(aes256key, 0x00, sizeof(aes256key));

    mbedtls_pk_init(&pk);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_gcm_init(&aes_ctx);
    mbedtls_md_init(&md_ctx);

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, pers, QRYPTEXT_MIN(sizeof(pers), (MBEDTLS_CTR_DRBG_MAX_SEED_INPUT - MBEDTLS_CTR_DRBG_ENTROPY_LEN - 1)));
    if (ret != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

exit:
    mbedtls_md_free(&md_ctx);
    mbedtls_gcm_free(&aes_ctx);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_pk_free(&pk);

    return (ret);
}