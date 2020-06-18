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

#include <mbedtls/aes.h>
#include <mbedtls/gcm.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/entropy.h>
#include <mbedtls/platform.h>
#include <mbedtls/ctr_drbg.h>

#include <oqs/oqs.h>
#include <pqclean_kyber1024_clean/api.h>

#include "qryptext/util.h"
#include <qryptext/guid.h>
#include "qryptext/encrypt.h"
#include "qryptext/constants.h"

int qryptext_encrypt(const uint8_t* data, const size_t data_length, uint8_t* output_buffer, const size_t output_buffer_size, size_t* output_length, const bool output_base64, const qryptext_kyber1024_public_key public_kyber1024_key)
{
    int ret = 1;

    if (data == NULL || output_buffer == NULL)
    {
        return QRYPTEXT_ERROR_NULL_ARG;
    }

    if (data_length == 0)
    {
        return QRYPTEXT_ERROR_INVALID_ARG;
    }

    size_t olen = qryptext_calc_encryption_output_length(data_length);
    size_t total_output_length = output_base64 ? qryptext_calc_base64_length(olen) : olen;

    if (output_buffer_size < total_output_length)
    {
        return QRYPTEXT_ERROR_INSUFFICIENT_OUTPUT_BUFFER_SIZE;
    }

    mbedtls_gcm_context aes_ctx;
    mbedtls_md_context_t md_ctx;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    uint8_t pers[256];
    qryptext_dev_urandom(pers, 128);
    snprintf((char*)(pers + 128), 128, "qryptext_#!-;7$\\\"/.+@3+¨49'..#!0%llu%s", qryptext_get_random_big_integer(), qryptext_new_guid(false, true).string);

    uint8_t iv[16];
    uint8_t salt[32];
    uint8_t aes_key[32];
    uint8_t ciphertext[PQCLEAN_KYBER1024_CLEAN_CRYPTO_CIPHERTEXTBYTES];
    uint8_t public_key[PQCLEAN_KYBER1024_CLEAN_CRYPTO_PUBLICKEYBYTES + 1];
    uint8_t shared_secret[PQCLEAN_KYBER1024_CLEAN_CRYPTO_CIPHERTEXTBYTES];

    memset(iv, 0x00, sizeof(iv));
    memset(salt, 0x00, sizeof(salt));
    memset(aes_key, 0x00, sizeof(aes_key));
    memset(ciphertext, 0x00, sizeof(ciphertext));
    memset(public_key, 0x00, sizeof(public_key));
    memset(shared_secret, 0x00, sizeof(shared_secret));

    mbedtls_gcm_init(&aes_ctx);
    mbedtls_md_init(&md_ctx);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, pers, QRYPTEXT_MIN(sizeof(pers), (MBEDTLS_CTR_DRBG_MAX_SEED_INPUT - MBEDTLS_CTR_DRBG_ENTROPY_LEN - 1)));
    if (ret != 0)
    {
        qryptext_fprintf(stderr, "qryptext failure! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    ret = qryptext_hexstr2bin(public_kyber1024_key.hexstring, sizeof(public_kyber1024_key.hexstring), public_key, sizeof(public_key), NULL);
    if (ret != 0)
    {
        qryptext_fprintf(stderr, "qryptext encryption failed: couldn't parse the public key! qryptext_hexstr2bin returned %d\n", ret);
        goto exit;
    }

    ret = OQS_KEM_kyber_1024_encaps(ciphertext, shared_secret, public_key);
    if (ret != 0)
    {
        qryptext_fprintf(stderr, "qryptext failure! OQS_KEM_kyber_1024_encaps returned %d\n", ret);
        goto exit;
    }

    ret = mbedtls_ctr_drbg_random(&ctr_drbg, salt, 32);
    if (ret != 0 || memcmp(salt, empty32, 32) == 0)
    {
        qryptext_fprintf(stderr, "qryptext: Salt generation failed! mbedtls_ctr_drbg_random returned %d\n", ret);
        goto exit;
    }

    ret = mbedtls_ctr_drbg_random(&ctr_drbg, iv, 16);
    if (ret != 0 || memcmp(iv, empty32, 16) == 0)
    {
        qryptext_fprintf(stderr, "qryptext: IV generation failed! mbedtls_ctr_drbg_random returned %d\n", ret);
        goto exit;
    }

    ret = mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA512), 1);
    if (ret != 0)
    {
        qryptext_fprintf(stderr, "qryptext: MbedTLS MD context (SHA512) setup failed! mbedtls_md_setup returned %d\n", ret);
        goto exit;
    }

    ret = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA512), salt, 32, shared_secret, sizeof(shared_secret), NULL, 0, aes_key, 32);
    if (ret != 0 || memcmp(aes_key, empty32, 32) == 0)
    {
        qryptext_fprintf(stderr, "qryptext: HKDF failed! mbedtls_hkdf returned %d\n", ret);
        goto exit;
    }

    ret = mbedtls_gcm_setkey(&aes_ctx, MBEDTLS_CIPHER_ID_AES, aes_key, 256);
    if (ret != 0)
    {
        qryptext_fprintf(stderr, "qryptext: AES key setup failed! mbedtls_gcm_setkey returned %d\n", ret);
        goto exit;
    }

    const size_t ciphertext_length = sizeof(ciphertext);
    uint8_t* o = output_buffer;

    memcpy(o, iv, 16);
    o += 16;

    memcpy(o, salt, 32);
    o += 32;

    memcpy(o, ciphertext, ciphertext_length);
    o += ciphertext_length;

    ret = mbedtls_gcm_crypt_and_tag(&aes_ctx, MBEDTLS_GCM_ENCRYPT, data_length, iv, 16, NULL, 0, data, o + 16, 16, o);
    if (ret != 0)
    {
        qryptext_fprintf(stderr, "qryptext: AES-GCM encryption failed! mbedtls_gcm_crypt_and_tag returned %d\n", ret);
        goto exit;
    }

    if (output_base64)
    {
        size_t b64len;
        uint8_t* b64 = malloc(total_output_length);
        if (b64 == NULL)
        {
            ret = QRYPTEXT_ERROR_OUT_OF_MEMORY;
            qryptext_fprintf(stderr, "qryptext: AES-GCM encryption failed while base64-encoding the output - OUT OF MEMORY! \n");
            goto exit;
        }

        ret = mbedtls_base64_encode(b64, total_output_length, &b64len, output_buffer, olen);
        if (ret != 0)
        {
            qryptext_fprintf(stderr, "qryptext: AES-GCM encryption failed while base64-encoding! mbedtls_base64_encode returned %d\n", ret);
            free(b64);
            goto exit;
        }

        b64[total_output_length - 1] = '\0';
        memcpy(output_buffer, b64, total_output_length--);
        free(b64);
    }

    if (output_length != NULL)
    {
        *output_length = total_output_length;
    }

exit:
    mbedtls_gcm_free(&aes_ctx);
    mbedtls_md_free(&md_ctx);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);

    memset(iv, 0x00, sizeof(iv));
    memset(salt, 0x00, sizeof(salt));
    memset(aes_key, 0x00, sizeof(aes_key));
    memset(ciphertext, 0x00, sizeof(ciphertext));
    memset(public_key, 0x00, sizeof(public_key));
    memset(shared_secret, 0x00, sizeof(shared_secret));

    return (ret);
}