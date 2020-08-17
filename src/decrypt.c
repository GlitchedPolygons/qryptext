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

#include <mbedtls/md.h>
#include <mbedtls/gcm.h>
#include <mbedtls/hkdf.h>

#include "qryptext/util.h"
#include "qryptext/guid.h"
#include "qryptext/decrypt.h"
#include "qryptext/constants.h"

int qryptext_decrypt(uint8_t* encrypted_data, const size_t encrypted_data_length, const bool encrypted_data_base64, uint8_t* output_buffer, const size_t output_buffer_size, size_t* output_length, const qryptext_kyber1024_secret_key secret_kyber1024_key)
{
    if (encrypted_data == NULL || output_buffer == NULL || output_length == NULL)
    {
        qryptext_fprintf(stderr, "qryptext: decryption failed: one or more NULL arguments.\n");
        return QRYPTEXT_ERROR_NULL_ARG;
    }

    if (encrypted_data_length < 1633 || output_buffer_size == 0)
    {
        qryptext_fprintf(stderr, "qryptext: decryption failed: one or more invalid arguments.\n");
        return QRYPTEXT_ERROR_INVALID_ARG;
    }

    int ret = 1;
    uint8_t* input = encrypted_data;
    size_t input_length = encrypted_data_length;

    if (encrypted_data_base64)
    {
        input = malloc(input_length);
        if (input == NULL)
        {
            qryptext_fprintf(stderr, "qryptext: decryption failed: OUT OF MEMORY!\n");
            return QRYPTEXT_ERROR_OUT_OF_MEMORY;
        }

        if (encrypted_data[input_length - 1] == '\0')
        {
            input_length--;
        }

        ret = mbedtls_base64_decode(input, input_length, &input_length, encrypted_data, input_length);
        if (ret != 0)
        {
            free(input);
            qryptext_fprintf(stderr, "qryptext: decryption failed: couldn't base64-decode the given data! \"mbedtls_base64_decode\" returned: %d\n", ret);
            return QRYPTEXT_ERROR_INVALID_ARG;
        }
    }

    const size_t olen = input_length - 16 - 32 - 16 - OQS_KEM_kyber_1024_length_ciphertext;

    if (output_buffer_size < olen)
    {
        qryptext_fprintf(stderr, "qryptext: decryption failed due to insufficient output buffer size. Please allocate at least as many bytes as the encrypted input buffer, just to be sure!\n");
        return QRYPTEXT_ERROR_INSUFFICIENT_OUTPUT_BUFFER_SIZE;
    }

    mbedtls_gcm_context aes_ctx;
    mbedtls_md_context_t md_ctx;

    mbedtls_gcm_init(&aes_ctx);
    mbedtls_md_init(&md_ctx);

    uint8_t iv[16];
    uint8_t tag[16];
    uint8_t salt[32];
    uint8_t aes_key[32];
    uint8_t ciphertext[OQS_KEM_kyber_1024_length_ciphertext];
    uint8_t secret_key[OQS_KEM_kyber_1024_length_secret_key + 1];
    uint8_t shared_secret[OQS_KEM_kyber_1024_length_shared_secret];

    memset(aes_key, 0x00, 32);

    memcpy(iv, input, 16);
    memcpy(salt, input + 16, 32);
    memcpy(ciphertext, input + 16 + 32, OQS_KEM_kyber_1024_length_ciphertext);
    memcpy(tag, input + 16 + 32 + OQS_KEM_kyber_1024_length_ciphertext, 16);

    ret = qryptext_hexstr2bin(secret_kyber1024_key.hexstring, sizeof(secret_kyber1024_key.hexstring), secret_key, sizeof(secret_key), NULL);
    if (ret != 0)
    {
        qryptext_fprintf(stderr, "qryptext: decryption failed while converting secret key hexstring 2 bin... \"qryptext_hexstr2bin\" returned %d\n", ret);
        goto exit;
    }

    ret = OQS_KEM_kyber_1024_decaps(shared_secret, ciphertext, secret_key);
    if (ret != 0)
    {
        qryptext_fprintf(stderr, "qryptext: decryption failed! \"OQS_KEM_kyber_1024_decaps\" returned %d\n", ret);
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
        qryptext_fprintf(stderr, "qryptext: HKDF failed! \"mbedtls_hkdf\" returned %d\n", ret);
        goto exit;
    }

    ret = mbedtls_gcm_setkey(&aes_ctx, MBEDTLS_CIPHER_ID_AES, aes_key, 256);
    if (ret != 0)
    {
        qryptext_fprintf(stderr, "qryptext: AES key setup failed! \"mbedtls_gcm_setkey\" returned %d\n", ret);
        goto exit;
    }

    ret = mbedtls_gcm_auth_decrypt(&aes_ctx, olen, iv, 16, NULL, 0, tag, 16, input + 16 + 32 + 16 + OQS_KEM_kyber_1024_length_ciphertext, output_buffer);
    if (ret != 0)
    {
        qryptext_fprintf(stderr, "qryptext: decryption failed! mbedtls_gcm_auth_decrypt returned %d\n", ret);
        goto exit;
    }

    *output_length = (size_t)olen;

exit:
    mbedtls_gcm_free(&aes_ctx);
    mbedtls_md_free(&md_ctx);

    mbedtls_platform_zeroize(iv, sizeof(iv));
    mbedtls_platform_zeroize(tag, sizeof(tag));
    mbedtls_platform_zeroize(salt, sizeof(salt));
    mbedtls_platform_zeroize(aes_key, sizeof(aes_key));
    mbedtls_platform_zeroize(ciphertext, sizeof(ciphertext));
    mbedtls_platform_zeroize(secret_key, sizeof(secret_key));
    mbedtls_platform_zeroize(shared_secret, sizeof(shared_secret));

    if (encrypted_data_base64)
    {
        free(input);
    }

    return (ret);
}