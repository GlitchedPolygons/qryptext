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

    uint8_t iv[16];
    uint8_t tag[16];
    uint8_t salt[32];
    uint8_t aes_key[32];

    memset(iv, 0x00, 16);
    memset(tag, 0x00, 16);
    memset(salt, 0x00, 32);
    memset(aes_key, 0x00, 32);

    uint8_t pers[256];
    qryptext_dev_urandom(pers, 128);
    snprintf((char*)(pers + 128), 128, "qryptext_2**\"^£¨]8\\#(.F?= _.@//*73,9-%s%llu", qryptext_new_guid(false, true).string, qryptext_get_random_big_integer());

exit:
    memset(iv, 0x00, 16);
    memset(tag, 0x00, 16);
    memset(salt, 0x00, 32);
    memset(aes_key, 0x00, 32);

    if (encrypted_data_base64)
    {
        free(input);
    }

    return (ret);
}