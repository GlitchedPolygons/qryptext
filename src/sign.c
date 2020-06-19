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

#include <oqs/oqs.h>
#include <pqclean_falcon-1024_clean/api.h>

#include "qryptext/constants.h"
#include "qryptext/util.h"
#include "qryptext/sign.h"

// TODO: write various fprintf's to stderr

int qryptext_sign(uint8_t* data, size_t data_length, uint8_t* output_buffer, size_t output_buffer_size, size_t* output_length, bool output_base64, qryptext_falcon1024_secret_key secret_falcon1024_key)
{
    if (data == NULL || output_buffer)
    {
        return QRYPTEXT_ERROR_NULL_ARG;
    }

    if (data_length == 0)
    {
        return QRYPTEXT_ERROR_INVALID_ARG;
    }

    const size_t total_output_length = output_base64 ? qryptext_calc_base64_length(OQS_SIG_falcon_1024_length_signature) : OQS_SIG_falcon_1024_length_signature;

    if (output_buffer_size < total_output_length)
    {
        return QRYPTEXT_ERROR_INSUFFICIENT_OUTPUT_BUFFER_SIZE;
    }

    int ret = -1;
    size_t signature_length;
    uint8_t signature[OQS_SIG_falcon_1024_length_signature];
    uint8_t secret_key[OQS_SIG_falcon_1024_length_secret_key + 1];

    ret = qryptext_hexstr2bin(secret_falcon1024_key.hexstring, sizeof(secret_falcon1024_key.hexstring), secret_key, sizeof(secret_key), &signature_length);
    if (ret != 0)
    {
        return ret;
    }

    ret = OQS_SIG_falcon_1024_sign(signature, &signature_length, data, data_length, secret_key);
    if (ret != 0)
    {
        return ret;
    }

    if (output_base64)
    {
        ret = mbedtls_base64_encode(output_buffer, output_buffer_size, output_length, signature, signature_length);
        if (ret != 0)
        {
            return ret;
        }
    }
    else
    {
        memcpy(output_buffer, signature, signature_length);
    }

    return ret;
}