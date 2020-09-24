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
#include <mbedtls/base64.h>
#include <mbedtls/platform_util.h>

#include <oqs/oqs.h>
#include <pqclean_falcon-1024_clean/api.h>

#include "qryptext/util.h"
#include "qryptext/verify.h"
#include "qryptext/constants.h"

int qryptext_verify(const uint8_t* data, const size_t data_length, const uint8_t* signature, const size_t signature_length, const bool signature_base64, const qryptext_falcon1024_public_key public_falcon1024_key)
{
    if (data == NULL || signature == NULL)
    {
        qryptext_fprintf(stderr, "qryptext: signature verification failed due to one or more NULL arguments!\n");
        return QRYPTEXT_ERROR_NULL_ARG;
    }

    if (data_length == 0)
    {
        qryptext_fprintf(stderr, "qryptext: signature verification failed due to the data_length parameter having value zero OR invalid signature length.\n");
        return QRYPTEXT_ERROR_INVALID_ARG;
    }

    int ret = -1;
    size_t signature_bin_length;
    uint8_t signature_bin[OQS_SIG_falcon_1024_length_signature + 1];
    memset(signature_bin, 0x00, sizeof(signature_bin));
    if (signature_base64)
    {
        ret = mbedtls_base64_decode(signature_bin, sizeof(signature_bin), &signature_bin_length, signature, signature_length);
        if (ret != 0)
        {
            qryptext_fprintf(stderr, "qryptext: signature verification failed while base64-decoding the signature. \"mbedtls_base64_decode\" returned: %d\n", ret);
            return QRYPTEXT_ERROR_INVALID_ARG;
        }
    }
    else
    {
        memcpy(signature_bin, signature, signature_bin_length = signature_length);
    }

    uint8_t public_key[OQS_SIG_falcon_1024_length_public_key + 1];
    mbedtls_platform_zeroize(public_key, sizeof(public_key));
    ret = qryptext_hexstr2bin(public_falcon1024_key.hexstring, sizeof(public_falcon1024_key.hexstring), public_key, sizeof(public_key), NULL);
    if (ret != 0)
    {
        qryptext_fprintf(stderr, "qryptext: signature verification failed while trying to decode the public key from hex-string to binary. \"qryptext_hexstr2bin\" returned: %d\n", ret);
        return ret;
    }

    ret = OQS_SIG_falcon_1024_verify(data, data_length, signature_bin, signature_bin_length, public_key);
    if (ret != 0)
    {
        qryptext_fprintf(stderr, "qryptext: signature verification failed! \"OQS_SIG_falcon_1024_verify\" returned: %d\n", ret);
        return ret;
    }

    mbedtls_platform_zeroize(public_key, sizeof(public_key));
    mbedtls_platform_zeroize(signature_bin, sizeof(signature_bin));
    return ret;
}