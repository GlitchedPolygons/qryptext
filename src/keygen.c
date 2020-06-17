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

#include <oqs/oqs.h>
#include "qryptext/util.h"
#include "qryptext/guid.h"
#include "qryptext/keygen.h"
#include "qryptext/constants.h"

int qryptext_kyber1024_generate_keypair(qryptext_kyber1024_keypair* output)
{
    if (output == NULL)
    {
        qryptext_fprintf(stderr, "\nqryptext: Key generation failed because the output argument was NULL!");
        return QRYPTEXT_ERROR_NULL_ARG;
    }

    uint8_t public_key[PQCLEAN_KYBER1024_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t secret_key[PQCLEAN_KYBER1024_CLEAN_CRYPTO_SECRETKEYBYTES];

    int ret = OQS_KEM_kyber_1024_keypair(public_key, secret_key);
    if (ret != 0)
    {
        qryptext_fprintf(stderr, "\nqryptext: Kyber-1024 key generation failed. \"OQS_KEM_kyber_1024_keypair\" returned %d\n", ret);
        return ret;
    }

    ret = qryptext_bin2hexstr(public_key, sizeof(public_key), output->public_key.hexstring, sizeof(output->public_key.hexstring), NULL, false);
    if (ret != 0)
    {
        qryptext_fprintf(stderr, "\nqryptext: Kyber-1024 key generation failed while encoding public key to hex-string. \"qryptext_bin2hexstr\" returned %d\n", ret);
        return ret;
    }

    ret = qryptext_bin2hexstr(secret_key, sizeof(secret_key), output->secret_key.hexstring, sizeof(output->secret_key.hexstring), NULL, false);
    if (ret != 0)
    {
        qryptext_fprintf(stderr, "\nqryptext: Kyber-1024 key generation failed while encoding secret key to hex-string. \"qryptext_bin2hexstr\" returned %d\n", ret);
        return ret;
    }

    return 0;
}

int qryptext_falcon1024_generate_keypair(qryptext_falcon1024_keypair* output)
{
    if (output == NULL)
    {
        qryptext_fprintf(stderr, "\nqryptext: Key generation failed because the output argument was NULL!");
        return QRYPTEXT_ERROR_NULL_ARG;
    }

    uint8_t public_key[PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t secret_key[PQCLEAN_FALCON1024_CLEAN_CRYPTO_SECRETKEYBYTES];

    int ret = OQS_SIG_falcon_1024_keypair(public_key, secret_key);
    if (ret != 0)
    {
        qryptext_fprintf(stderr, "\nqryptext: Falcon-1024 key generation failed. \"OQS_SIG_falcon_1024_keypair\" returned %d\n", ret);
        return ret;
    }

    ret = qryptext_bin2hexstr(public_key, sizeof(public_key), output->public_key.hexstring, sizeof(output->public_key.hexstring), NULL, false);
    if (ret != 0)
    {
        qryptext_fprintf(stderr, "\nqryptext: Falcon-1024 key generation failed while encoding public key to hex-string. \"qryptext_bin2hexstr\" returned %d\n", ret);
        return ret;
    }

    ret = qryptext_bin2hexstr(secret_key, sizeof(secret_key), output->secret_key.hexstring, sizeof(output->secret_key.hexstring), NULL, false);
    if (ret != 0)
    {
        qryptext_fprintf(stderr, "\nqryptext: Falcon-1024 key generation failed while encoding secret key to hex-string. \"qryptext_bin2hexstr\" returned %d\n", ret);
        return ret;
    }

    return 0;
}