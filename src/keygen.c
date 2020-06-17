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

    qryptext_kyber1024_public_key public_key;
    qryptext_kyber1024_secret_key secret_key;

    int ret = OQS_KEM_kyber_1024_keypair(public_key.bytes, secret_key.bytes);
    if (ret != 0)
    {
        qryptext_fprintf(stderr, "\nqryptext: Kyber1024 key generation failed. \"OQS_KEM_kyber_1024_keypair\" returned %d\n", ret);
        return ret;
    }

    memcpy(&output->public_key, &public_key, sizeof(qryptext_kyber1024_public_key));
    memcpy(&output->secret_key, &secret_key, sizeof(qryptext_kyber1024_secret_key));

    return 0;
}

int qryptext_falcon1024_generate_keypair(qryptext_falcon1024_keypair* output)
{
    if (output == NULL)
    {
        qryptext_fprintf(stderr, "\nqryptext: Key generation failed because the output argument was NULL!");
        return QRYPTEXT_ERROR_NULL_ARG;
    }

    qryptext_falcon1024_public_key public_key;
    qryptext_falcon1024_secret_key secret_key;

    int ret = OQS_SIG_falcon_1024_keypair(public_key.bytes, secret_key.bytes);
    if (ret != 0)
    {
        qryptext_fprintf(stderr, "\nqryptext: Falcon1024 key generation failed. \"OQS_SIG_falcon_1024_keypair\" returned %d\n", ret);
        return ret;
    }

    memcpy(&output->public_key, &public_key, sizeof(qryptext_falcon1024_public_key));
    memcpy(&output->secret_key, &secret_key, sizeof(qryptext_falcon1024_secret_key));

    return 0;
}