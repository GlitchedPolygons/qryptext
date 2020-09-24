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

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <qryptext/util.h>
#include <qryptext/verify.h>
#include <pqclean_falcon-1024_clean/api.h>

int main(const int argc, const char* argv[])
{
    qryptext_enable_fprintf();

    if (argc == 1 || (argc == 2 && strcmp(argv[1], "--help") == 0))
    {
        fprintf(stdout, "qryptext_verify:  Verify a Falcon1024 signature using a specific public key. Call this program using exactly 3 arguments;  the FIRST one being the PUBLIC KEY (hex-string), the SECOND one being the SIGNATURE to verify and the THIRD one the actual STRING TO VERIFY the signature against.\n");
        return 0;
    }

    if (argc != 4)
    {
        fprintf(stderr, "qryptext_verify: wrong argument count. Check out \"qryptext_verify --help\" for more details about how to use this!\n");
        return -1;
    }

    const char* public_key_hexstr = argv[1];
    const char* signature = argv[2];
    const char* message = argv[3];

    const size_t public_key_hexstr_len = strlen(public_key_hexstr);
    const size_t signature_len = strlen(signature);
    const size_t message_len = strlen(message);

    if (public_key_hexstr_len != (PQCLEAN_FALCON1024_CLEAN_CRYPTO_PUBLICKEYBYTES * 2))
    {
        fprintf(stderr, "qryptext_verify: Invalid public key format/length!\n");
        return -2;
    }

    qryptext_falcon1024_public_key public_key;
    memset(&public_key, 0x00, sizeof(qryptext_falcon1024_public_key));
    memcpy(public_key.hexstring, public_key_hexstr, public_key_hexstr_len);

    int r = qryptext_verify((const uint8_t*)message, message_len, (const uint8_t*)signature, signature_len, true, public_key);
    if (r != 0)
    {
        return -3;
    }

    fprintf(stdout, "qryptext_verify: signature valid!\n");
    return 0;
}
