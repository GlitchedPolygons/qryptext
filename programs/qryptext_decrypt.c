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
#include <qryptext/decrypt.h>

int main(const int argc, const char* argv[])
{
    qryptext_enable_fprintf();

    if (argc == 1 || (argc == 2 && strcmp(argv[1], "--help") == 0))
    {
        fprintf(stdout, "qryptext_decrypt:  Decrypt a string using a Kyber1024 secret key. Call this program using exactly 2 arguments;  the first one being the secret key (hex-string) and the second the string to decrypt.\n");
        return 0;
    }

    if (argc != 3)
    {
        fprintf(stderr, "qryptext_decrypt: wrong argument count. Check out \"qryptext_decrypt --help\" for more details about how to use this!\n");
        return -1;
    }

    const char* secret_key_hexstr = argv[1];
    const char* message = argv[2];

    const size_t secret_key_hexstr_len = strlen(secret_key_hexstr);
    const size_t message_len = strlen(message);

    if (secret_key_hexstr_len != (PQCLEAN_KYBER1024_CLEAN_CRYPTO_SECRETKEYBYTES * 2))
    {
        fprintf(stderr, "qryptext_decrypt: Invalid secret key format/length!\n");
        return -2;
    }

    qryptext_kyber1024_secret_key secret_key;
    memset(&secret_key, 0x00, sizeof(qryptext_kyber1024_secret_key));
    memcpy(secret_key.hexstring, secret_key_hexstr, secret_key_hexstr_len);

    size_t olen = 0;
    uint8_t* o = calloc(message_len, sizeof(uint8_t));

    if (o == NULL)
    {
        fprintf(stderr, "qryptext_decrypt: OUT OF MEMORY!\n");
        memset(&secret_key, 0x00, sizeof(qryptext_kyber1024_secret_key));
        return -3;
    }

    int r = qryptext_decrypt((uint8_t*)message, message_len, true, o, message_len, &olen, secret_key);
    if (r != 0)
    {
        memset(o, 0x00, message_len);
        memset(&secret_key, 0x00, sizeof(qryptext_kyber1024_secret_key));
        free(o);
        return -4;
    }

    fprintf(stdout, "%s", o);

    memset(o, 0x00, message_len);
    memset(&secret_key, 0x00, sizeof(qryptext_kyber1024_secret_key));
    free(o);
    return 0;
}
