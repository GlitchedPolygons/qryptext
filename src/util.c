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
#include <string.h>
#include <stdbool.h>
#include "qryptext/util.h"

#include <oqs/oqs.h>
#include <pqclean_falcon-1024_clean/api.h>

#ifdef _WIN32
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <bcrypt.h>
#endif

#include <mbedtls/base64.h>

static bool _qryptext_fprintf_enabled = true;

bool qryptext_is_fprintf_enabled()
{
    return _qryptext_fprintf_enabled;
}

int (*_qryptext_fprintf_fptr)(FILE* stream, const char* format, ...) = &fprintf;

void qryptext_enable_fprintf()
{
    _qryptext_fprintf_enabled = true;
    _qryptext_fprintf_fptr = &fprintf;
}

void qryptext_disable_fprintf()
{
    _qryptext_fprintf_enabled = false;
    _qryptext_fprintf_fptr = &qryptext_printvoid;
}

void qryptext_dev_urandom(uint8_t* output_buffer, const size_t output_buffer_size)
{
    if (output_buffer != NULL && output_buffer_size > 0)
    {
#ifdef _WIN32
        BCryptGenRandom(NULL, output_buffer, (ULONG)output_buffer_size, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
#else
        FILE* rnd = fopen("/dev/urandom", "rb");
        if (rnd != NULL)
        {
            const size_t n = fread(output_buffer, sizeof(uint8_t), output_buffer_size, rnd);
            if (n != output_buffer_size)
            {
                qryptext_fprintf(stderr, "qryptext: Warning! Only %zu bytes out of %zu have been read from /dev/urandom\n", n, output_buffer_size);
            }
            fclose(rnd);
        }
#endif
    }
}

size_t qryptext_calc_encryption_output_length(const size_t plaintext_length)
{
    return 16 + 32 + 16 + OQS_KEM_kyber_1024_length_ciphertext + plaintext_length;
}

size_t qryptext_calc_base64_length(const size_t data_length)
{
    size_t r;
    return mbedtls_base64_encode(NULL, 0, &r, NULL, data_length) ? ((4 * data_length / 3 + 3) & ~(unsigned)3) + 1 : r;
}

int qryptext_hexstr2bin(const char* hexstr, const size_t hexstr_length, unsigned char* output, const size_t output_size, size_t* output_length)
{
    if (hexstr == NULL || output == NULL || hexstr_length == 0)
    {
        return 1;
    }

    const size_t hl = hexstr[hexstr_length - 1] ? hexstr_length : hexstr_length - 1;

    if (hl % 2 != 0)
    {
        return 2;
    }

    const size_t final_length = hl / 2;

    if (output_size < final_length + 1)
    {
        return 3;
    }

    for (size_t i = 0, ii = 0; ii < final_length; i += 2, ii++)
    {
        output[ii] = (hexstr[i] % 32 + 9) % 25 * 16 + (hexstr[i + 1] % 32 + 9) % 25;
    }

    output[final_length] = '\0';

    if (output_length != NULL)
    {
        *output_length = final_length;
    }

    return 0;
}

int qryptext_bin2hexstr(const unsigned char* bin, const size_t bin_length, char* output, const size_t output_size, size_t* output_length, const bool uppercase)
{
    if (bin == NULL || bin_length == 0 || output == NULL)
    {
        return 1;
    }

    const size_t final_length = bin_length * 2;

    if (output_size < final_length + 1)
    {
        return 2;
    }

    const char* format = uppercase ? "%02X" : "%02x";

    for (size_t i = 0; i < bin_length; i++)
    {
        sprintf(output + i * 2, format, bin[i]);
    }

    output[final_length] = '\0';

    if (output_length != NULL)
    {
        *output_length = final_length;
    }

    return 0;
}
