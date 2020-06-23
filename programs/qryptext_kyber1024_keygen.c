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
#include <qryptext/keygen.h>

int main(void)
{
    qryptext_kyber1024_keypair kyber1024_keypair;

    const int r = qryptext_kyber1024_generate_keypair(&kyber1024_keypair);
    if (r != 0)
    {
        return r;
    }

    fprintf(stdout, "{\"kyber1024_secret_key\":\"%s\",\"kyber1024_public_key\":\"%s\"}\n", kyber1024_keypair.secret_key.hexstring, kyber1024_keypair.public_key.hexstring);

    // Cleanup:
    memset(&kyber1024_keypair, 0x00, sizeof(qryptext_kyber1024_keypair));
    return 0;
}
