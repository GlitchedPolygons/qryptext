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
    qryptext_enable_fprintf(); // Allow fprintf in case errors occur and need to be fprintf'ed.
    printf("\n---- QRYPTEXT ----\n--  Example 02  --\n\n");

    // Generate a fresh Falcon-1024 keypair (on the stack) with the following instructions:
    qryptext_falcon1024_keypair falcon1024_keypair;
    int r = qryptext_falcon1024_generate_keypair(&falcon1024_keypair);
    if (r != 0)
    {
        printf("Falcon-1024 example key-pair generation failed!  \"qryptext_falcon1024_generate_keypair\" returned %d\n", r);
        return r;
    }

    // Print it out.
    printf("Successfully generated Falcon-1024 key-pair!\n\nSecret key:\n\n%s\n\nPublic key:\n\n%s\n\n", falcon1024_keypair.secret_key.hexstring, falcon1024_keypair.public_key.hexstring);

    // Cleanup:
    memset(&falcon1024_keypair, 0x00, sizeof(qryptext_falcon1024_keypair));
    qryptext_disable_fprintf();
    return 0;
}
