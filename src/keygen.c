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

#include "qryptext/constants.h"
#include "qryptext/keygen.h"

int qryptext_kyber1024_generate_keypair(qryptext_kyber1024_keypair* output, uint8_t* additional_entropy, size_t additional_entropy_length)
{
    if (output == NULL)
    {
        return QRYPTEXT_ERROR_NULL_ARG;
    }
}