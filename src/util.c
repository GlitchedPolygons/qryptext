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
#include "qryptext/util.h"

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