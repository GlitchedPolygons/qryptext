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

/**
 *  @file guid.h
 *  @author Raphael Beck
 *  @brief Mh! The smell of fresh GUIDs..
 */

#ifndef QRYPTEXT_GUID_H
#define QRYPTEXT_GUID_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include "types.h"

/**
 * Gets an empty GUID (<c>"00000000-0000-0000-0000-000000000000"</c>).
 * @return <c>"00000000-0000-0000-0000-000000000000"</c>
 */
QRYPTEXT_API qryptext_guid qryptext_empty_guid();

/**
 * Generates a new GUID (a.k.a. UUID).
 * @param lowercase Should the GUID be lowercase or UPPERCASE only? Pass any non-zero value for "true".
 * @param hyphens Should the GUID contain hyphen separators? Pass any non-zero value for "true".
 * @return The qryptext_guid
 */
QRYPTEXT_API qryptext_guid qryptext_new_guid(uint8_t lowercase, uint8_t hyphens);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // QRYPTEXT_GUID_H
