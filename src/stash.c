/*****************************************************************************
 *   Ledger App Bitcoin.
 *   (c) 2021 Ledger SAS.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

#include "common/buffer.h"
#include "stash.h"

// uint8_t g_stash[256];
// buffer_t g_stash_buff;

// void stash_init() {
//     g_stash_buff = buffer_create(g_stash, sizeof(g_stash));
// }

// void *stash_alloc(size_t size, bool aligned) {
//     return buffer_alloc(&g_stash_buff, size, aligned);
// }

// /**
//  * TODO: docs
//  */
// buffer_snapshot_t stash_snapshot() {
//     return g_stash_buff.offset;
// }

// /**
//  * TODO: docs
//  */
// void stash_restore(stash_snapshot_t snapshot) {
//     g_stash_buff.offset = snapshot;
// }
