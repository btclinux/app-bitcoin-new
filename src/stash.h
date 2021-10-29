#pragma once

#include <stdlib.h>
#include <stdbool.h>

typedef size_t stash_snapshot_t;

void stash_init();

void *stash_alloc(size_t size, bool aligned);

stash_snapshot_t stash_snapshot();

void stash_restore(stash_snapshot_t snapshot);
