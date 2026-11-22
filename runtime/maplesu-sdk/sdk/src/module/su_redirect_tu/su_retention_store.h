#pragma once
#include "module_err_def.h"
#include <cstdint>

// Persist the charged boot budget before any kernel allocation or publication.
KModErr maplesu_store_su_retention(const void* ledger, uint64_t size);
