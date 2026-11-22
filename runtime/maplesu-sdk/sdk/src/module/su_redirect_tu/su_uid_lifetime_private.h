// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include "module_err_def.h"
#include <cstdint>

// Actual target PREEMPT_RCU entrypoints; no MapleSU Image exports or guessed fields.
KModErr maplesu_su_uid_reader_functions(uint64_t& lock, uint64_t& unlock);
KModErr maplesu_su_uid_reader_reset();
KModErr maplesu_su_uid_reader_activate(uint64_t control);
KModErr maplesu_su_uid_reader_require(uint64_t control);
KModErr maplesu_su_uid_synchronize();
KModErr maplesu_su_uid_index_state(uint64_t control, uint64_t& state);
KModErr maplesu_su_uid_index_prepare(uint64_t table, uint32_t count);
KModErr maplesu_su_uid_index_release(uint64_t table);

// Init-only, single-shot cleanup under SuAuthLock for this call's new control.
// initialized is true only after complete zero-fill; detached is the independent
// publication rollback/drain result, not merely a failed install return code.
KModErr maplesu_su_uid_bootstrap_retire(uint64_t control, bool initialized, bool readers_detached);
