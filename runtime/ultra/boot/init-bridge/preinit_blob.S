/* SPDX-License-Identifier: GPL-2.0-only */
.section .init.rodata, "a"
.balign 16
.global msu_preinit_runner_start
msu_preinit_runner_start:
.incbin MSU_PREINIT_RUNNER_BIN
.global msu_preinit_runner_end
msu_preinit_runner_end:
