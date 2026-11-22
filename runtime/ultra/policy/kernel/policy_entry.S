/* SPDX-License-Identifier: GPL-3.0-only */
/* No stack frame: preserve the caller's LR and the kernel's x18/SCS state. */
.text
.macro POLICY_ENTRY name
    .p2align 2
    .global \name
    .hidden \name\()_impl
    .type \name, %function
\name:
    .inst 0xd503245f /* BTI C; remains intact during native dynamic-SCS patching */
    b \name\()_impl
    .size \name, .-\name
.endm

POLICY_ENTRY maplesu_policy_view_prepare
POLICY_ENTRY maplesu_policy_view_handles
POLICY_ENTRY maplesu_policy_view_context
POLICY_ENTRY maplesu_policy_view_access
POLICY_ENTRY maplesu_policy_view_setprocattr
POLICY_ENTRY maplesu_policy_view_status_open
POLICY_ENTRY maplesu_policy_view_status_read
POLICY_ENTRY maplesu_policy_view_status_mmap
POLICY_ENTRY maplesu_policy_view_filter
POLICY_ENTRY maplesu_policy_view_creds_changed
POLICY_ENTRY maplesu_policy_view_receive
POLICY_ENTRY maplesu_policy_view_transition
POLICY_ENTRY maplesu_policy_view_fork_guard
POLICY_ENTRY maplesu_policy_view_module_write
POLICY_ENTRY maplesu_policy_view_policyload
POLICY_ENTRY maplesu_policy_view_reload

.section .note.gnu.property, "a", %note
.p2align 3
.long 4, 16, 5
.asciz "GNU"
.long 0xc0000000, 4, 1, 0
