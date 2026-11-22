/* SPDX-License-Identifier: GPL-3.0-only */
.text
.p2align 2
.global msu_policy_call_original
.type msu_policy_call_original, %function
msu_policy_call_original:
    .inst 0xd503245f /* BTI C */
    paciasp
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    mov x16, x0
    mov x17, x1
    ldp x0, x1, [x17]
    ldp x2, x3, [x17, #16]
    ldp x4, x5, [x17, #32]
    blr x16
.global msu_policy_original_return
msu_policy_original_return:
    ldp x29, x30, [sp], #16
    autiasp
    ret
.size msu_policy_call_original, .-msu_policy_call_original
.section .note.GNU-stack,"",%progbits
