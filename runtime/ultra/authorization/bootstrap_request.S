// In-place replacement for the pinned helper's send_kernel_request at 0xc4598.
// The 48-byte key and 18+18-byte request ABI are unchanged. No heap allocation
// means no shifted C++ exception landing pads. Saved registers follow the
// existing FDE; the builder updates its initial CFA offset for this 176-byte
// frame. This is a selective patch of the existing helper.
.text
.global maplesu_bootstrap_request
.macro helper_call target
 bl \target
.endm
maplesu_bootstrap_request:
 sub sp, sp, #176
 stp x29, x30, [sp, #128]
 stp x22, x21, [sp, #144]
 stp x20, x19, [sp, #160]
 add x29, sp, #128
 mov x19, x5
 mov w20, w0
 // A zero page count makes set_memory_x a no-op, then BLR would enter NX memory.
 cmp w0, #51
 b.ne 10f
 cbz x2, 9f
 cbz w3, 9f
 cbz w4, 9f
10:
 strb w0, [sp, #96]
 strb w1, [sp, #97]
 stur x2, [sp, #98]
 stur w3, [sp, #106]
 stur w4, [sp, #110]
 // ADR x8, 0x11fa88 (same key storage as the original helper).
 adr x8, ROOT_KEY
 ldrb w9, [x8, #48]
 cbnz w9, 7f
 ldrb w9, [x8, #47]
 cbz w9, 7f
 ldp q0, q1, [x8]
 ldr q2, [x8, #32]
 stp q0, q1, [sp]
 str q2, [sp, #32]
 mov x8, #0
 add x9, sp, #96
 add x10, sp, #48
 add x11, sp, #66
1:
 ldrb w12, [x9, x8]
 // Identical additive encoding for all 256 byte values, within the pinned slot.
 cmp w12, #1
 cset w13, eq
 add w13, w13, #1
 sub w12, w12, w13
 strb w13, [x10, x8]
 strb w12, [x11, x8]
 add x8, x8, #1
 cmp x8, #18
 b.ne 1b
 strb wzr, [sp, #84]
 mov w0, #221
 mov x1, sp
 mov x2, xzr
 mov x3, xzr
 helper_call SYSCALL
 cbz x19, 5f
 helper_call GET_SUID
 mov w21, w0
 helper_call GET_SGID
 orr x21, x21, x0, lsl #32
 str x21, [x19]
 cmp w20, #51
 b.ne 5f
 mov x8, #-19999
 // getresgid maps INVALID_GID (-1) to Android's overflowgid (65534).
 // Match both complete replies; a matching low word alone is insufficient.
 cmp w21, w8
 b.ne 5f
 cmn w0, #1
 b.eq 8f
 mov w9, #65534
 cmp w0, w9
 b.ne 5f
8:
 mov x0, x8
 b 6f
7:
 mov x0, #-19997
 b 6f
9:
 mov x0, #-19999
 b 6f
5:
 mov x0, xzr
6:
 ldp x20, x19, [sp, #160]
 ldp x22, x21, [sp, #144]
 ldp x29, x30, [sp, #128]
 add sp, sp, #176
 ret

// The original executor's copy-failure branch is redirected here. X21 holds
// its error; SP+8 holds the staging allocation. Return through its own epilogue.
.org 304
.global maplesu_bootstrap_copy_failed
maplesu_bootstrap_copy_failed:
 ldr x2, [sp, #8]
 mov w0, #53
 mov w1, wzr
 mov w3, wzr
 mov w4, wzr
 mov x5, xzr
 bl maplesu_bootstrap_request
 b EXECUTOR_RETURN
