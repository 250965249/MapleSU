.text
.global maplesu_bootstrap_finish_entry
.type maplesu_bootstrap_finish_entry,%function
maplesu_bootstrap_finish_entry:
    // main: x19 owns the initialization result; sp+8 owns the safe-flag string.
    mov x1, x19
    add x0, sp, #8
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    ldrb w8, [x0]
    ldr x9, [x0, #16]
    add x0, x0, #1
    tst w8, #1
    csel x0, x0, x9, eq
    bl maplesu_bootstrap_finish
    ldp x29, x30, [sp], #16
    cbnz w0, original_bootstrap_exit
    // Replay the instruction replaced by the branch into this adapter.
    add x8, sp, #0x110
    b original_bootstrap_finish_continue
.size maplesu_bootstrap_finish_entry, .-maplesu_bootstrap_finish_entry
