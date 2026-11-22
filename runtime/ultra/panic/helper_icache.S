.text
.p2align 2
.global maplesu_helper_icache_exit
.type maplesu_helper_icache_exit,%function
maplesu_helper_icache_exit:
    mov x1, x0
    ldr x0, [sp, #0]
    bl maplesu_helper_icache_finish
    b original_icache_return
.size maplesu_helper_icache_exit, .-maplesu_helper_icache_exit

.global maplesu_helper_icache_unwind
.type maplesu_helper_icache_unwind,%function
maplesu_helper_icache_unwind:
    ldr x0, [sp, #0]
    mov x1, #0
    bl maplesu_helper_icache_finish
    mov x0, x19
    b original_icache_resume_call
.size maplesu_helper_icache_unwind, .-maplesu_helper_icache_unwind

.global maplesu_helper_icache_next_exit
.type maplesu_helper_icache_next_exit,%function
maplesu_helper_icache_next_exit:
    cmp x0, #1
    csel x0, xzr, x0, eq
    b maplesu_helper_icache_exit
.size maplesu_helper_icache_next_exit, .-maplesu_helper_icache_next_exit
