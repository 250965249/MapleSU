.text
.p2align 2
.global maplesu_helper_hook_args
.type maplesu_helper_hook_args,%function
maplesu_helper_hook_args:
    sub x1, x29, #0x80
    ldur x9, [x29, #-0x18]
    ldur w2, [x9, #-8]
    ldr x3, [sp, #0x88]
    mov x4, x21
    ldr x5, [sp, #0x80]
    mov x6, x19
    mov x0, x20
    b original_hook_publication_call
.size maplesu_helper_hook_args, .-maplesu_helper_hook_args
