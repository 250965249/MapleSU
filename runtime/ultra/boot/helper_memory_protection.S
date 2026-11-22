.text
.p2align 2
.global maplesu_helper_memory_protection_identify
.hidden maplesu_helper_memory_protection_identify
.type maplesu_helper_memory_protection_identify,%function
maplesu_helper_memory_protection_identify:
    mov x20, x0
    ldr x9, [x0, #32]
    mov x10, #0
    cbz x9, 2f
    ldr x9, [x9]
    adr x11, original_text_vtable
    cmp x9, x11
    b.eq 1f
    adr x11, original_ro_vtable
    cmp x9, x11
    b.eq 1f
    adr x11, original_rw_vtable
    cmp x9, x11
    b.eq 1f
    adr x11, original_x_vtable
    cmp x9, x11
    b.ne 2f
1:  mov x10, #1
2:  str x10, [sp, #24]
    b original_noresult_init_call
.size maplesu_helper_memory_protection_identify, .-maplesu_helper_memory_protection_identify
