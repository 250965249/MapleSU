
.text
.p2align 2
.global maplesu_helper_text_identify
.type maplesu_helper_text_identify,%function
maplesu_helper_text_identify:
    mov x20, x0
    ldr x9, [x0, #32]
    mov x10, #0
    cbz x9, 1f
    ldr x9, [x9]
    adr x11, original_text_vtable
    cmp x9, x11
    cset x10, eq
1:  str x10, [sp, #24]
    b original_noresult_init_call
.size maplesu_helper_text_identify, .-maplesu_helper_text_identify

.global maplesu_helper_text_generated
.type maplesu_helper_text_generated,%function
maplesu_helper_text_generated:
    ldr x9, [sp, #24]
    cmp x0, #0
    csel x20, x9, x0, eq
    ret
.size maplesu_helper_text_generated, .-maplesu_helper_text_generated

.global maplesu_helper_text_epilogue
.type maplesu_helper_text_epilogue,%function
maplesu_helper_text_epilogue:
    cmp x20, #1
    b.ne original_noresult_end
    adr x1, original_x0_operand
    b original_result_end
.size maplesu_helper_text_epilogue, .-maplesu_helper_text_epilogue

.global maplesu_helper_text_checked
.type maplesu_helper_text_checked,%function
maplesu_helper_text_checked:
    cmp x20, #1
    b.ne 2f
    cbnz x0, 2f
    ldr w9, [sp, #24]
    cbz w9, 2f
    mov x0, #-19990
2:  mov x20, x0
    ret
.size maplesu_helper_text_checked, .-maplesu_helper_text_checked
