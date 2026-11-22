.section .extension,"ax",@progbits
.p2align 2
.global range_ro, range_rw, range_x
range_ro:
    mov x17, #0
    b range_common
range_rw:
    mov x17, #1
    b range_common
range_x:
    mov x17, #2
range_common:
    // Reuse the original caller frame and get_page_size unwind location.
    mov w9, w0
    cmp x9, #1, lsl #12
    b.eq range_page_valid
    cmp x9, #4, lsl #12
    b.eq range_page_valid
    cmp x9, #16, lsl #12
    b.ne range_invalid
range_page_valid:
    cbz x19, range_invalid
    sub x11, x19, #1
    adds x11, x20, x11
    b.cs range_invalid
    sub x11, x9, #1
    and x12, x20, x11
    udiv x8, x19, x9
    msub x13, x8, x9, x19
    add x12, x12, x13
    udiv x13, x12, x9
    msub x14, x13, x9, x12
    add x8, x8, x13
    cmp x14, #0
    cinc x8, x8, ne
    mov w14, #0x7fffffff
    cmp x8, x14
    b.hi range_invalid
    bic x20, x20, x11
    mul x12, x8, x9
    adds x12, x20, x12
    b.cs range_invalid
    mov x10, sp
    cbz x17, range_ro_continue
    cmp x17, #1
    b.eq range_rw_continue
    b original_x_continue
range_ro_continue:
    b original_ro_continue
range_rw_continue:
    b original_rw_continue
range_invalid:
    cbz x17, range_ro_invalid
    b original_main_invalid
range_ro_invalid:
    b original_ro_invalid
