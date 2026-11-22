.section .text.entry,"ax"
.global vr_entry, vr_displaced, vr_continue, vr_return, vr_hdr, vr_len, vr_compressed
.global vr_release, vr_release_hdr, vr_vfree, vr_decompress
vr_entry:
    stp x29, x30, [sp, #-64]!
    stp x0, x1, [sp, #16]
    str x2, [sp, #32]
    mov w1, w2
vr_hdr:
    mov w2, #16
vr_len:
    mov w3, #24
vr_compressed:
    mov w4, #0
    bl vr_filter
    cbnz w0, 1f
    ldp x0, x1, [sp, #16]
    ldr x2, [sp, #32]
    ldp x29, x30, [sp], #64
vr_displaced:
    nop
vr_continue:
    b .
1:
    ldp x29, x30, [sp], #64
    mov w0, #0
vr_return:
    b .
vr_release:
    tbnz w1, #2, vr_decompress
vr_release_hdr:
    ldr x0, [x0, #16]
vr_vfree:
    b .
vr_decompress:
    b .
