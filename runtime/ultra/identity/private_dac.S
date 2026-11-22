.text
.p2align 2
.global maplesu_private_directory_gate
.type maplesu_private_directory_gate,%function
maplesu_private_directory_gate:
    cmp x21, #32
    mov w1, #0700
    mov w9, #0711
    csel w1, w9, w1, eq
    b original_directory_resume
.size maplesu_private_directory_gate, .-maplesu_private_directory_gate

.p2align 2
.global maplesu_private_allowlist_create_gate
.type maplesu_private_allowlist_create_gate,%function
maplesu_private_allowlist_create_gate:
    mov x0, x21
    bl maplesu_private_allowlist_create
    mov w21, w0
    b original_allowlist_return
.size maplesu_private_allowlist_create_gate, .-maplesu_private_allowlist_create_gate
