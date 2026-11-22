.text
.global maplesu_module_gate
.type maplesu_module_gate,%function
maplesu_module_gate:
    stp x29,x30,[sp,#-80]!
    stp x19,x20,[sp,#16]
    mov x19,x0
    add x0,x0,#1,lsl #12
    add x0,x0,#3072
    add x8,sp,#32
    bl module_private_path
    ldrb w9,[sp,#32]
    add x0,sp,#33
    tbz w9,#0,1f
    ldr x0,[sp,#48]
1:  bl maplesu_skip_disabled
    mov w20,w0
    ldrb w9,[sp,#32]
    tbz w9,#0,2f
    ldr x0,[sp,#48]
    bl helper_delete
2:  mov x0,x19
    mov w9,w20
    ldp x19,x20,[sp,#16]
    ldp x29,x30,[sp],#80
    cbnz w9,3f
    sub sp,sp,#0x40 // displaced first instruction of original version precheck
    b original_precheck_body
3:  mov x0,#-20150
    ret
.size maplesu_module_gate,.-maplesu_module_gate
