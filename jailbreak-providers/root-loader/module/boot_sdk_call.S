/* SPDX-License-Identifier: GPL-3.0-only */
.text
.p2align 2
#ifdef MSU_BOOT_SDK_NATIVE
#include "native_cfi.h"
#if MSU_INIT_BRIDGE_CFI_LEGACY
#include "boot_sdk_layout.h"
/* The kernel module loader owns this whole non-init section, its symbols and
 * relocations. Metadata keeps the original one-page BLR displacement. */
.pushsection .text.msu_sdk_legacy_carrier,"ax",%progbits
.balign MSU_BS_PAGE_BYTES
#endif
#endif
/* Position independent template copied into the arena adjacent to metadata.
 * x11 points to the decoded legacy packet; x17 is the private cred saved-ID
 * area. JIT frame_start loads x10/w12/w13 from x11 and retains the BLR's LR. */
.global msu_sdk_call_template, msu_sdk_call_blr, msu_sdk_call_template_end
.type msu_sdk_call_template, %function
#ifdef MSU_BOOT_SDK_NATIVE
.global msu_sdk_call_prefix
msu_sdk_call_prefix:
#if MSU_INIT_BRIDGE_CFI_KCFI
    .4byte __kcfi_typeid_msu_sdk_call_template
#endif
#endif
msu_sdk_call_template:
    .inst 0xd503245f /* BTI C */
    paciasp
    stp x29, x30, [sp, #-32]!
    mov x29, sp
    str x18, [sp, #16]
    mov x10, x0
    mov x11, x1
    mov x17, x2
msu_sdk_call_blr:
    blr x10
    ldr x18, [sp, #16]
    ldp x29, x30, [sp], #32
    autiasp
    ret
msu_sdk_call_template_end:
.size msu_sdk_call_template, .-msu_sdk_call_template

/* Copied lookup veneer: its literal is bound before the page becomes RX. */
#if defined(MSU_BOOT_SDK_NATIVE) && MSU_INIT_BRIDGE_CFI_LEGACY
.p2align 4
#endif
.global msu_sdk_lookup_template, msu_sdk_lookup_target, msu_sdk_lookup_end
.type msu_sdk_lookup_template, %function
msu_sdk_lookup_template:
    .inst 0xd503245f
    paciasp
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    ldr x16, msu_sdk_lookup_target
    blr x16
    ldp x29, x30, [sp], #16
    autiasp
    ret
.p2align 3
msu_sdk_lookup_target:
    .quad 0
msu_sdk_lookup_end:
.size msu_sdk_lookup_template, .-msu_sdk_lookup_template

/* A real B-imm26 return site for the pinned SymPack decoder. The SDK hooks
 * msu_sdk_avc_result; the native AVC bridge passes its actual w0 through it. */
#if defined(MSU_BOOT_SDK_NATIVE) && MSU_INIT_BRIDGE_CFI_LEGACY
.p2align 4
#else
.p2align 2
#endif
.global msu_sdk_avc_template, msu_sdk_avc_branch, msu_sdk_avc_result, msu_sdk_avc_end
.type msu_sdk_avc_template, %function
msu_sdk_avc_template:
    .inst 0xd503245f
msu_sdk_avc_branch:
    b msu_sdk_avc_result
.p2align 4
msu_sdk_avc_result:
    .inst 0xd50324df /* BTI JC */
    nop
    nop
    nop
    ret
msu_sdk_avc_end:
.size msu_sdk_avc_template, .-msu_sdk_avc_template
#if defined(MSU_BOOT_SDK_NATIVE) && MSU_INIT_BRIDGE_CFI_LEGACY
/* .org fails at assembly if the code exceeds its actual target page. */
.org msu_sdk_call_prefix + MSU_BS_PAGE_BYTES, 0
.global msu_sdk_legacy_metadata, msu_sdk_legacy_carrier_end
msu_sdk_legacy_metadata:
.zero MSU_BS_PAGE_BYTES
#if MSU_BS_ENVIRONMENT
.zero 64 * MSU_BS_PAGE_BYTES
#endif
msu_sdk_legacy_carrier_end:
.popsection
#endif

/* Entered at native avc_denied's untouched entry frame. All eight arguments
 * go to the original, with one exact LR sentinel preventing redirection. */
.p2align 2
.global msu_sdk_avc_bridge, msu_sdk_avc_original_return
.type msu_sdk_avc_bridge, %function
msu_sdk_avc_bridge:
    .inst 0xd503245f
    paciasp
    stp x29, x30, [sp, #-32]!
    mov x29, sp
    stp x18, x19, [sp, #16]
    /* The pre-handler supplies targets in scratch x16/x17, preserving x0..x7. */
    mov x19, x17
    blr x16
msu_sdk_avc_original_return:
    mov x16, x19
    blr x16
    ldp x18, x19, [sp, #16]
    ldp x29, x30, [sp], #32
    autiasp
    ret
.size msu_sdk_avc_bridge, .-msu_sdk_avc_bridge

/* Recursion sentinel for the native execve passthrough. */
.global msu_sdk_call_original, msu_sdk_original_return
.type msu_sdk_call_original, %function
msu_sdk_call_original:
    .inst 0xd503245f
    paciasp
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    mov x16, x0
    mov x0, x1
    blr x16
msu_sdk_original_return:
    ldp x29, x30, [sp], #16
    autiasp
    ret
.size msu_sdk_call_original, .-msu_sdk_call_original
.section .note.GNU-stack,"",%progbits
