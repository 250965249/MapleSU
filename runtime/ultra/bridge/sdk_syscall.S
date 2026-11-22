.text
.global __wrap_syscall
.hidden __wrap_syscall
.type __wrap_syscall, %function
__wrap_syscall:
    // SDK execve packets can live in a tagged Android heap. The kernel's
    // nofault reader needs the user address without its top-byte tag.
    cmp x0, #221
    b.ne 1f
    tbnz x1, #55, 1f
    and x1, x1, #0x00ffffffffffffff
1:
    b __real_syscall
.size __wrap_syscall, .-__wrap_syscall
.section .note.GNU-stack,"",%progbits
