// Real A64 C ABI callee for the execution-frame emulator. No kernel helpers.
__attribute__((noinline)) unsigned long long maplesu_frame_callee(unsigned long long value) {
    __asm__ volatile(
        "mov x0, #0\nmov x1, #1\nmov x2, #2\nmov x3, #3\n"
        "mov x4, #4\nmov x5, #5\nmov x6, #6\nmov x7, #7\n"
        "mov x8, #8\nmov x9, #9\nmov x10, #10\nmov x11, #11\n"
        "mov x12, #12\nmov x13, #13\nmov x14, #14\nmov x15, #15\n"
        "mov x16, #16\nmov x17, #17\nmov x19, #19\nmov x20, #20\n"
        "mov x21, #21\nmov x22, #22\nmov x23, #23\nmov x24, #24\n"
        "mov x25, #25\nmov x26, #26\nmov x27, #27\nmov x28, #28\n"
        ::: "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8",
            "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17",
            "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28");
    return value;
}
