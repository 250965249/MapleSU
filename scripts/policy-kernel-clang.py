"""Forward the arm64 kernel's TPIDRRO_EL0 guard option to Clang cc1.

Some upstream Clang drivers reject this register even though their AArch64
backend implements it. This build-only adapter retains the requested register,
offset and stack protection. Verify the emitted assembly before using a new
compiler; it does not make an incompatible compiler or kernel supported.
Usage: python3 policy-kernel-clang.py /path/to/clang [compiler arguments...]
"""
import os
import sys

if len(sys.argv) < 2:
    raise SystemExit(__doc__)

compiler, *arguments = sys.argv[1:]
forwarded = []
for argument in arguments:
    if argument == "-mstack-protector-guard-reg=tpidrro_el0":
        forwarded.append("-Xclang")
    forwarded.append(argument)
os.execvp(compiler, [compiler, *forwarded])
