"""Check the generated executor's cache-publication contract, without executing it.

This models a caller migrating between cache invalidation and BLR. It is not a
reproduction of a hardware IABT or a device Panic acceptance test.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM


parser = argparse.ArgumentParser()
parser.add_argument("--kernel", type=Path, required=True)
parser.add_argument("--receipt", type=Path, required=True)
parser.add_argument("--out", type=Path, required=True)
args = parser.parse_args()
kernel = args.kernel.read_bytes()
receipt = json.loads(args.receipt.read_text())
assert hashlib.sha256(kernel).hexdigest() == receipt["patchedKernelSha256"]
record = next(r for r in receipt["records"] if r["role"] == "__drm_printfn_coredump+0x0")
code = kernel[record["offset"]:record["offset"] + record["length"]]
instructions = list(Cs(CS_ARCH_ARM64, CS_MODE_ARM).disasm(code, record["offset"]))
calls = [i for i, instruction in enumerate(instructions)
         if instruction.mnemonic == "blr" and instruction.op_str == "x10"]
assert len(calls) == 1
call = calls[0]
publication = instructions[call - 3:call]
observed = [(instruction.mnemonic, instruction.op_str) for instruction in publication]
expected = [("ic", "ialluis"), ("dsb", "ish"), ("isb", "")]
checks = [{"name": "shareable-invalidation-and-barriers", "passed": observed == expected}]

# An IALLU affects the issuing PE; an IALLUIS reaches the inner-shareable PEs.
# A completion barrier and a context synchronization event must precede BLR.
for source in range(4):
    for destination in range(4):
        stale = [True] * 4
        scope = publication[0].op_str
        if publication[0].mnemonic == "ic" and scope in ("iallu", "ialluis"):
            for cpu in range(4) if scope == "ialluis" else [source]:
                stale[cpu] = False
        passed = not stale[destination] and observed[1:] == expected[1:]
        checks.append({"name": f"migration-{source}-to-{destination}", "passed": passed})

result = dict(kernelSha256=hashlib.sha256(kernel).hexdigest(),
              executorOffset=record["offset"], executorBytes=len(code),
              callOffset=instructions[call].address,
              publication=[f"{mnemonic} {operand}".strip() for mnemonic, operand in observed],
              encodedInstruction=struct.unpack_from("<I", code, (call - 3) * 4)[0],
              checks=checks, passed=all(item["passed"] for item in checks),
              hardwareFaultReproduced=False, devicePanicAcceptance=False)
args.out.parent.mkdir(parents=True, exist_ok=True)
args.out.write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps({"passed": result["passed"], "checks": len(checks),
                  "failures": sum(not item["passed"] for item in checks),
                  "publication": result["publication"]}))
raise SystemExit(0 if result["passed"] else 1)
