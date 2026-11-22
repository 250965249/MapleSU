"""Replay the reference kernel's actual dynamic-SCS patcher against our PIC image.

Only libc string functions are fixtures. The opcode walker, jump table and patch stores
are the unmodified reference-vmlinux instructions; hardware cache/BTI/PAC
enforcement and live kernel installation are not exercised.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import random

from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn import arm64_const as R

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("directory", type=Path)
args = parser.parse_args()
directory = args.directory
metadata = json.loads((directory / "target-identity.json").read_text())
native = metadata["nativeScsReplay"]
frames = json.loads((directory / "scs-replay.json").read_text())
before = (directory / "scs-replay-before.bin").read_bytes()
expected = (directory / "scs-replay-expected.bin").read_bytes()
text = (directory / "native-scs.bin").read_bytes()
assert hashlib.sha256(text).hexdigest() == native["sha256"]
with (directory / "policy-view.so").open("rb") as f:
    elf = ELFFile(f)
    entries = {s.name: s["st_value"] for s in elf.get_section_by_name(".dynsym").iter_symbols()
               if s.name.startswith("maplesu_policy_view_")}

report = dict(generatedAt=datetime.now(timezone.utc).isoformat(), passed=False, cases=0,
              kernelBuildId=metadata["buildId"], nativeTextSha256=native["sha256"],
              payloadSha256=hashlib.sha256((directory / "policy-view.so").read_bytes()).hexdigest(),
              beforeSha256=hashlib.sha256(before).hexdigest(), expectedSha256=hashlib.sha256(expected).hexdigest(),
              patchSites=frames["patchSites"], scope=__doc__, deviceAccess=False, liveKernelExecution=False)
try:
    for base in (0x10000000, 0xffff800040000000, 0xffff800090000000):
        for seed in range(8):
            rng = random.Random(seed)
            u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
            mapped = set()

            def write(at, data):
                for page in range(at & ~4095, (at + len(data) + 4095) & ~4095, 4096):
                    if page not in mapped:
                        u.mem_map(page, 4096)
                        mapped.add(page)
                u.mem_write(at, data)

            write(native["base"], text)
            for item in native["rodata"] + native.get("extraText", []):
                data = (directory / item["file"]).read_bytes()
                assert hashlib.sha256(data).hexdigest() == item["sha256"]
                write(item["base"], data)
            write(native["strlen"], bytes(4))
            if "strcmp" in native:
                write(native["strcmp"], bytes(4))
            write(base, before)
            stack, stop = 0x4000000, 0x5000000
            write(stack, bytes(65536))
            write(stop, bytes(4))
            regs = [rng.getrandbits(64) for _ in range(31)]
            for i, value in enumerate(regs):
                u.reg_write(getattr(R, f"UC_ARM64_REG_X{i}"), value)
            u.reg_write(R.UC_ARM64_REG_X0, base + frames["frameOffset"])
            u.reg_write(R.UC_ARM64_REG_X1, frames["frameBytes"])
            if metadata["scsArguments"] == 3:
                # Native module_finalize skips dry run for a rejectable image.
                u.reg_write(R.UC_ARM64_REG_X2, 1)
            u.reg_write(R.UC_ARM64_REG_X30, stop)
            sp = stack + 32768
            u.reg_write(R.UC_ARM64_REG_SP, sp)
            stores = []

            def tick(uc, pc, size, unused):
                if pc == stop:
                    u.emu_stop()
                elif pc == native["strlen"]:
                    at = u.reg_read(R.UC_ARM64_REG_X0)
                    length = 0
                    while bytes(u.mem_read(at + length, 1)) != b"\0":
                        length += 1
                        assert length < 128
                    u.reg_write(R.UC_ARM64_REG_X0, length)
                    u.reg_write(R.UC_ARM64_REG_PC, u.reg_read(R.UC_ARM64_REG_X30))
                elif pc == native.get("strcmp"):
                    left, right = u.reg_read(R.UC_ARM64_REG_X0), u.reg_read(R.UC_ARM64_REG_X1)
                    for i in range(128):
                        a, b = bytes(u.mem_read(left + i, 1))[0], bytes(u.mem_read(right + i, 1))[0]
                        if a != b or not a:
                            u.reg_write(R.UC_ARM64_REG_X0, (a - b) & ((1 << 64) - 1))
                            u.reg_write(R.UC_ARM64_REG_PC, u.reg_read(R.UC_ARM64_REG_X30))
                            break
                    else:
                        raise AssertionError("unterminated fixture string")

            def store(uc, access, address, size, value, unused):
                if stack <= address and address + size <= stack + 65536:
                    return
                assert base <= address and address + size <= base + len(before)
                assert size == 4
                stores.append(address - base)

            u.hook_add(UC_HOOK_CODE, tick)
            u.hook_add(UC_HOOK_MEM_WRITE, store)
            try:
                u.emu_start(native["entry"], stop + 4, count=100000)
            except Exception:
                report["errorContext"] = dict(pc=hex(u.reg_read(R.UC_ARM64_REG_PC)),
                    lr=hex(u.reg_read(R.UC_ARM64_REG_X30)), base=hex(base), seed=seed)
                raise
            assert u.reg_read(R.UC_ARM64_REG_PC) == stop
            assert u.reg_read(R.UC_ARM64_REG_X0) == 0
            assert bytes(u.mem_read(base, len(before))) == expected
            assert len(stores) == len(set(stores)) == frames["patchSites"]
            for name, offset in entries.items():
                assert bytes(u.mem_read(base + offset, 4)) == bytes.fromhex("5f2403d5"), name
            assert u.reg_read(R.UC_ARM64_REG_SP) == sp
            assert [u.reg_read(getattr(R, f"UC_ARM64_REG_X{i}")) for i in range(18, 30)] == regs[18:30]
            report["cases"] += 1
    report["passed"] = True
finally:
    report["sourceSha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    (directory / "native-scs-verification.json").write_text(json.dumps(report, indent=2) + "\n")
print("PASS", report["cases"], "native kernel SCS replays;", frames["patchSites"], "patch sites, independent BTI entries intact")
