"""Replay the early ARM64 policy barrier without altering native initialization."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import random

from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn import arm64_const as reg

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--build", required=True, type=Path)
args = parser.parse_args()
meta = json.loads((args.build / "build.json").read_text())
blob = (args.build / "embedded-bootstrap.elf").read_bytes()
assert hashlib.sha256(blob).hexdigest() == meta["helperSha256"]
elf = ELFFile(io.BytesIO(blob))
cases = []
for base in (0, 0x10000, 0x70000000):
    for policy_result in (0, 1, 2, 3, 4, 5, 6, -1):
        for seed in range(8):
            rnd = random.Random(seed)
            u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
            u.mem_map(base, 0x140000)
            for s in elf.iter_segments():
                if s["p_type"] == "PT_LOAD":
                    u.mem_write(base + s["p_vaddr"], s.data())
            assert bytes(u.mem_read(base + meta["readySlot"], 4)) == bytes(4)
            stack = 0x4000000
            u.mem_map(stack, 0x10000)
            sp = stack + 0x8000
            u.reg_write(reg.UC_ARM64_REG_SP, sp)
            registers = [rnd.getrandbits(64) for _ in range(30)]
            vectors = [rnd.getrandbits(128) for _ in range(32)]
            for i, value in enumerate(registers):
                u.reg_write(getattr(reg, f"UC_ARM64_REG_X{i}"), value)
            for i, value in enumerate(vectors):
                u.reg_write(getattr(reg, f"UC_ARM64_REG_Q{i}"), value)
            calls = []

            def clobber_return(value):
                link = u.reg_read(reg.UC_ARM64_REG_X30)
                for i in range(18):
                    u.reg_write(getattr(reg, f"UC_ARM64_REG_X{i}"), 0xbad000 + i)
                for i in range(8):
                    u.reg_write(getattr(reg, f"UC_ARM64_REG_Q{i}"), 0xbad)
                u.reg_write(reg.UC_ARM64_REG_X0, value & ((1 << 64) - 1))
                u.reg_write(reg.UC_ARM64_REG_PC, link)

            def hook(uc, address, size, unused):
                at = address - base
                if at == meta["policyLauncher"]:
                    assert uc.reg_read(reg.UC_ARM64_REG_X0) == base + meta["keyAddress"]
                    calls.append("policy")
                    clobber_return(policy_result)
                elif at == meta["originalIdentityLauncher"]:
                    calls.append("identity")
                    clobber_return(seed % 5)
                elif at == meta["originalSelinuxInitializer"]:
                    calls.append("selinux")
                    assert [uc.reg_read(getattr(reg, f"UC_ARM64_REG_X{i}")) for i in range(9)] == registers[:9]
                    assert [uc.reg_read(getattr(reg, f"UC_ARM64_REG_Q{i}")) for i in range(8)] == vectors[:8]
                    assert uc.reg_read(reg.UC_ARM64_REG_SP) == sp
                    assert uc.reg_read(reg.UC_ARM64_REG_X30) == base + meta["hookSite"] + 4
                    clobber_return(0x1234)
                elif at == meta["hookSite"] + 4:
                    uc.emu_stop()

            u.hook_add(UC_HOOK_CODE, hook)
            u.emu_start(base + meta["hookSite"], base + 0x140000, count=300)
            assert u.reg_read(reg.UC_ARM64_REG_PC) == base + meta["hookSite"] + 4
            assert calls == ["policy", "selinux"]
            assert u.reg_read(reg.UC_ARM64_REG_SP) == sp
            assert u.reg_read(reg.UC_ARM64_REG_X30) == base + meta["hookSite"] + 4
            assert [u.reg_read(getattr(reg, f"UC_ARM64_REG_X{i}")) for i in range(18, 30)] == registers[18:30]
            assert u.reg_read(reg.UC_ARM64_REG_X0) == 0x1234
            assert bytes(u.mem_read(base + meta["readySlot"], 4)) == (int(policy_result == 0)).to_bytes(4, "little")
            cases.append(dict(base=base, result=policy_result, seed=seed))
record = dict(passed=True, helperSha256=meta["helperSha256"], cases=cases,
              checked=["policy before native SELinux initializer", "native initialization and result preserved on preparation failure",
                       "boot-local readiness word published before module entry",
                       "original argument/vector registers", "SP/LR", "ASLR", "in-process key pointer"],
              scope="Actual candidate ARM64 thunks; C loader, backend, and module body are fixtures",
              deviceAccess=False, kernelHookInstalled=False)
(args.build / "entry-tests.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
print(f"PASS {len(cases)} ARM64 synchronous entry cases")
