"""Replay the SDK's real SELinux-to-custom-module startup branch offline."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import random
import struct

from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn import arm64_const as reg

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--build", required=True, type=Path)
parser.add_argument("--output", required=True, type=Path)
args = parser.parse_args()
meta = json.loads((args.build / "build.json").read_text())
blob = (args.build / "embedded-bootstrap.elf").read_bytes()
assert hashlib.sha256(blob).hexdigest() == meta["helperSha256"]
elf = ELFFile(io.BytesIO(blob))
# These sites belong to the verified r14/r15 main, not a modeled startup order.
selinux_site, selinux_function = 0xA96C0, 0xFDF74
custom_site, failure_target = 0xA974C, 0xA95B8
main_end = custom_site + 4


def word(address):
    for segment in elf.iter_segments():
        if (segment["p_type"] == "PT_LOAD" and
                segment["p_vaddr"] <= address < segment["p_vaddr"] + segment["p_filesz"]):
            return struct.unpack_from("<I", segment.data(), address - segment["p_vaddr"])[0]
    raise AssertionError("unmapped startup instruction")


def call_target(site):
    instruction = word(site)
    assert instruction >> 26 == 0b100101
    delta = instruction & 0x3ffffff
    if delta & 0x2000000:
        delta -= 0x4000000
    return site + delta * 4


assert call_target(custom_site) in (meta["originalIdentityEntry"], meta["hookEntry"])
# C bodies are fixtures; the real MOV/STR/CBNZ and both SDK thunks execute.
stubs = {call_target(site) for site in
         (0xA96D0, 0xA96F8, 0xA9714, 0xA9724, 0xA9730, 0xA973C, 0xA9748)}
cases, failure = [], None
for base in (0, 0x10000, 0x70000000):
    for policy_result in (0, 1, 2, 3, 4, 5, 6, -1):
        for native_result in (0, -1, -19936):
            for seed in range(8):
                rnd = random.Random(seed)
                u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
                u.mem_map(base, 0x140000)
                for segment in elf.iter_segments():
                    if segment["p_type"] == "PT_LOAD":
                        u.mem_write(base + segment["p_vaddr"], segment.data())
                stack = 0x4000000
                u.mem_map(stack, 0x10000)
                sp = stack + 0x8000
                u.reg_write(reg.UC_ARM64_REG_SP, sp)
                registers = [rnd.getrandbits(64) for _ in range(30)]
                registers[22] = stack + 0x1000
                vectors = [rnd.getrandbits(128) for _ in range(32)]
                for i, value in enumerate(registers):
                    u.reg_write(getattr(reg, f"UC_ARM64_REG_X{i}"), value)
                for i, value in enumerate(vectors):
                    u.reg_write(getattr(reg, f"UC_ARM64_REG_Q{i}"), value)
                calls = []

                def return_from_c(value):
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
                        assert not calls, "policy preparation must precede the SDK SELinux initializer"
                        assert uc.reg_read(reg.UC_ARM64_REG_X0) == base + meta["keyAddress"]
                        calls.append("policy")
                        return_from_c(policy_result)
                    elif at == selinux_function:
                        assert calls == ["policy"], "SDK SELinux initializer ran before policy preparation"
                        assert [uc.reg_read(getattr(reg, f"UC_ARM64_REG_X{i}")) for i in range(9)] == registers[:9]
                        assert [uc.reg_read(getattr(reg, f"UC_ARM64_REG_Q{i}")) for i in range(8)] == vectors[:8]
                        assert uc.reg_read(reg.UC_ARM64_REG_SP) == sp
                        assert uc.reg_read(reg.UC_ARM64_REG_X30) == base + selinux_site + 4
                        calls.append("sdk-selinux")
                        return_from_c(native_result)
                    elif at == meta["originalIdentityLauncher"]:
                        calls.append("identity")
                        return_from_c(seed % 5)
                    elif at == meta["originalModuleLoader"]:
                        assert policy_result == 0 and native_result == 0
                        calls.append("custom-modules")
                        assert uc.reg_read(reg.UC_ARM64_REG_SP) == sp
                        assert uc.reg_read(reg.UC_ARM64_REG_X30) == base + main_end
                        return_from_c(0x1234)
                    elif at in stubs:
                        return_from_c(0)
                    elif at in (failure_target, main_end):
                        uc.emu_stop()

                u.hook_add(UC_HOOK_CODE, hook)
                try:
                    u.emu_start(base + selinux_site, base + 0x140000, count=500)
                    assert "sdk-selinux" in calls, "policy preparation failure suppressed the SDK native SELinux initializer"
                    expected = (["policy", "sdk-selinux"] if native_result else
                                ["policy", "sdk-selinux", "identity"] if policy_result else
                                ["policy", "sdk-selinux", "identity", "custom-modules"])
                    assert calls == expected, (calls, expected)
                    stop = failure_target if native_result else main_end
                    assert u.reg_read(reg.UC_ARM64_REG_PC) == base + stop
                    assert u.reg_read(reg.UC_ARM64_REG_SP) == sp
                    assert [u.reg_read(getattr(reg, f"UC_ARM64_REG_X{i}")) for i in range(20, 30)] == registers[20:30]
                    result = native_result
                    assert u.reg_read(reg.UC_ARM64_REG_X19) == result & ((1 << 64) - 1)
                    assert bytes(u.mem_read(registers[22] + 0x80, 8)) == struct.pack("<Q", result & ((1 << 64) - 1))
                except AssertionError as error:
                    failure = dict(base=base, policyResult=policy_result, nativeResult=native_result,
                                   seed=seed, calls=calls, error=str(error))
                    break
                cases.append(dict(base=base, policyResult=policy_result, nativeResult=native_result, seed=seed))
            if failure:
                break
        if failure:
            break
    if failure:
        break

record = dict(passed=failure is None, helperSha256=meta["helperSha256"],
              sourceSha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              cases=cases, failure=failure,
              checked=["policy before native SELinux initializer", "single preparation",
                       "preparation failure holds custom modules and preserves native SDK initialization",
                       "real SDK conditional error branch and stored return code", "SP/LR/ASLR"],
              scope="Actual reviewed SDK startup instructions and candidate thunks; C bodies and kernel are fixtures",
              deviceAccess=False, kernelHookInstalled=False)
args.output.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
if failure:
    raise SystemExit("FAIL " + failure["error"])
print(f"PASS {len(cases)} ARM64 startup-order cases")
