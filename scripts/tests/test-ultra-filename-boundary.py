"""Check filename boundaries in the actual plan-placed AArch64 dispatcher bytes."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from unicorn import (Uc, UcError, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE,
                     UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE)
from unicorn import arm64_const as R

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--replay", type=Path, required=True,
                    help="Directory containing image-*/plan.json and patched.raw")
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
results = []
sources = []


def replay(plan, raw, name, valid, euid):
    base, arena = 0x10000000, 0x60000000
    request, filename, task, cred, target = [arena + i * 0x10000 for i in range(1, 6)]
    records = {r["role"]: r for r in plan["records"]}
    gate = base + records["die+0x0"]["offset"]
    end = base + records["arm64_notify_die+0x0"]["offset"]
    text = name + b"\0"
    terminated_length = text.index(0) + 1
    suid_offset = plan["structOffsets"].get("cred.suid", 16)
    euid_offset = plan["structOffsets"].get("cred.euid", 24)
    machine = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    pages = {page for record in plan["records"]
             for page in range(record["offset"] & ~4095,
                               (record["offset"] + record["length"] + 4095) & ~4095, 4096)}
    for page in sorted(pages):
        machine.mem_map(base + page, 4096)
        machine.mem_write(base + page, raw[page:page+4096])
    for page in (request, filename, task, cred, target, arena + 0x7e000):
        machine.mem_map(page, 4096)
    machine.mem_write(request, b"\x7f" * 4096)
    machine.mem_write(request, text)
    machine.mem_write(filename, struct.pack("<Q", request))
    machine.mem_write(task + plan["structOffsets"]["task_struct.cred"], struct.pack("<Q", cred))
    original_reply = 0xa5a5a5a5a5a5a5a5
    machine.mem_write(cred + suid_offset, struct.pack("<Q", original_reply))
    machine.mem_write(cred + euid_offset, struct.pack("<I", euid))
    machine.reg_write(R.UC_ARM64_REG_X1, filename)
    machine.reg_write(R.UC_ARM64_REG_SP, arena + 0x7f000)
    machine.reg_write(R.UC_ARM64_REG_SP_EL0, task)
    violations, returned = [], []

    def memory(uc, access, address, size, value, _):
        if request <= address < request + 4096 and address + size > request + terminated_length:
            violations.append(dict(offset=address-request, width=size, access=access))
            uc.emu_stop()

    def code(uc, pc, size, _):
        if pc == end:
            returned.append(True)
            uc.emu_stop()

    hooks = [machine.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, memory),
             machine.hook_add(UC_HOOK_CODE, code)]
    error = None
    try:
        machine.emu_start(gate, 0, count=20000)
    except UcError as exc:
        error = str(exc)
    unchanged = bytes(machine.mem_read(request, len(text))) == text
    reply = struct.unpack("<Q", machine.mem_read(cred + suid_offset, 8))[0]
    for hook in hooks:
        machine.hook_del(hook)
    passed = (not violations and error is None and bool(returned)
              and (reply == target if valid else unchanged and reply == original_reply))
    return dict(passed=passed, filenameLength=len(name), terminatedLength=terminated_length-1,
                credSuid=suid_offset, credEuid=euid_offset, euid=euid, valid=valid,
                mappedKernelBytes=len(pages)*4096,
                firstViolation=violations[:1], returned=bool(returned),
                requestUnchanged=unchanged, error=error)


folders = sorted(args.replay.glob("image-*"))
assert folders, "No production replay images were selected"
for folder in folders:
    plan_bytes = (folder / "plan.json").read_bytes()
    plan = json.loads(plan_bytes)
    raw = (folder / "patched.raw").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == plan["patchedSha256"]
    slot = plan["slots"]["credential"]
    at = plan["records"][slot["recordIndex"]]["offset"] + slot["offsetInRecord"]
    key = raw[at:at+48]
    assert len(key) == 48 and hashlib.sha256(key).hexdigest() == plan["credentialSha256"]
    sources.append(dict(image=folder.name, planSha256=hashlib.sha256(plan_bytes).hexdigest(),
                        patchedSha256=plan["patchedSha256"]))
    plain = struct.pack("<BBQII", 52, 0x5a, 0x60050000, 4096, 1)
    masks = bytes(2 if byte == 1 else 1 for byte in plain)
    encoded = bytes(255 if byte in (0, 1) else byte - 1 for byte in plain)
    transport = key + masks + encoded
    names = [("complete", transport, True)]
    names += [(f"terminated-{length}", transport[:length], False) for length in range(84)]
    names += [(f"embedded-nul-{offset}", transport[:offset]+b"\0"+transport[offset+1:], False)
              for offset in range(84)]
    names += [("overlong", transport+b"x", False)]
    names += [("ordinary-"+name.decode(), name, False) for name in
              (b"", b"/system/bin/sh", b"/system/bin/ip", b"/system/bin/app_process64",
               b"/system/bin/su", b"/sbin/magisk", b"/data/adb/magisk/magisk",
               b"/data/adb/magisk/busybox", b"com.topjohnwu.magisk")]
    for case, name, valid in names:
        for euid in (0, 10001):
            row = replay(plan, raw, name, valid, euid)
            results.append(dict(image=folder.name, case=case, **row))

report = dict(passed=all(row["passed"] for row in results), deviceAccess=False,
              coverage="Actual generated dispatcher placements, filename memory boundaries and reply; synthetic task/cred memory",
              sources=sources, results=results)
args.output.parent.mkdir(parents=True, exist_ok=True)
args.output.write_text(json.dumps(report, indent=2)+"\n", encoding="utf-8")
failed = [row for row in results if not row["passed"]]
print(json.dumps(dict(passed=report["passed"], cases=len(results), failed=len(failed), first=failed[:1])))
raise SystemExit(1 if failed else 0)
