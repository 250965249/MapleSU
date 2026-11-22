"""Validate segmented allocator selection against a supplied real device BTF."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from policy_btf_abi import Btf

p = argparse.ArgumentParser(description=__doc__)
p.add_argument("--btf", type=Path, required=True)
p.add_argument("--output", type=Path, required=True)
a = p.parse_args()
out = a.output.resolve()
out.mkdir(parents=True, exist_ok=True)
raw = a.btf.read_bytes()
btf = Btf(raw)
inner = "___vmalloc_node_range_noprof"
expected = "f*v(i8:64;i8:64;i4:32;i4:32;i4:32;i4:32;i8:64;i8:64;i4:32;s:8{0=i8:64;};i8:64;i4:16777248;*v;)"
assert btf.function(inner) == expected, "Supply the actual segmented-ABI BTF"
docker = ["docker", "run", "--rm", "--pull", "never", "--network", "none", "--cap-drop", "ALL",
          "--security-opt", "no-new-privileges", "--mount", f"type=bind,source={ROOT},target=/source,readonly",
          "--mount", f"type=bind,source={out},target=/output", "ghcr.io/ylarod/ddk-min:android16-6.12-20260828"]
build = subprocess.run(docker + ["sh", "-c", "c++ -std=c++17 -Wall -Wextra -Werror -fsanitize=address,undefined "
    "-I/source/runtime/ultra/policy /source/runtime/ultra/policy/kernel_layout.cpp "
    "/source/module-policy/src/boot_sdk_layout.cpp /source/runtime/tests/boot_sdk_layout_probe.cpp -o /output/probe"],
    capture_output=True, text=True, timeout=60)
assert build.returncode == 0, build.stderr

def changed_u32(changes):
    changed = bytearray(raw)
    for offset, value in changes:
        struct.pack_into("<I", changed, offset, value)
    return changed

prototypes = {btf.types[index][3] for index in btf.functions[inner]}
scalar = next(i for i, t in enumerate(btf.types[1:], 1) if t[1] == 1 and t[3] == 4)
wide = next(i for i, t in enumerate(btf.types[1:], 1) if t[1] == 1 and t[3] == 8)
stack_members = []
def find_stack_members(t, depth=0):
    assert depth < 8
    for i in range(t[2]):
        pos = t[5] + i * 12
        name = btf.name(btf.u32(pos))
        if name == "sp": stack_members.append(pos)
        elif not name:
            child = btf.types[btf.u32(pos + 4)]
            if child[1] in (4, 5): find_stack_members(child, depth + 1)

for t in btf.types[1:]:
    if t[1] == 4 and btf.name(t[0]) == "pt_regs":
        find_stack_members(t)
assert stack_members
fixtures = [("reference-enabled", raw, True, 13), ("old-resident-capability", raw, False, 5),
    ("missing-inner", changed_u32([(btf.types[i][5]-12, 0) for i in btf.functions[inner]]), True, 5),
    ("wrong-return", changed_u32([(btf.types[i][5]-4, scalar) for i in prototypes]), True, 5),
    ("shifted-sp", changed_u32([(pos+8, 30*64) for pos in stack_members]), True, 5),
    ("narrow-sp", changed_u32([(pos+4, scalar) for pos in stack_members]), True, 5)]
for parameter in (2, 3, 4, 5, 8, 11):
    fixtures.append((f"wrong-parameter-{parameter}",
        changed_u32([(btf.types[i][5]+parameter*8+4, wide) for i in prototypes]), True, 5))
rows = []
for name, data, enabled, allocator in fixtures:
    target = out / "input.btf"
    target.write_bytes(data)
    for page in ((4096, 16384, 65536) if name == "reference-enabled" else (4096,)):
        result = subprocess.run(docker + ["/output/probe", "/output/input.btf", str(page), "1", "1", str(int(enabled))],
                                capture_output=True, text=True, timeout=30)
        passed = result.returncode == 0 and f"allocatorNoprof={allocator}\n" in result.stdout
        rows.append(dict(name=name, page=page, passed=passed, stdout=result.stdout.strip(), stderr=result.stderr.strip()))
    target.unlink()
report = dict(passed=all(row["passed"] for row in rows), btfSha256=hashlib.sha256(raw).hexdigest(), results=rows)
(out / "verification.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
print(json.dumps(dict(passed=report["passed"], cases=len(rows), failed=[row for row in rows if not row["passed"]])))
sys.exit(0 if report["passed"] else 1)
