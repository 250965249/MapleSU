"""Build an offline r14/r15/r16 bootstrap candidate with a synchronous policy barrier.

This never replaces the production SDK archive or installs anything on a device.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import struct
import subprocess

from elftools.elf.elffile import ELFFile
from verify_sdk_member_diff import parse_ar
from policy_backend_identity import describe_backend, write_identity

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--out", required=True, type=Path)
parser.add_argument("--ndk", required=True, type=Path)
parser.add_argument("--backend", required=True, type=Path,
                    help="Already linked boot backend; pins this helper to its immutable file identity")
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
sdk = root / "runtime/maplesu-sdk"
archive = sdk / "lib/arm64-v8a/libkernel_module_kit_static.a"
manifest_bytes = (sdk / "SDK-RELEASE.json").read_bytes()
manifest = json.loads(manifest_bytes)
out = args.out.resolve()
out.mkdir(parents=True, exist_ok=True)
sha = lambda data: hashlib.sha256(data).hexdigest()
base = archive.read_bytes()
verified_archives = {
    "c4795e8a3d221017119cda62baa6a19050eee86710a13bcf8970ab0e34df220d",  # r14
    "e82179f4bc7ed5474a7d4e46169ae28cbb1a089a094a67f14abd49dec0efe4e4",  # r15
    "ccface9bbfbb162bb615ff20213b63eda213a0e0d9b758dcc3f77f3dd2bc4679",  # r16; helper unchanged from r15
}
assert sha(base) == manifest["archive"]["sha256"] and sha(base) in verified_archives
member = parse_ar(str(archive))["members"][52]
obj = ELFFile(io.BytesIO(base[member["body_offset"]:member["body_offset"] + member["size"]]))
original = obj.get_section_by_name(".data").data()
assert sha(original) == manifest["helper"]["sha256"]
helper = bytearray(original)
elf = ELFFile(io.BytesIO(original))
loads = [(i, s) for i, s in enumerate(elf.iter_segments()) if s["p_type"] == "PT_LOAD"]
index, tail = max(loads, key=lambda row: row[1]["p_vaddr"])
assert tail["p_flags"] == 5
va = (tail["p_vaddr"] + max(tail["p_memsz"], len(original) - tail["p_offset"]) + 15) & ~15

def file_offset(address):
    for _, segment in loads:
        if segment["p_vaddr"] <= address < segment["p_vaddr"] + segment["p_filesz"]:
            return segment["p_offset"] + address - segment["p_vaddr"]
    raise AssertionError("unmapped address")

def branch(site, entry, link=True):
    delta = entry - site
    assert delta % 4 == 0 and -(1 << 27) <= delta < (1 << 27)
    return struct.pack("<I", (0x94000000 if link else 0x14000000) | ((delta // 4) & 0x3ffffff))

prior = manifest["environmentIdentity"]
identity_site = prior["hookSite"]
identity_at = file_offset(identity_site)
assert original[identity_at:identity_at + 4] == branch(identity_site, prior["hookEntry"])
# Retain the Identity thunk and launcher. Guard its final module-loader tail.
identity_tails = [address for address in range(prior["hookEntry"], prior["launcher"], 4)
                  if original[file_offset(address):file_offset(address) + 4] ==
                  branch(address, prior["originalModuleLoader"], False)]
assert len(identity_tails) == 1
identity_tail = identity_tails[0]
assert identity_tail + 4 == prior["launcher"]
identity_tail_at = file_offset(identity_tail)
# Add a zero-initialized word after the existing non-RELRO writable segment.
# Existing globals and file-backed bytes retain their addresses and contents.
rw_index, rw = max((row for row in loads if row[1]["p_flags"] == 6),
                   key=lambda row: row[1]["p_vaddr"])
ready_slot = (rw["p_vaddr"] + rw["p_memsz"] + 3) & ~3
assert all(not (s["p_vaddr"] <= ready_slot < s["p_vaddr"] + s["p_memsz"])
           for _, s in loads)
assert ready_slot + 4 <= tail["p_vaddr"]
for pages in (4096, 16384, 65536):
    assert ((ready_slot + 4 + pages - 1) // pages ==
            (rw["p_vaddr"] + rw["p_memsz"] + pages - 1) // pages), "readiness word added a mapped page"
relro = next(s for s in elf.iter_segments() if s["p_type"] == "PT_GNU_RELRO")
assert ready_slot >= relro["p_vaddr"] + relro["p_memsz"]
# The fixed SDK main calls native SELinux setup before the Identity/custom
# dispatcher. Capture the baseline there, preserving its existing error branch.
site, native_selinux = 0xA96C0, 0xFDF74
at = file_offset(site)
assert original[at - 8:at] == bytes.fromhex("e05f40b9e103142a")
assert original[at:at + 4] == branch(site, native_selinux)
assert original[at + 4:at + 24] == bytes.fromhex("f30300aac04200f9e08303914af9ff9733f7ffb5")
slot = manifest["helper"]["keySlotOffset"]
key_va = next(s["p_vaddr"] + slot - s["p_offset"] for _, s in loads
              if s["p_offset"] <= slot < s["p_offset"] + s["p_filesz"])
tool = args.ndk / "toolchains/llvm/prebuilt/windows-x86_64/bin"
commands = []
backend_path = args.backend.resolve()
backend_identity = describe_backend(backend_path)
identity_header = out / "environment_backend_identity.h"
write_identity(identity_header, backend_identity)

def run(name, *command):
    argv = [str(tool / (name + ".exe")), *map(str, command)]
    result = subprocess.run(argv, capture_output=True, text=True, timeout=60)
    commands.append(dict(command=argv, exitCode=result.returncode, stderr=result.stderr))
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)

sources = ["runtime/ultra/policy/environment_loader.c", "runtime/ultra/policy/environment_entry.S"]
common = ["--target=aarch64-linux-android21", "-Oz", "-ffreestanding", "-fno-builtin", "-fPIC",
          "-fno-stack-protector", "-fno-unwind-tables", "-fno-asynchronous-unwind-tables",
          "-Wall", "-Wextra", "-Werror", "-I", out, "-c"]
for source in sources:
    run("clang", *common, root / source, "-o", out / (Path(source).name + ".o"))
(out / "entry.ld").write_text(f"SECTIONS {{ . = {hex(va)}; .extension : {{ *(.text*) *(.rodata*) }} "
                             "/DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) } }")
dyn = elf.get_section_by_name(".dynsym")
plt = elf.get_section_by_name(".plt")["sh_addr"]
defs = {dyn.get_symbol(r["r_info_sym"]).name: plt + 32 + 16 * i
        for i, r in enumerate(elf.get_section_by_name(".rela.plt").iter_relocations())}
defs.update(original_selinux_initializer=native_selinux,
            original_module_loader=prior["originalModuleLoader"], original_root_key=key_va,
            policy_ready_slot=ready_slot)
run("ld.lld", "-T", out / "entry.ld", "--entry=maplesu_environment_policy_entry",
    *[f"--defsym={name}={hex(value)}" for name, value in defs.items()],
    *[out / (Path(source).name + ".o") for source in sources], "-o", out / "entry.elf")
linked = ELFFile(io.BytesIO((out / "entry.elf").read_bytes()))
assert not [s for s in linked.iter_sections() if s["sh_type"] in ("SHT_REL", "SHT_RELA") and s["sh_size"]]
symbols = {s.name: s["st_value"] for s in linked.get_section_by_name(".symtab").iter_symbols()}
code = linked.get_section_by_name(".extension").data()
file_at = tail["p_offset"] + va - tail["p_vaddr"]
assert file_at >= len(helper)
helper.extend(bytes(file_at - len(helper)))
helper.extend(code)
helper.extend(bytes((-len(helper)) % 8))
entry = symbols["maplesu_environment_policy_entry"]
helper[at:at + 4] = branch(site, entry)
module_entry = symbols["maplesu_environment_policy_module_entry"]
helper[identity_tail_at:identity_tail_at + 4] = branch(identity_tail, module_entry, False)
ph = elf["e_phoff"] + index * elf["e_phentsize"]
length = len(helper) - tail["p_offset"]
struct.pack_into("<QQ", helper, ph + 32, length, length)
rw_ph = elf["e_phoff"] + rw_index * elf["e_phentsize"]
struct.pack_into("<Q", helper, rw_ph + 40, ready_slot + 4 - rw["p_vaddr"])
note = elf.get_section_by_name(".note.gnu.build-id")["sh_offset"] + 16
helper[note:note + 20] = bytes(20)
normalized = bytearray(helper)
normalized[slot:slot + 4096] = bytes(4096)
build_id = hashlib.sha1(normalized).digest()
helper[note:note + 20] = normalized[note:note + 20] = build_id
allowed = [(at, at + 4), (identity_tail_at, identity_tail_at + 4),
           (ph + 32, ph + 48), (rw_ph + 40, rw_ph + 48), (note, note + 20)]
assert all(x == y or any(start <= i < end for start, end in allowed)
           for i, (x, y) in enumerate(zip(original, helper)))
assert helper[slot:slot + 4096] == original[slot:slot + 4096]
assert helper[identity_at:identity_at + 4] == original[identity_at:identity_at + 4]
assert archive.read_bytes() == base
assert (sdk / "SDK-RELEASE.json").read_bytes() == manifest_bytes
assert sha(backend_path.read_bytes()) == backend_identity["sha256"]
(out / "embedded-bootstrap.elf").write_bytes(helper)
record = dict(baselineArchiveSha256=sha(base), baselineHelperSha256=sha(original),
              baselineSdkBuildId=manifest["sdkBuildId"], baselineSdkManifestSha256=sha(manifest_bytes),
              helperSha256=sha(helper), helperNormalizedSha256=sha(normalized), helperBuildId=build_id.hex(),
              helperBytes=len(helper), hookSite=site, hookEntry=entry,
              policyLauncher=symbols["maplesu_environment_policy_load"], keyAddress=key_va,
              originalSelinuxInitializer=native_selinux, identityHookSite=identity_site,
              identityCallUnchanged=True,
              identityModuleTail=identity_tail, moduleGuardEntry=module_entry, readySlot=ready_slot,
              originalIdentityEntry=prior["hookEntry"], originalIdentityLauncher=prior["launcher"],
              originalModuleLoader=prior["originalModuleLoader"], extensionBytes=len(code),
              backend=dict(path=str(backend_path), **backend_identity),
              backendIdentityHeaderSha256=sha(identity_header.read_bytes()),
              sourceSha256={name: sha((root / name).read_bytes()) for name in
                            sources + ["scripts/policy_backend_identity.py", "scripts/build-ultra-policy-entry.py"]},
              commands=commands,
              productionArchiveUnchanged=True, deviceAccess=False,
              limitation="Candidate only. Kernel backend/hiding and deployment acceptance remain pending.")
(out / "build.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
print(json.dumps({key: value for key, value in record.items() if key not in ("sourceSha256", "commands")}, indent=2))
