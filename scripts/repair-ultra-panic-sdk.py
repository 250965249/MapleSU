"""Repair request/executor members and selectively patch the pinned helper.

Input is the output of repair-ultra-su-authorization.py. Embedded helper provenance
is recorded separately: the helper is patched, not rebuilt from complete inputs.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import struct
import io

from elftools.elf.elffile import ELFFile

from verify_sdk_member_diff import parse_ar

SEND = "_ZN13kernel_moduleL19send_kernel_requestENS_13KernelCmdFlagEhmjjPm"
EXEC = "_ZN13kernel_moduleL22__exec_kernel_asm_funcEPKhjRm"

def replace_once(text, old, new):
    assert text.count(old) == 1, old[:80]
    return text.replace(old, new, 1)

def patch_request(ir):
    ir = replace_once(ir, "  store i64 %60, ptr %5, align 8, !tbaa !31\n", """  store i64 %60, ptr %5, align 8, !tbaa !31
  %maplesu.exec = icmp eq i8 %0, 51
  %maplesu.failed = icmp eq i64 %60, -19999
  %maplesu.error = and i1 %maplesu.exec, %maplesu.failed
  %maplesu.status = select i1 %maplesu.error, i64 -19999, i64 0
""")
    ir = replace_once(ir, "63:                                               ; preds = %56, %50\n",
        "63:                                               ; preds = %56, %50\n"
        "  %maplesu.reply = phi i64 [ %maplesu.status, %56 ], [ 0, %50 ]\n")
    ir = replace_once(ir, "%65 = phi i64 [ 0, %63 ]", "%65 = phi i64 [ %maplesu.reply, %63 ]")
    # Old optimizer range excluded -19999. Retaining it would invalidate the new
    # error path, including in inlined send callers.
    ir = ir.replace(", !range !22", "")
    at = ir.index("\nattributes #0")
    ir = ir[:at] + f"""
define hidden i64 @maplesu_release_staging(i64 %address) {{
  %result = call fastcc i64 @{SEND}(i8 53, i8 0, i64 %address, i32 0, i32 0, ptr null)
  ret i64 %result
}}
""" + ir[at:]
    return ir

def patch_executor(ir):
    start = ir.index("define internal fastcc noundef i64 @" + EXEC)
    end = ir.index("\n}\n", start) + 3
    body = ir[start:end]
    body = replace_once(body, "br i1 %12, label %13, label %27", "br i1 %12, label %13, label %maplesu.copy_failed")
    body = replace_once(body, "27:                                               ; preds = %26, %9, %3\n", """maplesu.copy_failed:
  %maplesu.discard = call i64 @maplesu_release_staging(i64 %10)
  br label %27

27:                                               ; preds = %26, %maplesu.copy_failed, %3
""")
    body = replace_once(body, "[ %11, %9 ]", "[ %11, %maplesu.copy_failed ]")
    ir = ir[:start] + body + ir[end:]
    at = ir.index("\nattributes #0")
    return ir[:at] + "\ndeclare i64 @maplesu_release_staging(i64)\n" + ir[at:]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--ndk", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    tool = args.ndk / "toolchains/llvm/prebuilt/windows-x86_64/bin"
    def run(name, *argv):
        subprocess.run([str(tool / (name + ".exe")), *map(str, argv)], check=True)
    before = parse_ar(str(args.archive))
    data = args.archive.read_bytes()
    expected = {23: "module_base_kernel_request.o", 25: "module_base_kernel_func_executor.o"}
    rebuilt = []
    for ordinal, patch in [(23, patch_request), (25, patch_executor)]:
        member = before["members"][ordinal]
        assert member["name"] == expected[ordinal]
        source = args.out / ("m%03d.original.bc" % ordinal)
        source.write_bytes(data[member["body_offset"]:member["body_offset"] + member["size"]])
        assert source.read_bytes().startswith(b"BC\xc0\xde")
        original = source.with_suffix(".ll")
        run("clang", "--target=aarch64-linux-android21", "-S", "-emit-llvm", "-x", "ir", source, "-o", original)
        patched = args.out / ("m%03d.patched.ll" % ordinal)
        patched.write_text(patch(original.read_text()))
        obj = args.out / member["name"]
        run("clang", "--target=aarch64-linux-android21", "-Oz", "-fPIC", "-c", patched, "-o", obj)
        rebuilt.append(obj)
    # Freeze the exact stripped helper and patch only two verified instruction
    # ranges. Its TU/link inputs are absent; do not describe this as a full rebuild.
    member = before["members"][52]
    assert member["name"] == "maplesu_autorun_bootstrap_install.o", member["name"]
    source = args.out / "m052.original.bc"
    source.write_bytes(data[member["body_offset"]:member["body_offset"] + member["size"]])
    original = source.with_suffix(".ll")
    run("clang", "--target=aarch64-linux-android21", "-S", "-emit-llvm", "-x", "ir", source, "-o", original)
    ir = original.read_text()
    match = re.search(r'\[145416 x i64\] \[(.*?)\]', ir)
    assert match
    values = [int(x) for x in re.findall(r'i64 (-?\d+)', match[1])]
    helper = bytearray(struct.pack('<' + 'Q' * len(values), *(x & ((1 << 64)-1) for x in values)))
    assert hashlib.sha256(helper).hexdigest() == 'b26264e370a55eccd23c8f268384626bb0da61713d746736acef15d4fd4820ef'
    root = Path(__file__).resolve().parents[1]
    obj, elf, binary = [args.out / ('bootstrap-request.' + suffix) for suffix in ('o', 'elf', 'bin')]
    run('clang', '--target=aarch64-linux-android21', '-c', root / 'runtime/ultra/authorization/bootstrap_request.S', '-o', obj)
    run('ld.lld', '-Ttext=0xc4598', '--defsym=ROOT_KEY=0x11fa88', '--defsym=SYSCALL=0x112fc0',
        '--defsym=GET_SUID=0xc4560', '--defsym=GET_SGID=0xc457c', '--defsym=EXECUTOR_RETURN=0xc5e60',
        '--entry=maplesu_bootstrap_request', obj, '-o', elf)
    run('llvm-objcopy', '-O', 'binary', '--only-section=.text', elf, binary)
    replacement = binary.read_bytes()
    assert len(replacement) == 336
    helper[0xc4598:0xc46f4] = replacement + bytes.fromhex('1f2003d5') * ((348-len(replacement))//4)
    assert helper[0xc5e24:0xc5e28] == struct.pack('<I', 0xb50001e0)
    delta = 0xc46c8 - 0xc5e24
    helper[0xc5e24:0xc5e28] = struct.pack('<I', 0xb5000000 | (((delta//4) & 0x7ffff) << 5))
    # Change the build-id to identify the derived binary; retain note layout.
    parsed = ELFFile(io.BytesIO(helper))
    note = parsed.get_section_by_name('.note.gnu.build-id')
    assert note is not None
    build_id_at = note['sh_offset'] + 16
    helper[build_id_at:build_id_at+20] = bytes(20)
    normalized = bytearray(helper)
    normalized[182886:182886+4096] = bytes(4096)
    build_id = hashlib.sha1(normalized).digest()
    helper[build_id_at:build_id_at+20] = build_id
    normalized[build_id_at:build_id_at+20] = build_id
    (args.out / 'embedded-bootstrap.elf').write_bytes(helper)
    words = struct.unpack('<' + 'q' * 145416, helper)
    patched_ir = ir[:match.start(1)] + ', '.join('i64 ' + str(x) for x in words) + ir[match.end(1):]
    patched = args.out / 'm052.patched.ll'
    patched.write_text(patched_ir)
    obj = args.out / member['name']
    run('clang', '--target=aarch64-linux-android21', '-Oz', '-fPIC', '-c', patched, '-o', obj)
    rebuilt.append(obj)
    archive = args.out / "libkernel_module_kit_static.a"
    assert archive.resolve() != args.archive.resolve()
    archive.write_bytes(data)
    run("llvm-ar", "rD", archive, *rebuilt)
    run("llvm-ar", "sD", archive)
    after = parse_ar(str(archive))
    assert len(before["members"]) == len(after["members"]) == 255
    changes = []
    for old, new in zip(before["members"], after["members"]):
        assert old["name"] == new["name"]
        if old["sha256"] != new["sha256"]:
            changes.append({"ordinal": old["ord"], "name": old["name"], "before": old["sha256"], "after": new["sha256"]})
    assert [x["ordinal"] for x in changes] == [23, 25, 52]
    metadata = {"archiveSha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
        "baselineArchiveSha256": hashlib.sha256(data).hexdigest(), "memberChanges": changes,
        "embeddedBootstrapChanged": True, "helperPatchKind": "selective binary patch; not a full TU rebuild",
        "helperSha256": hashlib.sha256(helper).hexdigest(),
        "helperNormalizedSha256": hashlib.sha256(normalized).hexdigest(),
        "helperBuildId": build_id.hex(), "deviceVerification": "not performed"}
    (args.out / "build.json").write_text(json.dumps(metadata, indent=2) + "\n")
    print(json.dumps(metadata, indent=2))

if __name__ == "__main__":
    main()
