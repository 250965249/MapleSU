"""Rebuild an isolated SDK candidate around a verified, paired policy entry.

Only embedded-bootstrap member 52 and module-control identity member 255 may
change. No production files or device state are updated by this script.
"""
import argparse
import copy
from datetime import datetime, timezone
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import subprocess
import sys

from elftools.elf.elffile import ELFFile
from policy_backend_identity import describe_backend
from verify_sdk_member_diff import compare_members, parse_ar

ROOT = Path(__file__).resolve().parents[1]
PRODUCTION = ROOT / "runtime/maplesu-sdk"
sha = lambda data: hashlib.sha256(data).hexdigest()
spec = importlib.util.spec_from_file_location("sdk_upgrade", ROOT / "scripts/repair-ultra-environment-upgrade.py")
upgrade = importlib.util.module_from_spec(spec)
spec.loader.exec_module(upgrade)


def contract(data):
    return sorted((s.name, s["st_info"]["bind"], s["st_info"]["type"],
                   s["st_other"]["visibility"], s["st_shndx"] == "SHN_UNDEF")
                  for s in ELFFile(io.BytesIO(data)).get_section_by_name(".symtab").iter_symbols()
                  if s["st_info"]["bind"] != "STB_LOCAL")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--entry", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--ndk", required=True, type=Path)
    args = parser.parse_args()
    entry_dir, out = args.entry.resolve(), args.out.resolve()
    if not out.is_relative_to(ROOT / "work") or out == ROOT / "work":
        parser.error("SDK candidates must use a dedicated directory below work/")
    entry = json.loads((entry_dir / "build.json").read_text(encoding="utf-8"))
    original_manifest = (PRODUCTION / "SDK-RELEASE.json").read_bytes()
    manifest = json.loads(original_manifest)
    archive = PRODUCTION / "lib/arm64-v8a/libkernel_module_kit_static.a"
    base = archive.read_bytes()
    assert sha(base) == entry["baselineArchiveSha256"] == manifest["archive"]["sha256"]
    assert sha(original_manifest) == entry["baselineSdkManifestSha256"]
    for name, expected in entry["sourceSha256"].items():
        assert sha((ROOT / name).read_bytes()) == expected, "stale entry input: " + name
    assert sha((entry_dir / "environment_backend_identity.h").read_bytes()) == entry["backendIdentityHeaderSha256"]
    helper = (entry_dir / "embedded-bootstrap.elf").read_bytes()
    assert sha(helper) == entry["helperSha256"]
    backend_path = Path(entry["backend"]["path"])
    assert describe_backend(backend_path) == {k: v for k, v in entry["backend"].items() if k != "path"}
    backend = backend_path.read_bytes()
    assert sha(backend) == entry["backend"]["sha256"]
    out.mkdir(parents=True, exist_ok=True)
    tool = args.ndk / "toolchains/llvm/prebuilt/windows-x86_64/bin"
    commands = []

    def run(name, *arguments):
        command = [str(tool / (name + ".exe")), *map(str, arguments)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        commands.append(dict(command=command, exitCode=result.returncode, stderr=result.stderr))
        if result.returncode:
            raise RuntimeError(result.stdout + result.stderr)

    before = parse_ar(str(archive))
    member = before["members"][52]
    original_object = base[member["body_offset"]:member["body_offset"] + member["size"]]
    elf = ELFFile(io.BytesIO(original_object))
    original_helper = elf.get_section_by_name(".data").data()
    assert sha(original_helper) == entry["baselineHelperSha256"]
    slot = manifest["helper"]["keySlotOffset"]
    assert helper[slot:slot + 4096] == original_helper[slot:slot + 4096]
    normalized = bytearray(helper)
    normalized[slot:slot + 4096] = bytes(4096)
    assert sha(normalized) == entry["helperNormalizedSha256"]
    # r13 replaced the old size-immediate layout with atomic publication.
    # Reproduce that installer from its pinned IR before changing its payload.
    frozen = ROOT / "runtime/ultra/upgrade/sdk-m052.bc"
    assert sha(frozen.read_bytes()) == "342b920914ad62f700398482f8bfd403344e54cf36f032a77c51d0c1e306d3c2"
    input_ir = out / "m052.input.ll"
    run("clang", "--target=aarch64-linux-android21", "-S", "-emit-llvm", "-x", "ir", frozen, "-o", input_ir)
    ir = upgrade.patch_stream(input_ir.read_text(), "_ZN7maplesu3sdk32unsafe_install_autorun_bootstrapEv",
                              131, 148, 151, 10, 1215088, 78, 145, 144, (147, 146), "u:object_r:kernel:s0")
    ir = upgrade.keep_bootstrap_until_publish(ir)
    payload = re.compile(r'^(@_ZN7maplesu3sdkL27autorun_bootstrap_file_dataE = internal global )[^\n]+, align 8$', re.M)
    assert len(payload.findall(ir)) == 1

    def installer_ir(blob):
        encoded = "".join("\\%02X" % byte for byte in blob)
        result = payload.sub(lambda m: m[1] + f'[{len(blob)} x i8] c"' + encoded + '", align 8', ir)
        return re.sub(r"\b1215088\b", str(len(blob)), result)

    baseline_ir, baseline_object = out / "m052.baseline.ll", out / "m052.baseline.o"
    baseline_ir.write_text(installer_ir(original_helper))
    run("clang", "--target=aarch64-linux-android21", "-Oz", "-fPIC", "-c", baseline_ir, "-o", baseline_object)
    assert upgrade.object_contract(baseline_object.read_bytes()) == upgrade.object_contract(original_object), "r16 installer code/ABI drift"
    (out / "embedded-bootstrap.elf").write_bytes(helper)
    installer = out / member["name"]
    patched_ir = out / "m052.patched.ll"
    patched_ir.write_text(installer_ir(helper))
    run("clang", "--target=aarch64-linux-android21", "-Oz", "-fPIC", "-c", patched_ir, "-o", installer)
    assert ELFFile(io.BytesIO(installer.read_bytes())).get_section_by_name(".data").data() == helper
    assert upgrade.object_contract(installer.read_bytes())[1] == upgrade.object_contract(original_object)[1]

    # The module switch gate pins the full containing program header. Extending
    # the helper without rebuilding this identity would disable its controls.
    helper_elf = ELFFile(io.BytesIO(helper))
    ph_index, _ = max(((i, s) for i, s in enumerate(helper_elf.iter_segments()) if s["p_type"] == "PT_LOAD"),
                      key=lambda item: item[1]["p_vaddr"])
    ph = helper_elf["e_phoff"] + ph_index * helper_elf["e_phentsize"]
    gate = manifest["moduleControl"]
    gate_at, gate_size, branch_at = gate["gateFileOffset"], gate["gateBytes"], 0xA6D68
    header = (f"#pragma once\n#define MAPLESU_GATE_FILE_OFFSET {gate_at}\n"
              f"#define MAPLESU_GATE_BRANCH_OFFSET {branch_at}\n#define MAPLESU_GATE_PHDR_OFFSET {ph}\n")
    for name, data in [("bytes", helper[gate_at:gate_at + gate_size]),
                       ("branch", helper[branch_at:branch_at + 4]), ("phdr", helper[ph:ph + 56])]:
        header += "static constexpr unsigned char maplesu_gate_" + name + "[] = {" + ",".join(map(str, data)) + "};\n"
    (out / "module_gate_identity.h").write_text(header, encoding="utf-8")
    control = out / before["members"][255]["name"]
    assert control.name == "maplesu_module_control.o"
    run("clang++", "--target=aarch64-linux-android21", "-std=c++17", "-Oz", "-fPIC", "-fexceptions",
        "-ffunction-sections", "-fdata-sections", "-I", PRODUCTION / "include", "-I", out,
        "-c", ROOT / "runtime/ultra/modules/module_control.cpp", "-o", control)
    candidate = out / "lib/arm64-v8a" / archive.name
    candidate.parent.mkdir(parents=True, exist_ok=True)
    candidate.write_bytes(base)
    run("llvm-ar", "rD", candidate, installer, control)
    run("llvm-ar", "sD", candidate)
    after = parse_ar(str(candidate))
    diff = compare_members(before, after)
    assert [r["ord"] for r in diff["changed"]] == [52, 255]
    assert not diff["added"] and not diff["removed"] and not diff["orderErrors"]
    candidate_bytes = candidate.read_bytes()
    for row in diff["changed"]:
        old, new = before["members"][row["ord"]], after["members"][row["ord"]]
        assert contract(base[old["body_offset"]:old["body_offset"] + old["size"]]) == contract(
            candidate_bytes[new["body_offset"]:new["body_offset"] + new["size"]])
    backend_copy = out / "backend" / entry["backend"]["fileName"]
    backend_copy.parent.mkdir(exist_ok=True)
    backend_copy.write_bytes(backend)

    # Keep the complete lineage, including every earlier Panic/auth repair.
    earliest = parse_ar(str(ROOT / "runtime/maplesu-sdk/maintenance/baseline/libkernel_module_kit_static.a"))
    count = earliest["member_count"]
    full = compare_members(earliest, dict(after, members=after["members"][:count], member_count=count))
    full["added"] = [dict(ord=m["ord"], name=m["name"], candidateSha256=m["sha256"]) for m in after["members"][count:]]
    diff_path = out / "SU-AUTH-MEMBER-DIFF.json"
    diff_path.write_text(json.dumps(dict(schemaVersion=1, baselineArchiveSha256=earliest["file_sha256"],
        archiveSha256=sha(candidate_bytes), totalMembers=after["member_count"], **full), indent=2) + "\n", encoding="utf-8")
    release = copy.deepcopy(manifest)
    release.update(appVersion="5.1.2", versionCode=50102)
    release["sdkBuildId"] = manifest["sdkBuildId"] + "-policy-candidate"
    release["generatedUtc"] = datetime.now(timezone.utc).isoformat()
    release["archive"].update(path=candidate.relative_to(ROOT).as_posix(), sha256=sha(candidate_bytes), size=len(candidate_bytes))
    for name in ("helper", "bootstrap"):
        release[name].update(sha256=sha(helper), buildId=entry["helperBuildId"], size=len(helper), changed=True)
    release["helper"]["normalizedSha256"] = entry["helperNormalizedSha256"]
    release["moduleControl"].update(helperSha256=sha(helper), helperNormalizedSha256=entry["helperNormalizedSha256"],
        helperBuildId=entry["helperBuildId"], helperBytes=len(helper), archiveSha256=sha(candidate_bytes))
    for row in diff["changed"]:
        for repair in release["repairs"]:
            if repair["memberOrdinal"] == row["ord"]:
                repair["sha256"] = row["candidateSha256"]
    release["memberDiff"].update(path=diff_path.relative_to(ROOT).as_posix(), sha256=sha(diff_path.read_bytes()),
        changed=len(full["changed"]), added=len(full["added"]), removed=len(full["removed"]))
    release["environmentPolicyBoot"] = dict(status="candidate", backend=dict(entry["backend"], path=backend_copy.relative_to(ROOT).as_posix()),
        entryHelperSha256=entry["helperSha256"], identityMatched=True, complete=False,
        productionPackagingIntegrated=False, deviceAcceptance=False)
    release["statement"] = "Isolated policy startup candidate; all r16 repairs retained. Production delivery and device acceptance pending."
    (out / "SDK-RELEASE.json").write_text(json.dumps(release, indent=2) + "\n", encoding="utf-8")
    subprocess.run([sys.executable, str(ROOT / "scripts/sync-ultra-sdk-identity.py"),
                    "--manifest", str(out / "SDK-RELEASE.json"), "--output", str(out / "SDK-IDENTITY.cmake")], check=True)
    assert archive.read_bytes() == base and (PRODUCTION / "SDK-RELEASE.json").read_bytes() == original_manifest
    record = dict(passed=True, recordedAt=datetime.now(timezone.utc).isoformat(),
        baselineArchiveSha256=sha(base), archiveSha256=sha(candidate_bytes), archiveBytes=len(candidate_bytes),
        helperSha256=sha(helper), backendSha256=sha(backend), memberDiff=diff,
        abiPreserved=True, keySlotPreserved=True, priorRepairsPreserved=True, installerBaselineReproduced=True,
        entryManifestSha256=sha((entry_dir / "build.json").read_bytes()),
        sourceSha256={n: sha((ROOT / n).read_bytes()) for n in
                     ["scripts/build-ultra-policy-sdk.py", "scripts/sync-ultra-sdk-identity.py", "scripts/repair-ultra-environment-upgrade.py",
                      "runtime/ultra/upgrade/sdk-m052.bc", "runtime/ultra/modules/module_control.cpp"]},
        artifactSha256={p.relative_to(out).as_posix(): sha(p.read_bytes()) for p in
                        [candidate, backend_copy, out / "SDK-RELEASE.json", out / "SDK-IDENTITY.cmake", diff_path,
                         out / "module_gate_identity.h"]},
        commands=commands, productionArchiveUnchanged=True, candidateOnly=True,
        deviceAccess=False, kernelHookInstalled=False, complete=False)
    (out / "verification.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in record.items() if k not in ("commands", "memberDiff", "sourceSha256", "artifactSha256")}, indent=2))


if __name__ == "__main__":
    main()
