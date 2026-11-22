#!/usr/bin/env python3
"""Run one real target Kbuild; preserve compiler/modpost failure verbatim.

--native-only builds the two independent native components. A module build
requires the completed provider Kbuild in --module-source; this tool does not
invent its entry, export bindings, service factory or credential implementation.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess


TARGET_PROFILE_SOURCES = ("fs/exec.c", "fs/stat.c", "fs/open.c",
                          "arch/arm64/include/asm/syscall_wrapper.h",
                          "arch/arm64/include/asm/ptrace.h", "include/linux/binfmts.h")


def identity(path):
    data = path.read_bytes()
    return {"path": str(path.resolve()), "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest()}


def staged_target_inputs(source, kdir, repo, kernel_source=None, target_contract=None):
    profile = source / "host/manager_su_runtime_target_profile.h"
    if not profile.is_file():
        return []
    receipt_path = source / "SOURCE-SELECTION.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    binding = receipt.get("targetBinding")
    if not binding:
        raise ValueError("ULTRA_BRIDGE_TARGET_PROFILE_SOURCE_CONTRACT_REQUIRED")
    if binding.get("kind") == "maplesu-init-bridge-kmi-target/1":
        spec = importlib.util.spec_from_file_location("bridge_target_kmi", Path(__file__).with_name("target_kmi.py"))
        kmi = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(kmi)
        reference = binding["contract"]
        contract_path = target_contract if target_contract is not None else (
            repo / reference["repositoryPath"] if "repositoryPath" in reference else Path(reference["path"]))
        if any(identity(contract_path)[key] != reference[key] for key in ("bytes", "sha256")):
            raise ValueError("ULTRA_BRIDGE_KMI_CONTRACT_IDENTITY")
        contract = kmi.read_contract(contract_path, kdir)
        if any(binding.get("kmiProfile", binding["profile"])[key] != contract["profile"][key]
               for key in ("bytes", "sha256")):
            raise ValueError("ULTRA_BRIDGE_TARGET_PROFILE_IDENTITY")
        selected_inputs = []
        if receipt.get("runtimeLayoutSelected"):
            layout_ref = binding.get("runtimeLayoutProfile")
            if not layout_ref or layout_ref not in receipt.get("formalRuntimeSuccessors", []):
                raise ValueError("ULTRA_BRIDGE_RUNTIME_PROFILE_SELECTION_REQUIRED")
            layout_path = (repo / layout_ref["repositoryPath"] if "repositoryPath" in layout_ref
                           else Path(layout_ref["path"]))
            if any(identity(layout_path)[key] != layout_ref[key] for key in ("bytes", "sha256")):
                raise ValueError("ULTRA_BRIDGE_RUNTIME_PROFILE_SELECTION_IDENTITY")
            layout = json.loads(layout_path.read_text(encoding="utf-8-sig"))
            if layout.get("schema") != "maplesu-claim-runtime-layout-source-selection/1":
                raise ValueError("ULTRA_BRIDGE_RUNTIME_PROFILE_SELECTION_SCHEMA")
            selected_profiles = [row for row in layout.get("files", []) if row.get("logicalPath") ==
                                 "runtime/ultra/identity/kernel/manager_su_runtime_target_profile.h"]
            staged_profiles = [row for row in receipt.get("inputs", [])
                               if row.get("repositoryPath") ==
                               "runtime/ultra/identity/kernel/manager_su_runtime_target_profile.h" and
                               row.get("staged") == "host/manager_su_runtime_target_profile.h"]
            actual_profile = identity(profile)
            if (len(selected_profiles) != 1 or len(staged_profiles) != 1 or
                    staged_profiles[0].get("selection") != "runtime-layout-source-successor" or any(
                    actual_profile[key] != selected_profiles[0]["after"][key] or
                    binding["profile"][key] != selected_profiles[0]["after"][key] or
                    staged_profiles[0]["selected"][key] != selected_profiles[0]["after"][key]
                    for key in ("bytes", "sha256"))):
                raise ValueError("ULTRA_BRIDGE_RUNTIME_TARGET_PROFILE_IDENTITY")
            selected_inputs.append(layout_path)
        elif any(identity(profile)[key] != contract["profile"][key] or
                 binding["profile"][key] != contract["profile"][key]
               for key in ("bytes", "sha256")):
            raise ValueError("ULTRA_BRIDGE_TARGET_PROFILE_IDENTITY")
        for field, expected in (("targetConfig", contract["inputs"]["targetConfig"]),
                                ("buildConfig", contract["inputs"]["buildConfig"])):
            if any(binding[field][key] != expected[key] for key in ("bytes", "sha256")):
                raise ValueError("ULTRA_BRIDGE_KMI_CONFIG_BINDING:" + field)
        return [receipt_path, contract_path, profile, *selected_inputs, Path(__file__).with_name("target_kmi.py"),
                *[kmi.reference_path(row) for row in contract["inputs"].values()],
                kmi.reference_path(contract["targetSymvers"], contract_path.resolve().parent)]
    if kernel_source is None:
        raise ValueError("ULTRA_BRIDGE_TARGET_PROFILE_SOURCE_ROOT_REQUIRED")
    reference = binding["ownerSelection"]
    owner_path = repo / reference["repositoryPath"] if "repositoryPath" in reference else Path(reference["path"])
    if any(identity(owner_path)[key] != reference[key] for key in ("bytes", "sha256")):
        raise ValueError("ULTRA_BRIDGE_TARGET_PROFILE_OWNER_IDENTITY")
    owner = json.loads(owner_path.read_text(encoding="utf-8"))
    if binding["kernelProfile"] != owner["kernelProfile"]:
        raise ValueError("ULTRA_BRIDGE_TARGET_PROFILE_GENERATION")
    expected_profile = [row["after"] for row in owner["kernelFiles"]
                        if row["logicalPath"] == "runtime/ultra/identity/kernel/manager_su_runtime_target_profile.h"]
    if len(expected_profile) != 1 or any(identity(profile)[key] != expected_profile[0][key] or
                                       binding["profile"][key] != expected_profile[0][key]
                                       for key in ("bytes", "sha256")):
        raise ValueError("ULTRA_BRIDGE_TARGET_PROFILE_IDENTITY")
    if any(identity(kdir / ".config")[key] != owner["targetConfig"][key] or
           binding["targetConfig"][key] != owner["targetConfig"][key] for key in ("bytes", "sha256")):
        raise ValueError("ULTRA_BRIDGE_TARGET_PROFILE_CONFIG_MISMATCH")
    source_files = binding["sourceFiles"]
    if sorted(row["repositoryPath"] for row in source_files) != sorted(TARGET_PROFILE_SOURCES):
        raise ValueError("ULTRA_BRIDGE_TARGET_PROFILE_SOURCE_CONTRACT")
    actual_sources = []
    for row in source_files:
        declared = [item for item in owner["targetSourceFiles"]
                    if item["path"].replace("\\", "/").endswith("/" + row["repositoryPath"])]
        if len(declared) != 1 or any(row["actual"][key] != declared[0][key] or
                                   row["declared"][key] != declared[0][key] for key in ("bytes", "sha256")):
            raise ValueError("ULTRA_BRIDGE_TARGET_PROFILE_SOURCE_MISMATCH:" + row["repositoryPath"])
        path = kernel_source / row["repositoryPath"]
        actual = identity(path)
        if any(actual[key] != declared[0][key] for key in ("bytes", "sha256")):
            raise ValueError("ULTRA_BRIDGE_TARGET_PROFILE_SOURCE_MISMATCH:" + row["repositoryPath"])
        actual_sources.append(path)
    return [receipt_path, owner_path, profile, *actual_sources]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("repo-root", "kernel-build", "llvm-bin", "module-source", "evidence"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--source", type=Path, action="append", required=True)
    parser.add_argument("--kernel-source", type=Path)
    parser.add_argument("--target-contract", type=Path)
    parser.add_argument("--modpost", type=Path)
    parser.add_argument("--native-only", action="store_true")
    parser.add_argument("--object", action="append", default=[])
    args = parser.parse_args()
    kdir, source = args.kernel_build.resolve(), args.module_source.resolve()
    if any(not re.fullmatch(r"(?:host/|producer/module/)?[a-zA-Z0-9_]+\.o", name) for name in args.object):
        raise ValueError("ULTRA_BRIDGE_OBJECT_TARGET")
    component_only = args.native_only or bool(args.object)
    targets = args.object or (["native_layout.o", "native_lookup.o"] if args.native_only else ["modules"])
    outputs = [source / name for name in (targets if component_only else ["maplesu_ultra_bridge.ko"])]
    if any(path.exists() for path in outputs):
        raise ValueError("ULTRA_BRIDGE_OUTPUT_EXISTS: use an independent source-only build directory")
    kbuild = source / "Kbuild"
    selected = [kbuild, kdir / ".config", kdir / "include/generated/utsrelease.h",
                *[path.resolve() for path in args.source]]
    selected.extend(staged_target_inputs(source, kdir, args.repo_root.resolve(),
                                         args.kernel_source.resolve() if args.kernel_source else None,
                                         args.target_contract.resolve() if args.target_contract else None))
    vmlinux = kdir / "vmlinux"
    vmlinux_present = vmlinux.is_file()
    if not component_only:
        # Modpost needs the real exports. Bare modules can skip BTF without
        # vmlinux; a successful link still supplies no target/BTF qualification.
        selected.append(kdir / "Module.symvers")
        if vmlinux_present:
            selected.append(vmlinux)
        if not re.search(r"^obj-m\s*(?::=|\+=|=).*\bmaplesu_ultra_bridge\.o\b",
                         kbuild.read_text(), re.M):
            raise ValueError("ULTRA_BRIDGE_MODULE_PROVIDER_REQUIRED: see bridge-provider-gap.md")
    before = [identity(path) for path in dict.fromkeys(selected)]
    tool = args.llvm_bin.resolve()
    tools = [identity(tool / name) for name in ("clang", "ld.lld", "llvm-nm")]
    if args.modpost:
        tools.append(identity(args.modpost.resolve()))
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=False)
    command = ["make", "-C", str(kdir), "M=" + str(source), "ARCH=arm64",
               "LLVM=" + str(tool) + "/", "MAPLESU_REPO_ROOT=" + str(args.repo_root.resolve()),
               "V=1"]
    if args.modpost:
        command.extend(["MODPOST=" + str(args.modpost.resolve()), "KBUILD_MODPOST_WARN="])
    command.extend(targets)
    with (evidence / "stdout.log").open("wb") as stdout, (evidence / "stderr.log").open("wb") as stderr:
        result = subprocess.run(command, stdout=stdout, stderr=stderr, check=False)
    after = [identity(Path(row["path"])) for row in before]
    tools_after = [identity(Path(row["path"])) for row in tools]
    receipt = {"command": command, "exitCode": result.returncode, "sources": before,
               "tools": tools, "inputsUnchanged": before == after and tools == tools_after and
               (component_only or vmlinux.is_file() == vmlinux_present),
               "nativeComponentsOnly": component_only, "targetQualified": False,
               "targetVmlinuxCaptured": not component_only and vmlinux_present,
               "targetBtfQualified": False,
               "deviceOperations": False, "sdkOrSuQualified": False}
    if result.returncode == 0 and all(path.is_file() for path in outputs):
        receipt["artifacts"] = [identity(path) for path in outputs]
    (evidence / "BUILD.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    if result.returncode:
        raise SystemExit(result.returncode)
    if not receipt["inputsUnchanged"]:
        raise ValueError("ULTRA_BRIDGE_BUILD_INPUT_CHANGED")
    if "artifacts" not in receipt:
        raise ValueError("ULTRA_BRIDGE_KBUILD_OUTPUT_MISSING")


if __name__ == "__main__":
    main()
