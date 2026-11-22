"""Build and check the KSU-derived Ultra kernel view without accessing a device."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import uuid

from elftools.elf.elffile import ELFFile
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # shared helpers live in scripts/
from policy_payload_inspect import inspect_payload

ROOT = Path(__file__).resolve().parents[2]
KERNELS = ["android12-5.10", "android13-5.15", "android14-6.1", "android15-6.6", "android16-6.12", "android17-6.18"]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--output", type=Path,
                    default=Path(tempfile.gettempdir()) / "MapleSU-ultra-module-policy-20261107" / "kernel-view")
parser.add_argument("kernels", nargs="*", choices=KERNELS, default=KERNELS)
parser.add_argument("--timeout", type=int, default=180)
parser.add_argument("--save", type=Path,
                    default=ROOT / "work/ultra-module-policy-20261107/kernel-view-verification.json")
parser.add_argument("--source-618", type=Path)
parser.add_argument("--objtree-618", type=Path)
parser.add_argument("--toolchain-618", type=Path, help="Extracted LLVM usr/ directory containing bin/clang-22 and lib/")
parser.add_argument("--cc-618", default="/compiler/bin/clang-22", help="Actual compiler in the container; defaults to the mounted LLVM toolchain")
args = parser.parse_args()
if "android17-6.18" in args.kernels and not (args.source_618 and args.objtree_618 and (args.toolchain_618 or args.cc_618 != "/compiler/bin/clang-22")):
    parser.error("6.18 needs the prepared reference source, object tree and LLVM usr/ paths; see --source-618, --objtree-618, --toolchain-618")
if args.timeout <= 0:
    parser.error("--timeout must be positive")
args.output.mkdir(parents=True, exist_ok=True)

def run(kernel, script):
    name = "maplesu-policy-test-" + kernel + "-" + uuid.uuid4().hex[:8]
    mounts = []
    if kernel == "android17-6.18":
        mounts = ["--mount", f"type=bind,source={args.source_618},target=/kernel,readonly",
                  "--mount", f"type=bind,source={args.objtree_618},target=/kernel-build"]
        if args.toolchain_618:
            mounts += ["--mount", f"type=bind,source={args.toolchain_618},target=/compiler,readonly"]
    image = "android16-6.12" if kernel == "android17-6.18" else kernel
    command = ["docker", "run", "--rm", "--pull", "never", "--network", "none",
               "--name", name, "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--mount",
               f"type=bind,source={ROOT},target=/source,readonly", "--mount",
               f"type=bind,source={args.output},target=/output", *mounts,
               f"ghcr.io/ylarod/ddk-min:{image}-20260828", "sh", "-c", script]
    started = time.monotonic()
    try:
        result = subprocess.run(command, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=args.timeout)
    except subprocess.TimeoutExpired:
        # The docker client exiting does not stop its container. Remove only
        # this invocation's unique container, never another task's build.
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=20)
        return dict(exitCode=124, elapsedSeconds=round(time.monotonic() - started, 3),
                    stdout="", stderr="Policy test exceeded its offline build timeout", command=command)
    return dict(exitCode=result.returncode, elapsedSeconds=round(time.monotonic() - started, 3),
                stdout=result.stdout, stderr=result.stderr, command=command)

inputs = list((ROOT / "runtime/ultra/policy/kernel").glob("*")) + [
    ROOT / "runtime/ultra/policy/policy_layout_slots.h", ROOT / "runtime/ultra/policy/kernel_payload_loader.h",
    ROOT / "runtime/tests/kernel_payload_io_fixture.h", ROOT / "runtime/tests/kernel_dynamic_payload_test.cpp",
    ROOT / "runtime/tests/policy_dynamic_access_fixture.c",
    ROOT / "runtime/tests/policy_context_parse_test.c", ROOT / "runtime/tests/policy_sid_test.c",
    ROOT / "runtime/tests/policy_view_fixture/policy_kernel_fixture.h",
    ROOT / "runtime/tests/policy_view_boot_test.c",
    ROOT / "runtime/tests/policy_status_inheritance_test.c",
    ROOT / "runtime/tests/policy_reload_test.c",
    ROOT / "runtime/tests/policy_view_fixture/policy_boot_fixture.h",
    ROOT / "runtime/ultra/policy/kernel_layout.h", ROOT / "runtime/ultra/policy/kernel_layout.cpp",
    ROOT / "runtime/tests/kernel_layout_test.cpp", ROOT / "runtime/tests/kernel_layout_probe.cpp",
    ROOT / "scripts/build-ultra-policy-layout.py", ROOT / "scripts/policy_payload_inspect.py", ROOT / "scripts/policy_payload_target.py",
    ROOT / "scripts/policy_payload_image_target.py", ROOT / "scripts/policy-kernel-clang.py",
    ROOT / "runtime/ultra/policy/kernel_payload.h", ROOT / "runtime/ultra/policy/kernel_payload.cpp",
    ROOT / "runtime/ultra/policy/kernel_payload_loader.h", ROOT / "runtime/ultra/policy/kernel_payload_loader.cpp",
    ROOT / "runtime/tests/kernel_payload_test.cpp", ROOT / "runtime/tests/kernel_payload_loader_test.cpp",
    ROOT / "runtime/tests/kernel_payload_scs_probe.cpp", ROOT / "scripts/tests/test-ultra-policy-native-scs.py",
    Path(__file__).resolve()]
source_before = {str(p.relative_to(ROOT)).replace("\\", "/"): hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs if p.is_file()}

compile_host = ("cc -std=gnu11 -Wall -Wextra -Werror -fsanitize=address,undefined "
                "-fno-omit-frame-pointer -DMAPLESU_POLICY_VIEW_HOST_TEST "
                "-I/source/runtime/ultra/policy/kernel -I/source/runtime/tests/policy_view_fixture "
                "/source/runtime/ultra/policy/kernel/ksu_context.c ")
commands = [
    compile_host + "/source/runtime/tests/policy_context_parse_test.c -o /output/context-test",
    compile_host + "/source/runtime/ultra/policy/kernel/ksu_sid.c "
                   "/source/runtime/tests/policy_sid_test.c -o /output/sid-test",
    "cc -std=gnu11 -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer "
    "-DMAPLESU_POLICY_BOOT_HOST_TEST -I/source/runtime/ultra/policy/kernel "
    "-I/source/runtime/tests/policy_view_fixture /source/runtime/ultra/policy/kernel/policy_view.c "
    "/source/runtime/ultra/policy/kernel/policy_status.c "
    "/source/runtime/ultra/policy/kernel/policy_notifications.c /source/runtime/ultra/policy/kernel/policy_reload.c "
    "/source/runtime/tests/policy_view_boot_test.c -o /output/boot-test",
    "cc -std=gnu11 -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer "
    "-DMAPLESU_POLICY_BOOT_HOST_TEST -I/source/runtime/ultra/policy/kernel "
    "-I/source/runtime/tests/policy_view_fixture /source/runtime/ultra/policy/kernel/policy_view.c "
    "/source/runtime/ultra/policy/kernel/policy_status.c "
    "/source/runtime/ultra/policy/kernel/policy_notifications.c /source/runtime/ultra/policy/kernel/policy_reload.c "
    "/source/runtime/tests/policy_status_inheritance_test.c -o /output/status-inheritance-test",
    "cc -std=gnu11 -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer "
    "-DMAPLESU_POLICY_BOOT_HOST_TEST -I/source/runtime/ultra/policy/kernel "
    "-I/source/runtime/tests/policy_view_fixture /source/runtime/ultra/policy/kernel/policy_view.c "
    "/source/runtime/ultra/policy/kernel/policy_status.c "
    "/source/runtime/ultra/policy/kernel/policy_notifications.c /source/runtime/ultra/policy/kernel/policy_reload.c "
    "/source/runtime/tests/policy_reload_test.c -o /output/reload-test",
    "c++ -std=c++17 -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer "
    "-I/source/runtime/ultra/policy /source/runtime/ultra/policy/kernel_layout.cpp "
    "/source/runtime/tests/kernel_layout_test.cpp -o /output/layout-test",
    "c++ -std=c++20 -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer "
    "-I/source/runtime/ultra/policy /source/runtime/ultra/policy/kernel_payload.cpp "
    "/source/runtime/tests/kernel_payload_test.cpp -o /output/payload-test",
    "c++ -std=c++20 -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer "
    "-I/source/runtime/ultra/policy /source/runtime/ultra/policy/kernel_payload.cpp "
    "/source/runtime/ultra/policy/kernel_layout.cpp /source/runtime/ultra/policy/kernel_payload_loader.cpp "
    "/source/runtime/tests/kernel_payload_loader_test.cpp -o /output/loader-test",
    "c++ -std=c++20 -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer "
    "-I/source/runtime/ultra/policy /source/runtime/ultra/policy/kernel_payload.cpp "
    "/source/runtime/tests/kernel_payload_scs_probe.cpp -o /output/scs-probe",
    "/output/context-test", "/output/sid-test", "/output/boot-test", "/output/status-inheritance-test", "/output/reload-test", "/output/layout-test",
]
host = run("android15-6.6", " && ".join(commands))

def build(kernel):
    script = (f"mkdir -p /output/{kernel} && "
              f"cp /source/runtime/ultra/policy/kernel/* /source/runtime/ultra/policy/policy_layout_slots.h /output/{kernel}/ && "
              f"make -C /opt/ddk/kdir/{kernel} M=/output/{kernel} LLVM=1 ARCH=arm64 "
              f"MAPLESU_POLICY_PIC=1 -j2 maplesu_policy_view.o && "
              f"make -C /opt/ddk/kdir/{kernel} M=/output/{kernel} LLVM=1 ARCH=arm64 -j2 maplesu_policy_layout.o && "
              f"ld.lld -r -o /output/{kernel}/maplesu_policy_view.payload.o --whole-archive "
              f"/output/{kernel}/maplesu_policy_view.o --no-whole-archive && "
              f"ld.lld -shared --entry=0 --strip-debug -Bsymbolic -z max-page-size=65536 -z force-bti "
              f"-o /output/{kernel}/policy-view.so /output/{kernel}/maplesu_policy_view.payload.o && "
              f"llvm-objcopy --decompress-debug-sections /output/{kernel}/abi_anchors.o /output/{kernel}/abi-layout.o && "
              f"python3 /source/scripts/policy_payload_target.py /opt/ddk/kdir/{kernel} /output/{kernel}/target-identity.json && "
              f"cp /opt/ddk/kdir/{kernel}/System.map /output/{kernel}/System.map && "
              f"cp /opt/ddk/kdir/{kernel}/include/config/auto.conf /output/{kernel}/target.config")
    if kernel == "android17-6.18":
        script = (f"set -eu; mkdir -p /output/{kernel}; "
                  f"cp /source/runtime/ultra/policy/kernel/* /source/runtime/ultra/policy/policy_layout_slots.h /output/{kernel}/; "
                  "export LD_LIBRARY_PATH=/compiler/lib/x86_64-linux-gnu; "
                  f"cc='python3 /source/scripts/policy-kernel-clang.py {args.cc_618}'; "
                  f"make -C /kernel O=/kernel-build M=/output/{kernel} ARCH=arm64 LLVM=1 CC=\"$cc\" "
                  "LOCALVERSION=-maplesu-policy-ci MAPLESU_POLICY_PIC=1 -j2 maplesu_policy_view.o; "
                  f"make -C /kernel O=/kernel-build M=/output/{kernel} ARCH=arm64 LLVM=1 CC=\"$cc\" "
                  "LOCALVERSION=-maplesu-policy-ci -j2 maplesu_policy_layout.o; "
                  f"ld.lld -r -o /output/{kernel}/maplesu_policy_view.payload.o --whole-archive "
                  f"/output/{kernel}/maplesu_policy_view.o --no-whole-archive; "
                  "ld.lld -shared --entry=0 --strip-debug -Bsymbolic -z max-page-size=65536 -z force-bti "
                  f"-o /output/{kernel}/policy-view.so /output/{kernel}/maplesu_policy_view.payload.o; "
                  f"llvm-objcopy --decompress-debug-sections /output/{kernel}/abi_anchors.o /output/{kernel}/abi-layout.o; "
                  f"cp /kernel-build/include/config/auto.conf /output/{kernel}/compiled.config")
    result = dict(kernel=kernel, **run(kernel, script))
    if result["exitCode"]:
        return result
    target = args.output / kernel
    if kernel == "android17-6.18":
        metadata = subprocess.run([sys.executable, str(ROOT / "scripts/policy_payload_image_target.py"),
            str(ROOT / "jailbreak-providers/root-loader/contracts/family-6.18.json"), "--output", str(target),
            "--kernel-source", str(args.source_618)], capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=40)
        result["rawImageMetadata"] = dict(exitCode=metadata.returncode, stdout=metadata.stdout, stderr=metadata.stderr)
        if metadata.returncode:
            result["exitCode"] = 1
            return result
        identity_path = args.source_618 / "source-identity.json"
        if not identity_path.is_file():
            identity_path = args.source_618 / "SOURCE-IDENTITY.json"
        if identity_path.is_file():
            identity = json.loads(identity_path.read_text())
            commit = identity.get("sourceCommit", identity.get("commit", ""))
            if len(commit) != 40 or any(c not in "0123456789abcdef" for c in commit):
                raise ValueError("6.18 source export identity is incomplete")
            hashes = identity.get("sourceSha256", {})
            if not hashes and identity.get("kind") != "official-gitiles-subtree-export":
                raise ValueError("6.18 source export identity has no verified inputs")
            for name, digest in hashes.items():
                path = (args.source_618 / name).resolve()
                if not path.is_relative_to(args.source_618.resolve()) or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                    raise ValueError("Recovered source changed: " + name)
            result["sourceCommit"] = commit
            result["sourceIdentitySha256"] = hashlib.sha256(identity_path.read_bytes()).hexdigest()
            result["sourceIsGitCheckout"] = False
            result["sourceOrigin"] = "commit-bound archive, selected build inputs"
        else:
            result["sourceCommit"] = subprocess.check_output(["git", "-C", str(args.source_618), "rev-parse", "HEAD"], text=True).strip()
            result["sourceIsGitCheckout"] = True
        result["fullKernelPrepared"] = False
        result["scope"] = "Actual C payload/layout Kbuild; prepare0 only. Rust bindings/full kernel build remain separate."
    result["targetIdentity"] = json.loads((target / "target-identity.json").read_text())
    symbols = {line.split()[-1] for line in (target / "System.map").read_text().splitlines() if line.split()}
    binary = target / "maplesu_policy_view.payload.o"
    with binary.open("rb") as stream:
        elf = ELFFile(stream)
        table = elf.get_section_by_name(".symtab")
        undefined = sorted({sym.name for sym in table.iter_symbols()
                            if sym["st_shndx"] == "SHN_UNDEF" and sym.name})
        missing = sorted(set(undefined) - symbols)
        relocations = sorted({reloc["r_info_type"] for section in elf.iter_sections()
                              if section["sh_type"] == "SHT_RELA" and
                              elf.get_section(section["sh_info"])["sh_flags"] & 2
                              for reloc in section.iter_relocations()})
        entries = ["maplesu_policy_view_prepare", "maplesu_policy_view_handles",
                   "maplesu_policy_view_context", "maplesu_policy_view_access",
                   "maplesu_policy_view_setprocattr", "maplesu_policy_view_status_open",
                   "maplesu_policy_view_status_read", "maplesu_policy_view_status_mmap",
                   "maplesu_policy_view_filter"]
        missing_entries = [name for name in entries if not table.get_symbol_by_name(name)]
        result.update(architecture=elf["e_machine"], elfType=elf["e_type"],
                      hasDwarf=elf.has_dwarf_info(), requiredSymbols=undefined,
                      missingRequiredSymbols=missing, missingEntrypoints=missing_entries,
                      allocatedSectionRelocations=relocations,
                      sha256=hashlib.sha256(binary.read_bytes()).hexdigest(), size=binary.stat().st_size)
        if missing or missing_entries or elf["e_machine"] != "EM_AARCH64" or elf["e_type"] != "ET_REL":
            result["exitCode"] = 1
    if result["exitCode"]:
        return result
    try:
        result["picPayload"] = inspect_payload(target / "policy-view.so", symbols)
    except ValueError as error:
        result["picPayload"] = {"passed": False, "reason": str(error)}
        result["exitCode"] = 1
        return result
    generated = subprocess.run([sys.executable, str(ROOT / "scripts/build-ultra-policy-layout.py"),
                                str(binary), str(target / "abi-layout.o"), "--output",
                                str(target / "compiled-layout.json")], capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=30)
    result["layoutGeneration"] = dict(exitCode=generated.returncode, stdout=generated.stdout, stderr=generated.stderr)
    if generated.returncode:
        result["exitCode"] = 1
        return result
    types = json.loads((target / "compiled-layout.json").read_text())
    result["layoutTypes"] = len(types)
    result["layoutFields"] = sum(len(t["fields"]) for t in types)
    dynamic = " dynamic-scs" if result["targetIdentity"]["dynamicScs"] else ""
    # Static failure injection is replayed separately against legacy production
    # payloads (test-ultra-policy-loader.py). New images require their complete
    # dynamic contract rather than that test's deliberately minimal fake BTF.
    payload_tests = [f"/output/payload-test /output/{kernel}/policy-view.so{dynamic}",
        "cc -std=gnu11 -Wall -Wextra -Werror -fsanitize=address,undefined "
        "-fno-omit-frame-pointer -I/source/runtime/ultra/policy -I/source/runtime/ultra/policy/kernel "
        f"-c /source/runtime/tests/policy_dynamic_access_fixture.c -o /output/{kernel}/dynamic-access.o",
        "c++ -std=c++20 -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer "
        f"-I/source/runtime/ultra/policy -I/output/{kernel} /source/runtime/ultra/policy/kernel_layout.cpp "
        "/source/runtime/ultra/policy/kernel_payload.cpp /source/runtime/ultra/policy/kernel_payload_loader.cpp "
        f"/source/runtime/tests/kernel_dynamic_payload_test.cpp /output/{kernel}/dynamic-access.o "
        f"-o /output/{kernel}/dynamic-test",
        f"/output/{kernel}/dynamic-test /output/{kernel}/policy-view.so"]
    if result["targetIdentity"]["dynamicScs"]:
        payload_tests.append(f"/output/scs-probe /output/{kernel}/policy-view.so /output/{kernel}/scs-replay")
    result["payloadLoaderTests"] = run("android15-6.6", " && ".join(payload_tests))
    if result["payloadLoaderTests"]["exitCode"]:
        result["exitCode"] = 1
        return result
    if result["targetIdentity"]["dynamicScs"]:
        replay = subprocess.run([sys.executable, str(ROOT / "scripts/tests/test-ultra-policy-native-scs.py"), str(target)],
                                capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=30)
        result["nativeScsReplay"] = dict(exitCode=replay.returncode, stdout=replay.stdout, stderr=replay.stderr)
        if replay.returncode:
            result["exitCode"] = 1
            return result
    # Avoid a temporary copy of the complete vmlinux just to dump one section.
    extracted = (dict(exitCode=0) if kernel == "android17-6.18" else
                 run(kernel, f"llvm-objcopy --only-section=.BTF --output-target=binary "
                     f"--dump-section .BTF=/output/{kernel}/vmlinux.btf "
                     f"/opt/ddk/kdir/{kernel}/vmlinux /dev/null"))
    if extracted["exitCode"]:
        if "section '.BTF' not found" in extracted["stderr"]:
            result["targetBtfProbe"] = dict(available=False, passed=False,
                reason="This reference kernel image has no .BTF section; compile success is not runtime layout acceptance")
            return result
        result["exitCode"] = 1
        result["targetBtfProbe"] = extracted
        return result
    probe = run(kernel, "c++ -std=c++17 -Wall -Wextra -Werror -fsanitize=address,undefined "
                "-fno-omit-frame-pointer -I/source/runtime/ultra/policy "
                f"-I/output/{kernel} /source/runtime/ultra/policy/kernel_layout.cpp "
                f"/source/runtime/tests/kernel_layout_probe.cpp -o /output/{kernel}/layout-probe && "
                f"/output/{kernel}/layout-probe /output/{kernel}/vmlinux.btf && "
                f"/output/{kernel}/dynamic-test /output/{kernel}/policy-view.so /output/{kernel}/vmlinux.btf")
    result["targetBtfProbe"] = dict(available=True, **probe)
    if probe["exitCode"]:
        result["exitCode"] = 1
    return result

with ThreadPoolExecutor(max_workers=2) as executor:
    results = list(executor.map(build, args.kernels))
report = dict(generatedAt=datetime.now(timezone.utc).isoformat(), hostTests=host, results=results,
              sourceSha256={str(p.relative_to(ROOT)).replace("\\", "/"):
                            hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs if p.is_file()},
              sourcesUnchanged=source_before == {str(p.relative_to(ROOT)).replace("\\", "/"): hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs if p.is_file()},
              deviceAccess=False, installed=False, productionSdkChanged=False,
              scope="KSU-derived parser/SID logic and loader failures with kernel I/O fixtures; actual PIC/object compilation, independent BTI entry/relocation/import/alternative inspection, reference BTF layout and native SCS instruction replay; no live kernel loading or hook acceptance")
receipt = args.save
receipt.parent.mkdir(parents=True, exist_ok=True)
receipt.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
print(host["stdout"] or host["stderr"])
for result in results:
    print(json.dumps(dict(kernel=result["kernel"], exitCode=result["exitCode"],
        layoutTypes=result.get("layoutTypes"), layoutFields=result.get("layoutFields"),
        referenceBtf=result.get("targetBtfProbe", {}).get("available", False),
        loaderTests=result.get("payloadLoaderTests", {}).get("stdout", "").strip(),
        nativeScs=result.get("nativeScsReplay", {}).get("stdout", "").strip())))
print("Receipt:", receipt)
raise SystemExit(0 if report["sourcesUnchanged"] and host["exitCode"] == 0 and all(r["exitCode"] == 0 for r in results) else 1)
