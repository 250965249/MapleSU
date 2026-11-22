#!/usr/bin/env python3
"""Run current IR and actual C++ installers in the same recorded host fixture.

Kernel identity and SELinux labels are synthetic; output is not device evidence.
The immutable IR inputs are retained as the legacy behaviour oracle.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

SDK = Path(__file__).resolve().parents[1]
REPO = SDK.parents[2]
IMAGE = "ghcr.io/ylarod/ddk-min:android15-6.6-20260828"
MEMBERS = {
    48: ("maplesu_unsafe_su_install", "unsafe_install_su", "installer_ir/maplesu_unsafe_su_install_patched.ll"),
    49: ("maplesu_unsafe_resetprop_install", "unsafe_install_resetprop", "maplesu_unsafe_resetprop_install_patched.ll"),
    50: ("maplesu_unsafe_webui_loader_install", "unsafe_install_webui_loader", "maplesu_unsafe_webui_loader_install_patched.ll"),
    52: ("maplesu_autorun_bootstrap_install", "unsafe_install_autorun_bootstrap", "maplesu_autorun_bootstrap_install_patched.ll"),
}

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def scenarios(member):
    result = ["success", "root:1", "publish:1", "chmod:1", "label:1"]
    if member != 49:
        result += ["payloadalloc", "tokenalloc", "tokenmissing"]
    if member in (48, 50):
        result += ["chmod:2", "label:2"] if member == 48 else ["chmod:2"]
    if member == 48:
        result += ["publish:2"]
    if member == 52:
        result += ["root:2", "root:3"]
        result += [f"open:{i}" for i in range(1, 10)]
        result += [f"chmod:{i}" for i in range(2, 10)]
        result += [f"label:{i}" for i in range(2, 10)]
    return result

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--members", nargs="+", type=int, choices=MEMBERS, default=[49, 50, 48, 52])
    parser.add_argument("--assets-gen", required=True, type=Path)
    args = parser.parse_args()
    output = args.out.resolve()
    output.mkdir(parents=True, exist_ok=True)
    assets = args.assets_gen.resolve()
    if not (assets / "payload_assets.generated.h").is_file():
        raise ValueError("Generate the actual payload headers before differential acceptance")
    try:
        asset_include = "/repo/" + assets.relative_to(REPO).as_posix()
    except ValueError:
        raise ValueError("The generated payload headers must be in the repository fixture")
    commands = ["set -eu", "cd /case", "C=/opt/ddk/clang/clang-r510928", "export LD_LIBRARY_PATH=$C/lib/x86_64-unknown-linux-gnu"]
    include = "-I/repo/runtime/maplesu-sdk/sdk/tests/installer_stub -I/repo/runtime/maplesu-sdk/include -I/repo/runtime/maplesu-sdk/sdk/include"
    flags = f"-stdlib=libc++ -std=c++20 -Oz -fno-builtin-memcmp -ffunction-sections -fdata-sections {include} -DMAPLESU_PAYLOAD_ASSETS=1 -I{asset_include}"
    wraps = " ".join(f"-Wl,--wrap={name}" for name in ["fopen", "chmod", "setxattr", "fsetxattr", "memcmp", "maplesu_publish_executable", "_ZnamRKSt9nothrow_t"])
    inputs = []
    for member in args.members:
        stem, entry, ir_name = MEMBERS[member]
        cpp = SDK / "src/maplesu_assets" / (stem + ".cpp")
        ir = SDK / "src/maplesu_assets" / ir_name
        text = ir.read_text(encoding="utf-8-sig")
        text = re.sub(r"^@llvm.global_ctors = .*\n", "", text, flags=re.M)
        text = re.sub(r"^target datalayout = .*\n", "", text, flags=re.M)
        text = re.sub(r'^target triple = .*\n', 'target triple = "x86_64-unknown-linux-gnu"\n', text, flags=re.M)
        text = re.sub(r'"target-[^"]+"="[^"]*"', "", text)
        text = text.replace("6__ndk1", "3__1").replace("__ndk1", "__1").replace("9mbstate_t", "11__mbstate_t")
        (output / f"m{member}.oracle.ll").write_text(text, encoding="utf-8")
        wrapper = (f'#include "module_err_def.h"\nnamespace maplesu::sdk {{ KModErr {entry}(); }}\n'
                   f'extern "C" KModErr test_install() {{ return maplesu::sdk::{entry}(); }}\n')
        (output / f"m{member}.entry.cpp").write_text(wrapper, encoding="utf-8")
        commands.append(f"$C/bin/clang++ -c -ffunction-sections -fdata-sections m{member}.oracle.ll -o m{member}.oracle.o")
        for producer, source in [("oracle", f"m{member}.oracle.o"), ("cpp", "/repo/" + cpp.relative_to(REPO).as_posix())]:
            commands.append(f"$C/bin/clang++ {flags} -Wl,--gc-sections {wraps} /repo/runtime/maplesu-sdk/sdk/tests/installer_differential.cpp m{member}.entry.cpp {source} /repo/runtime/maplesu-sdk/sdk/src/maplesu_assets/installer_ir/executable_publish.cpp -o m{member}.{producer}")
            for index, fault in enumerate(scenarios(member)):
                target = f"results/m{member}/{index:02}_{fault.replace(':', '-')}/{producer}"
                commands.append("rm -rf /data/ABCDEFGHIJKLMNOP /data/ABCDEFGHIJKLMNOPA")
                commands.append(f"./m{member}.{producer} {member} {fault} /case/{target}")
        inputs.append(dict(member=member, cpp=str(cpp.relative_to(REPO)), cpp_sha256=sha(cpp), oracle=str(ir.relative_to(REPO)), oracle_sha256=sha(ir)))
    script = "\n".join(commands) + "\n"
    (output / "run.sh").write_text(script, encoding="utf-8", newline="\n")
    run = subprocess.run(["docker", "run", "--rm", "--pull", "never", "--network", "none", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--mount", f"type=bind,source={REPO},target=/repo,readonly", "--mount", f"type=bind,source={output},target=/case", "--entrypoint", "sh", IMAGE, "/case/run.sh"], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300)
    (output / "build-run.log").write_text(run.stdout + run.stderr, encoding="utf-8")
    rows = []
    if run.returncode == 0:
        for member in args.members:
            for scenario in sorted((output / f"results/m{member}").iterdir()):
                oracle, candidate = scenario / "oracle", scenario / "cpp"
                differences = []
                expected = {p.relative_to(oracle).as_posix(): p for p in oracle.rglob("*") if p.is_file()}
                actual = {p.relative_to(candidate).as_posix(): p for p in candidate.rglob("*") if p.is_file()}
                for name in sorted(expected.keys() | actual.keys()):
                    if name not in expected or name not in actual or expected[name].read_bytes() != actual[name].read_bytes(): differences.append(name)
                row = dict(member=member, scenario=scenario.name, equivalent=not differences, differences=differences)
                rows.append(row)
                print(f"{'PASS' if not differences else 'FAIL'} m{member} {scenario.name} {','.join(differences)}")
    image_id = subprocess.run(["docker", "image", "inspect", "--format", "{{.Id}}", IMAGE], capture_output=True, text=True, check=True).stdout.strip()
    fixture_inputs = [Path(__file__), SDK / "tests/installer_differential.cpp",
                      SDK / "tests/installer_stub/kernel_module_kit_umbrella.h",
                      SDK / "src/maplesu_assets/installer_ir/executable_publish.cpp",
                      SDK / "src/maplesu_assets/installer_ir/executable_publish.h"]
    generated_headers = [{"path": str(path.relative_to(REPO)), "sha256": sha(path), "bytes": path.stat().st_size}
                         for path in sorted(assets.glob("*.h"))]
    report = dict(schema="maplesu-installer-differential/1", device_acceptance=False, image=IMAGE, image_id=image_id,
                  inputs=inputs, fixture_inputs=[{"path": str(path.relative_to(REPO)), "sha256": sha(path)} for path in fixture_inputs],
                  generated_headers=generated_headers, process_exit=run.returncode, cases=rows,
                  passed=sum(row['equivalent'] for row in rows), failed=sum(not row['equivalent'] for row in rows))
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if run.returncode:
        print((run.stdout + run.stderr)[-6000:], file=sys.stderr)
    print(f"passed={report['passed']} failed={report['failed']} process_exit={run.returncode}")
    return 1 if run.returncode or report['failed'] else 0

if __name__ == "__main__":
    raise SystemExit(main())
