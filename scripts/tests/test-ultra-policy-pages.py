"""Compile the real Ultra payload with independent 4K/16K/64K arm64 Kbuild configs.

This checks compilation, not compatibility with a running image. Each configuration
gets its own prepared object tree; no reference-image metadata is reused for it.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--source", required=True, type=Path)
parser.add_argument("--prepared", required=True, type=Path)
parser.add_argument("--toolchain", required=True, type=Path)
parser.add_argument("--output", required=True, type=Path)
parser.add_argument("--timeout", default=600, type=int)
args = parser.parse_args()
args.output.mkdir(parents=True, exist_ok=True)
results = []
for page in (4, 16, 64):
    name = "maplesu-policy-pages-" + str(page) + "-" + uuid.uuid4().hex[:8]
    script = f"""set -eu
out=/output/{page}k
mkdir -p "$out/build" "$out/payload"
cp -a /prepared/. "$out/build/"
cp /source/runtime/ultra/policy/kernel/* /source/runtime/ultra/policy/policy_layout_slots.h "$out/payload/"
export LD_LIBRARY_PATH=/compiler/lib/x86_64-linux-gnu
cc='python3 /source/scripts/policy-kernel-clang.py /compiler/bin/clang-22'
/kernel/scripts/config --file "$out/build/.config" -d ARM64_4K_PAGES -d ARM64_16K_PAGES -d ARM64_64K_PAGES -e ARM64_{page}K_PAGES
make -C /kernel O="$out/build" ARCH=arm64 LLVM=1 CC="$cc" LOCALVERSION=-maplesu-policy-pages olddefconfig
grep -qx CONFIG_ARM64_{page}K_PAGES=y "$out/build/.config"
make -C /kernel O="$out/build" ARCH=arm64 LLVM=1 CC="$cc" LOCALVERSION=-maplesu-policy-pages -j2 prepare0
mkdir -p "$out/build/security/selinux"
cc -O2 -I/kernel/security/selinux/include /kernel/security/selinux/genheaders.c -o "$out/build/security/selinux/genheaders"
"$out/build/security/selinux/genheaders" "$out/build/security/selinux/flask.h" "$out/build/security/selinux/av_permissions.h"
make -C /kernel O="$out/build" M="$out/payload" ARCH=arm64 LLVM=1 CC="$cc" LOCALVERSION=-maplesu-policy-pages MAPLESU_POLICY_PIC=1 -j2 maplesu_policy_view.o
make -C /kernel O="$out/build" M="$out/payload" ARCH=arm64 LLVM=1 CC="$cc" LOCALVERSION=-maplesu-policy-pages -j2 maplesu_policy_layout.o
ld.lld -r -o "$out/payload/payload.o" --whole-archive "$out/payload/maplesu_policy_view.o" --no-whole-archive
ld.lld -shared --entry=0 --strip-debug -Bsymbolic -z max-page-size=65536 -z force-bti -o "$out/payload/policy-view.so" "$out/payload/payload.o"
llvm-objcopy --decompress-debug-sections "$out/payload/abi_anchors.o" "$out/payload/abi-layout.o"
"""
    command = ["docker", "run", "--rm", "--pull", "never", "--network", "none",
               "--name", name, "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
               "--mount", f"type=bind,source={ROOT},target=/source,readonly",
               "--mount", f"type=bind,source={args.source.resolve()},target=/kernel,readonly",
               "--mount", f"type=bind,source={args.prepared.resolve()},target=/prepared,readonly",
               "--mount", f"type=bind,source={args.toolchain.resolve()},target=/compiler,readonly",
               "--mount", f"type=bind,source={args.output.resolve()},target=/output",
               "ghcr.io/ylarod/ddk-min:android16-6.12-20260828", "sh", "-c", script]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=args.timeout)
        record = dict(pageSize=page * 1024, exitCode=result.returncode,
                      stdout=result.stdout, stderr=result.stderr, command=command)
    except subprocess.TimeoutExpired as error:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=20)
        record = dict(pageSize=page * 1024, exitCode=124,
                      stdout=error.stdout if isinstance(error.stdout, str) else
                             (error.stdout or b"").decode(errors="replace"),
                      stderr="Kbuild timeout", command=command)
    if record["exitCode"] == 0:
        output = args.output / f"{page}k" / "payload"
        layout = subprocess.run([sys.executable, str(ROOT / "scripts/build-ultra-policy-layout.py"),
            str(output / "payload.o"), str(output / "abi-layout.o"), "--output",
            str(output / "compiled-layout.json")], capture_output=True, text=True, timeout=30)
        record["layout"] = dict(exitCode=layout.returncode, stdout=layout.stdout, stderr=layout.stderr)
        record["exitCode"] = layout.returncode
        record["artifactsSha256"] = {file: hashlib.sha256((output / file).read_bytes()).hexdigest()
                                     for file in ("policy-view.so", "payload.o", "abi-layout.o")}
        config = args.output / f"{page}k" / "build" / ".config"
        record["configSha256"] = hashlib.sha256(config.read_bytes()).hexdigest()
    results.append(record)
    print(f"{page}K: exit={record['exitCode']}", flush=True)
    if record["exitCode"]:
        print(record.get("stderr", ""), flush=True)
        break
sources = list((ROOT / "runtime/ultra/policy/kernel").glob("*")) + [Path(__file__),
    ROOT / "scripts/policy-kernel-clang.py", ROOT / "scripts/build-ultra-policy-layout.py"]
report = dict(recordedAt=datetime.now(timezone.utc).isoformat(),
    sourceCommit=subprocess.check_output(["git", "-C", str(args.source), "rev-parse", "HEAD"], text=True).strip(),
    sourceSha256={str(p.relative_to(ROOT)).replace("\\", "/"): hashlib.sha256(p.read_bytes()).hexdigest()
                  for p in sources if p.is_file()}, results=results,
    scope=__doc__, deviceAccess=False, fullKernelBuild=False, runningImageCompatibility=False)
receipt = ROOT / "work/ultra-module-policy-20261107/kernel-page-kbuild.json"
receipt.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
print("Receipt:", receipt)
raise SystemExit(0 if len(results) == 3 and all(r["exitCode"] == 0 for r in results) else 1)
