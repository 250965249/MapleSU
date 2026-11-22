"""Exercise the actual controller's source I/O and transaction ordering, without a device."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
IMAGE = "sha256:51159bc935c75a282fc65bc87e02f16bd098d1cdf55dc558c4fdd0fcf7a132e2"
SOURCES = ["module-policy/src/boot_sdk_control.cpp", "module-policy/src/boot_sdk_layout.h",
           "runtime/ultra/policy/kernel_layout.h", "jailbreak-providers/root-loader/boot_sdk_abi.h",
           "runtime/tests/boot_sdk_control_test.cpp", "scripts/tests/test-boot-sdk-control.py"]
CASES = ["info-empty", "info-ready", "start-ready", "start-failed", "start-initializing",
         "start-configured", "start-static", "good", "missing", "denied", "empty", "read-error",
         "read-interrupted", "limit", "oversize", "invalid-btf", "config-error", "clean-retry",
         "dirty-no-retry", "transport-interrupted", "bad-response", "query-error", "open-interrupted"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--red", action="store_true")
    args = parser.parse_args()
    output = args.out.resolve()
    output.mkdir(parents=True, exist_ok=False)
    digest = lambda: {path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest() for path in SOURCES}
    before = digest()
    for path in SOURCES:
        dest = output / "source" / path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes((ROOT / path).read_bytes())
    compile_args = ["c++", "-std=c++17", "-Wall", "-Wextra", "-Werror", "-static-libstdc++",
                    "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                    "/source/module-policy/src/boot_sdk_control.cpp",
                    "/source/runtime/tests/boot_sdk_control_test.cpp", "-o", "/output/control-test"]
    compile_args += ["-Wl,--wrap=" + name for name in
                     ("open", "fopen", "fopen64", "read", "close", "getuid", "geteuid", "sysconf", "prctl")]
    plan = [("compile", compile_args)] + [(name, ["/output/control-test", name])
              for name in (["denied"] if args.red else CASES)]
    (output / "commands.json").write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")
    driver = """import json, pathlib, subprocess
out = pathlib.Path('/output')
results = []
for name, argv in json.loads((out/'commands.json').read_text()):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=90)
    (out/(name+'.log')).write_text(result.stdout+result.stderr)
    results.append(dict(name=name, argv=argv, exit=result.returncode))
    print(name+': '+str(result.returncode), flush=True)
    if name == 'compile' and result.returncode: break
(out/'results.json').write_text(json.dumps(results, indent=2)+'\\n')
"""
    command = ["docker", "run", "--rm", "--pull", "never", "--network", "none", "--cap-drop", "ALL",
               "--security-opt", "no-new-privileges", "--mount", f"type=bind,source={output / 'source'},target=/source,readonly",
               "--mount", f"type=bind,source={output},target=/output", IMAGE, "python3", "-c", driver]
    result = subprocess.run(command, capture_output=True, text=True, timeout=180)
    (output / "docker.log").write_text(result.stdout + result.stderr, encoding="utf-8")
    rows = json.loads((output / "results.json").read_text()) if (output / "results.json").exists() else []
    compiled = bool(rows) and rows[0]["name"] == "compile" and rows[0]["exit"] == 0
    expected_red = False
    if args.red and compiled and len(rows) == 2:
        log = (output / "denied.log").read_text()
        expected_red = rows[1]["exit"] == 1 and "opened=1" in log and "expected=BOOT_SDK_BTF_OPEN:13" in log
    passed = expected_red if args.red else compiled and len(rows) == len(plan) and all(r["exit"] == 0 for r in rows)
    unchanged = before == digest()
    receipt = dict(at=datetime.now(timezone.utc).isoformat(), passed=passed, red=args.red,
                   expectedFailureReproduced=expected_red, sourcesBefore=before, sourcesUnchanged=unchanged,
                   dockerCommand=command, dockerExit=result.returncode, results=rows, sanitize=True,
                   formalArtifactBuilt=False, deviceTest=False,
                   scope="Actual controller TU and I/O; layout resolver is a link substitute, not layout evidence")
    (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(result.stdout + result.stderr, end="")
    print(json.dumps(dict(passed=passed, sourcesUnchanged=unchanged, red=args.red)))
    return 0 if passed and unchanged and not result.returncode else 1


if __name__ == "__main__":
    raise SystemExit(main())
