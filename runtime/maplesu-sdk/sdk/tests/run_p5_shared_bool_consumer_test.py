"""Run the production SELinux Hook dependency consumer with explicit I/O seams."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[4]
SDK = ROOT / "runtime/maplesu-sdk"
SOURCE = SDK / "sdk/src/module/module_selinux.cpp"
FIXTURE = Path(__file__).with_name("p5_shared_bool_consumer_fixture.cpp")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    options = parser.parse_args()
    out = options.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    source = SOURCE.read_text(encoding="utf-8")
    start = source.index("struct SelinuxHookReceipt {")
    end = source.index("\n}  // namespace", start)
    (out / "selinux_hooks_under_test.inc").write_text(source[start:end], encoding="utf-8")
    compiler = Path("C:/msys64/ucrt64/bin/g++.exe")
    command = [str(compiler), "-std=c++17", "-Wall", "-Wextra", "-Werror",
               "-I" + str(SDK / "include"), "-I" + str(ROOT / "runtime/ultra/authorization"),
               "-I" + str(out), str(FIXTURE), "-o", str(out / "consumer.exe")]
    env = dict(os.environ, PATH=str(compiler.parent) + os.pathsep + os.environ.get("PATH", ""))
    compiled = subprocess.run(command, capture_output=True, text=True, env=env)
    (out / "compile.log").write_text(compiled.stdout + compiled.stderr, encoding="utf-8")
    run = None
    if not compiled.returncode:
        run = subprocess.run([str(out / "consumer.exe")], capture_output=True, text=True, env=env)
        (out / "run.log").write_text(run.stdout + run.stderr, encoding="utf-8")
    result = {"compileCommand": command, "compileExitCode": compiled.returncode,
              "runExitCode": run.returncode if run else None,
              "productionSha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
              "fixtureSha256": hashlib.sha256(FIXTURE.read_bytes()).hexdigest(),
              "scope": "Exact production consumer functions; allocation/publication/storage are explicit seams; no kernel or device execution"}
    (out / "results.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(compiled.stdout + compiled.stderr)
    if run:
        print(run.stdout + run.stderr)
    return compiled.returncode or (run.returncode if run else 1)


if __name__ == "__main__":
    raise SystemExit(main())
