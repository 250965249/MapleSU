"""Build exact legacy kernel inverses from explicit, reviewed original/patched pairs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/specgen"))
from specgen.product import cached_jar


def identity(path):
    path = Path(path).resolve()
    data = path.read_bytes()
    return dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-receipt", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--pair", nargs=2, type=Path, action="append", required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    runtime = json.loads(args.runtime_receipt.read_bytes())["runtime"]
    source = ROOT / "tools/specgen/LegacyRecoveryAssets.kt"
    inputs = [identity(__file__), identity(source), identity(args.runtime_receipt),
        runtime["java"], runtime["jar"], *runtime["dependencies"], *runtime["buildDependencies"],
        *[identity(path) for pair in args.pair for path in pair]]
    assert all(identity(row["path"]) == row for row in inputs), "INPUT_DRIFT"
    compiler = cached_jar("org.jetbrains.kotlin", "kotlin-compiler-embeddable", "2.4.20")
    coroutines = cached_jar("org.jetbrains.kotlinx", "kotlinx-coroutines-core-jvm", "1.11.0")
    boot = os.pathsep.join(map(str, [compiler, *runtime["classpath"].split(os.pathsep)[:2], coroutines]))
    cp = runtime["jar"]["path"] + os.pathsep + runtime["classpath"]
    jar = out / "producer.jar"
    commands = [("compile", [runtime["java"]["path"], "-Dfile.encoding=UTF-8", "-Xmx768m", "-cp", boot,
        "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler", "-no-stdlib", "-no-reflect", "-jvm-target", "17",
        "-Xfriend-paths=" + runtime["jar"]["path"], "-classpath", cp, "-d", str(jar), str(source)]),
        ("produce", [runtime["java"]["path"], "-Dfile.encoding=UTF-8", "-Xmx768m", "-cp",
        str(jar) + os.pathsep + cp, "dev.maplesu.manager.ultrakernel.LegacyRecoveryAssetsKt", str(out / "assets"),
        *[str(path.resolve()) for pair in args.pair for path in pair]])]
    receipt = dict(inputs=inputs, commands=[], deviceTest=False, partitionWrites=False)
    for label, command in commands:
        done = subprocess.run(command, cwd=ROOT, stdin=subprocess.DEVNULL, capture_output=True)
        (out / (label + ".stdout.log")).write_bytes(done.stdout)
        (out / (label + ".stderr.log")).write_bytes(done.stderr)
        receipt["commands"].append(dict(label=label, argv=command, exitCode=done.returncode))
        if done.returncode:
            print(done.stderr.decode("utf-8", "replace"))
            break
    if done.returncode == 0:
        receipt["pairs"] = json.loads(done.stdout)
        receipt["outputs"] = [identity(path) for path in sorted((out / "assets").iterdir())]
    receipt["inputsUnchanged"] = all(identity(row["path"]) == row for row in inputs)
    receipt["exitCode"] = done.returncode or (0 if receipt["inputsUnchanged"] else 2)
    (out / "receipt.json").write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(dict(exitCode=receipt["exitCode"], inputsUnchanged=receipt["inputsUnchanged"])))
    return receipt["exitCode"]


if __name__ == "__main__":
    raise SystemExit(main())
