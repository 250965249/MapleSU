"""Run the real root-loader subject consumer and freeze its actual host commands."""
from __future__ import annotations

import argparse
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
TEST = ROOT / "jailbreak-providers/root-loader/tests/test_boot_current_model.py"


def identity(path, raw=None):
    path = Path(path).resolve()
    raw = path.read_bytes() if raw is None else raw
    return {"path": str(path), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    spec = importlib.util.spec_from_file_location("ngki_subject_test", TEST)
    tests = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tests)
    product = tests.builder.layout_product
    paths = [TEST, Path(__file__), ROOT / "jailbreak-providers/root-loader/build_root_module.py",
             ROOT / "jailbreak-providers/root-loader/legacy_cfi.py",
             ROOT / "jailbreak-providers/root-loader/legacy_510.py",
             ROOT / "jailbreak-providers/root-loader/tests/test_legacy_510.py",
             ROOT / "jailbreak-providers/root-loader/policy_hook_build.py",
             ROOT / "jailbreak-providers/root-loader/boot_sdk_build.py",
             ROOT / "tools/native_toolchain.py",
             ROOT / "tools/specgen/HostMain.kt", Path(product.__file__)]
    paths += sorted((ROOT / "manager/src/main/java/dev/maplesu/manager/ultrakernel").glob("*.kt"))
    paths += sorted((ROOT / "image-core/src/main/java").rglob("*.java"))
    sources = []
    for path in paths:
        raw = path.read_bytes()
        sources.append(identity(path, raw))
        snapshot = out / "source" / path.relative_to(ROOT)
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        snapshot.write_bytes(raw)
    commands = []
    original_run = subprocess.run

    def traced_run(command, *positional, **kwargs):
        row = {"argv": list(map(str, command)), "stdinClosed": kwargs.get("stdin") == subprocess.DEVNULL,
               "inputProvided": kwargs.get("input") is not None}
        if "--kernel" in row["argv"]:
            row["kernel"] = identity(row["argv"][row["argv"].index("--kernel") + 1])
        commands.append(row)
        result = original_run(command, *positional, **kwargs)
        row.update(exitCode=result.returncode, stdout=result.stdout, stderr=result.stderr)
        return result

    subprocess.run = traced_run
    status = 1
    runtime = None
    try:
        java, jar, classpath = product._host_runtime()
        runtime = {"java": identity(java), "jar": identity(jar), "classpath": classpath,
                   "jvmFlags": product.JVM_FLAGS,
                   "dependencies": [identity(path) for path in classpath.split(os.pathsep)]}
        suffix = ".exe" if os.name == "nt" else ""
        build_dependencies = [Path(java).parent / (tool + suffix) for tool in ("javac", "jar")]
        build_dependencies += [product.cached_jar("org.jetbrains.kotlin", "kotlin-compiler-embeddable", "2.4.20"),
                               product.cached_jar("org.jetbrains.kotlinx", "kotlinx-coroutines-core-jvm", "1.11.0")]
        runtime["buildDependencies"] = [identity(path) for path in build_dependencies]
        shutil.copyfile(jar, out / "host.jar")
        tests.RECEIPT = out / "tests.json"
        with (out / "tests.log").open("w", encoding="utf-8") as log:
            result = unittest.TextTestRunner(stream=log, verbosity=2).run(
                unittest.defaultTestLoader.loadTestsFromModule(tests))
        status = 0 if result.wasSuccessful() else 1
        print(f"tests={result.testsRun} failures={len(result.failures)} errors={len(result.errors)}", flush=True)
    except Exception as error:
        (out / "error.txt").write_text(str(error), encoding="utf-8")
        print(type(error).__name__ + ": " + str(error), flush=True)
    finally:
        subprocess.run = original_run
        unchanged = all(identity(row["path"]) == row for row in sources)
        receipt = {"schemaVersion": 1, "capturedAtUtc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                   "entry": "build_root_module.derive_l3_subject_facts",
                   "python": identity(sys.executable), "pythonVersion": sys.version,
                   "hostOnly": True, "sources": sources, "sourcesUnchanged": unchanged,
                   "runtime": runtime, "commands": commands, "exitCode": status,
                   "deviceTest": False, "formalArtifactBuilt": False,
                   "scope": "subject producer/consumer and current qualifier; not complete CONFIGURE or NGKI startup"}
        (out / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    return status if unchanged else 2


if __name__ == "__main__":
    raise SystemExit(main())
