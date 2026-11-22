#!/usr/bin/env python3
"""Compile and run the dependency-free, synthetic Java host suites."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SUITES = {
    "image": ["BootImageEquivalenceTest", "BootImageInspectorTest", "BootImageRebuilderTest",
              "CodecCancellationTest", "ImagePipelineTest", "InitBootRoundTripTest", "LenovoAvbSignerTest",
              "RamdiskInspectorTest", "RamdiskRebuilderTest", "RamdiskEntryEditorTest",
              "RamdiskComponentWriterTest", "VendorBootInspectorTest"],
    "installer": ["BlockDeviceTransactionTest", "FileInstallTransactionTest", "MultiPartitionTransactionTest",
                  "SwitchPlanValidationTest", "SwitchVerifyTest", "WritePathGuardTest"],
}


def java_tool(name: str) -> str:
    suffix = ".exe" if os.name == "nt" else ""
    home = os.environ.get("JAVA_HOME")
    if home and (Path(home) / "bin" / (name + suffix)).is_file():
        return str(Path(home) / "bin" / (name + suffix))
    value = shutil.which(name)
    if not value:
        raise RuntimeError(f"JDK 17+ required: {name} is missing; set JAVA_HOME")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=ROOT / "build/host-check",
                        help="Output directory (default: %(default)s)")
    output = parser.parse_args().out.resolve()
    output.mkdir(parents=True, exist_ok=True)
    results = []
    with tempfile.TemporaryDirectory(prefix="run-", dir=output) as directory:
        work = Path(directory)
        classes = work / "classes"
        classes.mkdir()
        sources = sorted(p for component in ("image-core", "installer-core")
                         for kind in ("main", "test")
                         for p in (ROOT / component / "src" / kind / "java").rglob("*.java"))
        arguments = work / "sources.txt"
        arguments.write_text("\n".join('"' + p.as_posix() + '"' for p in sources), encoding="utf-8")
        subprocess.run([java_tool("javac"), "--release", "17", "-encoding", "UTF-8",
                        "-d", str(classes), "@" + str(arguments)], check=True)
        for component in ("image-core", "installer-core"):
            resources = ROOT / component / "src/test/resources"
            if resources.exists():
                shutil.copytree(resources, classes, dirs_exist_ok=True)
        for package, suites in SUITES.items():
            for suite in suites:
                name = f"dev.maplesu.{package}.{suite}"
                # One static write guard intentionally reads its production source tree.
                cwd = ROOT if suite == "WritePathGuardTest" else work
                command = [java_tool("java"), "-Dmaplesu.root=" + str(work), "-cp", str(classes), name]
                run = subprocess.run(command, cwd=cwd, capture_output=True, text=True,
                                     encoding="utf-8", errors="replace", timeout=180)
                results.append(dict(suite=name, passed=run.returncode == 0,
                                    output=run.stdout + run.stderr))
                print(f"{'PASS' if run.returncode == 0 else 'FAIL'} {name}", flush=True)
                if run.returncode:
                    print(results[-1]["output"], flush=True)
    report = dict(suites=len(results), passed=sum(r["passed"] for r in results),
                  private_device_tests=False, results=results)
    (output / "results.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"{report['passed']}/{report['suites']} suites passed; report: {output / 'results.json'}")
    return int(report["passed"] != report["suites"])


if __name__ == "__main__":
    raise SystemExit(main())
