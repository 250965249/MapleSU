"""Run the real Manager generator on every retained native kernel and independently replay output."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/specgen"))
from specgen import product as host_product


def identity(path):
    data = path.read_bytes()
    try:
        name = str(path.relative_to(ROOT))
    except ValueError:
        name = str(path)
    return {"path": name.replace("\\", "/"), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--java", type=Path, required=True)
    parser.add_argument("--image-core", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    java, image, output = (p.resolve() for p in (args.java, args.image_core, args.output))
    output.mkdir(parents=True, exist_ok=False)
    kernels = sorted((ROOT / "native-inputs/kernels").glob("*/Image"))
    assert len(kernels) == 7, f"expected the seven retained kernels, got {len(kernels)}"
    sources = sorted((ROOT / "manager/src/main/java/dev/maplesu/manager/ultrakernel").glob("*.kt"))
    sources += [ROOT / "tools/specgen/HostMain.kt", Path(host_product.__file__)]
    runtime_java, product, classpath = host_product._host_runtime(str(java), image)
    java = Path(runtime_java)
    dependencies = [Path(path) for path in classpath.split(os.pathsep)]
    compiler = host_product.cached_jar("org.jetbrains.kotlin", "kotlin-compiler-embeddable", "2.4.20")
    coroutines = host_product.cached_jar("org.jetbrains.kotlinx", "kotlinx-coroutines-core-jvm", "1.11.0")
    tracked = kernels + sources + dependencies + [compiler, coroutines, java, product]
    inputs = [identity(p) for p in tracked]
    receipt = {"schema": "maplesu-source-kernel-matrix/1", "inputs": inputs,
        "runtime": {"java": identity(java), "hostJar": identity(product), "classpath": classpath,
            "dependencies": [identity(path) for path in dependencies], "jvmFlags": host_product.JVM_FLAGS},
        "deviceBootTestPerformed": False, "partitionWrites": False,
        "bootContainerRebuildPerformed": False, "cases": []}
    credential = output / "synthetic-credential.txt"
    credential.write_text("Aa1" * 16 + "\n", encoding="ascii")
    try:
        for kernel in kernels:
            work = output / kernel.parent.name
            work.mkdir()
            candidate = work / "patched.raw"
            command = [sys.executable, ROOT / "tools/specgen/make_spec.py", "--kernel", kernel,
                "--credential-file", credential, "--java", java, "--image-core", image,
                "--out", work / "patch.spec", "--receipt", work / "host-receipt.json",
                "--patched-kernel", candidate]
            started = time.monotonic()
            result = subprocess.run(list(map(str, command)), cwd=ROOT, capture_output=True,
                text=True, encoding="utf-8", errors="replace")
            (work / "stdout.log").write_text(result.stdout, encoding="utf-8")
            (work / "stderr.log").write_text(result.stderr, encoding="utf-8")
            case = {"target": kernel.parent.name, "input": identity(kernel),
                "command": list(map(str, command)), "exitCode": result.returncode,
                "elapsedSeconds": time.monotonic() - started,
                "stdout": identity(work / "stdout.log"), "stderr": identity(work / "stderr.log")}
            receipt["cases"].append(case)
            try:
                if result.returncode:
                    error = (result.stderr or result.stdout).strip()
                    marker = re.search(r"(?m)^(PRO_[A-Z][A-Za-z0-9_]*)(?::(.*))?$", error)
                    case.update({"generatedAndReadBack": False,
                        "earliestObservedFailure": {"code": marker.group(1) if marker else "PROCESS_NONZERO",
                            "detail": marker.group(2) or "" if marker else error},
                        "layoutFields": None, "layoutReceiptPublished": False,
                        "downstreamApplicationAndReadbackReached": False})
                    assert not candidate.exists()
                else:
                    host = json.loads((work / "host-receipt.json").read_bytes())
                    raw, patched = kernel.read_bytes(), candidate.read_bytes()
                    expected, covered = bytearray(raw), bytearray(len(raw))
                    count = 0
                    for line in (work / "patch.spec").read_text(encoding="utf-8").splitlines():
                        if not line or line.startswith("#"):
                            continue
                        offset, original, replacement = line.split("|")
                        offset, original, replacement = int(offset), bytes.fromhex(original), bytes.fromhex(replacement)
                        assert len(original) == len(replacement)
                        assert 0 <= offset <= len(raw) - len(replacement)
                        assert raw[offset:offset + len(original)] == original
                        expected[offset:offset + len(replacement)] = replacement
                        covered[offset:offset + len(replacement)] = b"\1" * len(replacement)
                        count += 1
                    assert patched == expected
                    changed = sum(a != b for a, b in zip(raw, patched))
                    outside = sum(a != b and not site for a, b, site in zip(raw, patched, covered))
                    assert outside == host["outsideSites"] == 0
                    assert count == host["sites"] and changed == host["changedBytes"]
                    assert hashlib.sha256(raw).hexdigest() == host["baseKernelSha256"]
                    assert hashlib.sha256(patched).hexdigest() == host["patchedKernelSha256"]
                    for field in host["layout"]["fields"].values():
                        owner = field["ownerSizeBytes"]
                        assert field["offsetBytes"] >= 0 and field["widthBytes"] > 0
                        assert owner is None or field["offsetBytes"] + field["widthBytes"] <= owner
                    case.update({"generatedAndReadBack": True, "kernelRelease": host["kernelRelease"],
                        "layoutFields": host["layout"]["fields"], "layoutReceiptPublished": True,
                        "hostReceipt": identity(work / "host-receipt.json"), "spec": identity(work / "patch.spec"),
                        "candidate": identity(candidate), "records": count, "changedBytes": changed, "outsideSites": outside,
                        "independentFullImageReadback": True})
                    del raw, patched, expected, covered
            finally:
                candidate.unlink(missing_ok=True)
            (work / "execution.json").write_text(json.dumps(case, indent=2) + "\n", encoding="utf-8")
            print(kernel.parent.name + " code=" + str(result.returncode) + " readback=" + str(case["generatedAndReadBack"]), flush=True)
        receipt["compiledProduct"] = identity(product)
        receipt["inputsUnchanged"] = inputs == [identity(p) for p in tracked]
        assert receipt["inputsUnchanged"]
        receipt["matrixExecutionComplete"] = True
        receipt["generatedAndReadBack"] = sum(c["generatedAndReadBack"] for c in receipt["cases"])
        receipt["allTargetsGeneratedAndReadBack"] = receipt["generatedAndReadBack"] == len(kernels)
    finally:
        (output / "MATRIX.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    return 0 if receipt["allTargetsGeneratedAndReadBack"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
