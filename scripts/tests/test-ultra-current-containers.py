"""Verify representative boot/init_boot containers with an already source-built host."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/specgen"))
from specgen import bootimg


def identity(path):
    path = Path(path).resolve()
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    return dict(path=str(path), bytes=path.stat().st_size, sha256=digest)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-receipt", type=Path, required=True)
    parser.add_argument("--lz4-dependency", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    sys.path.insert(0, str(args.lz4_dependency.resolve()))
    import lz4
    import lz4.block

    runtime_receipt = json.loads(args.runtime_receipt.read_bytes())
    runtime = runtime_receipt["runtime"]
    assert runtime_receipt["exitCode"] == 0
    for row in runtime_receipt["sources"] + runtime["dependencies"] + [runtime["java"], runtime["jar"]]:
        assert identity(row["path"]) == {key: row[key] for key in ("path", "bytes", "sha256")}, row["path"]
    java = runtime["java"]["path"]
    cp = runtime["jar"]["path"] + os.pathsep + runtime["classpath"]
    tool = [java, "-Xmx768m", "-cp", cp, "dev.maplesu.image.ImageTool"]
    inputs = [ROOT / name for name in (
        "Ace6/boot.img", "Log_Reference/11.13/Boot/一加ace5至尊原boot.img",
        "Boot_Research/北/Y700_4.img", "Ace6/init_boot.img", "Boot_Research/init_boot/init_boot.img")]
    sources = [identity(path) for path in (Path(__file__), Path(bootimg.__file__), args.runtime_receipt)]
    before = [identity(path) for path in inputs]
    receipt = dict(schemaVersion=1, runtime=runtime, sourceBuildReceipt=identity(args.runtime_receipt),
                   sources=sources, inputs=before, lz4Version=lz4.__version__,
                   lz4Sources=[identity(lz4.__file__), identity(lz4.block.__file__)], cases=[],
                   fullSdkOrApkBuild=False, partitionWrites=False, deviceBootTest=False,
                   initBootBridgeInstalled=False)

    def command(argv, folder, label, data=None):
        done = subprocess.run(list(map(str, argv)), input=data,
                              stdin=subprocess.DEVNULL if data is None else None,
                              capture_output=True, timeout=180, cwd=ROOT)
        (folder / (label + ".stdout")).write_bytes(done.stdout)
        (folder / (label + ".stderr")).write_bytes(done.stderr)
        receipt["cases"][-1]["commands"].append(dict(argv=list(map(str, argv)), exitCode=done.returncode,
            stdout=identity(folder / (label + ".stdout")), stderr=identity(folder / (label + ".stderr"))))
        assert done.returncode == 0, (label, done.returncode, done.stderr.decode(errors="replace"))
        return json.loads(done.stdout) if label != "generate" else None

    def component(raw, report, name):
        return raw[report[name + "Offset"]:report[name + "Offset"] + report[name + "Size"]]

    try:
        for index, source in enumerate(inputs):
            folder = out / str(index)
            folder.mkdir()
            case = dict(input=before[index], commands=[], passed=False)
            receipt["cases"].append(case)
            try:
                original = command([*tool, "inspect", source], folder, "inspect-before")
                raw = source.read_bytes()
                with tempfile.TemporaryDirectory(prefix="candidate-", dir=folder) as directory:
                    work = Path(directory)
                    candidate = work / "candidate.img"
                    if original["kernelSize"]:
                        case["role"] = "boot"
                        command([java, "-Xmx768m", "-Djava.io.tmpdir=" + str(work), "-cp", cp,
                            "dev.maplesu.manager.ultrakernel.HostMainKt", "--boot", source,
                            "--out", folder / "patch.spec", "--receipt", folder / "host-receipt.json",
                            "--patched-boot", candidate], folder, "generate", ("Aa1" * 16 + "\n").encode())
                    else:
                        case["role"] = "init_boot-container-only"
                        encoded = work / "ramdisk.encoded"
                        encoded.write_bytes(component(raw, original, "ramdisk"))
                        rebuilt = command([*tool, "rebuild-ramdisk", source, encoded, candidate], folder, "rebuild")
                        assert rebuilt["equivalenceVerified"] and rebuilt["equivalence"]["uncoveredBytes"] == 0
                    after = command([*tool, "inspect", candidate], folder, "inspect-after")
                    actual = candidate.read_bytes()
                    assert original["headerVersion"] == after["headerVersion"]
                    assert original["pageSize"] == after["pageSize"]
                    for name in ("ramdisk", "second", "recoveryDtbo", "dtb"):
                        assert component(raw, original, name) == component(actual, after, name), name
                    if original["kernelSize"]:
                        original_kernel = bootimg.decode(component(raw, original, "kernel"))
                        actual_kernel = bootimg.decode(component(actual, after, "kernel"))
                        expected = bytearray(original_kernel)
                        covered = bytearray(len(expected))
                        records = 0
                        for line in (folder / "patch.spec").read_text().splitlines():
                            if not line or line.startswith("#"):
                                continue
                            offset, old, new = line.split("|")
                            offset, old, new = int(offset, 0), bytes.fromhex(old), bytes.fromhex(new)
                            assert len(old) == len(new) and old
                            assert 0 <= offset <= len(expected) - len(new)
                            assert original_kernel[offset:offset + len(old)] == old
                            expected[offset:offset + len(new)] = new
                            covered[offset:offset + len(new)] = b"\1" * len(new)
                            records += 1
                        assert expected == actual_kernel
                        outside = sum(a != b and not mark for a, b, mark in zip(original_kernel, actual_kernel, covered))
                        host = json.loads((folder / "host-receipt.json").read_bytes())
                        assert outside == host["outsideSites"] == 0 and records == host["sites"]
                        assert hashlib.sha256(actual_kernel).hexdigest() == host["patchedKernelSha256"]
                        assert identity(candidate)["sha256"] == host["patchedBootSha256"]
                        case.update(independentFullKernelReadback=True, outsideSites=outside, sites=records,
                                    compression=original["compression"])
                        del expected, covered, original_kernel, actual_kernel
                    else:
                        assert after["kernelSize"] == 0 and actual == raw
                        case.update(kernelSizeRemainsZero=True, byteIdentical=True, bridgeTest=False)
                    case.update(passed=True, nonKernelComponentsPreserved=True, candidate=identity(candidate),
                                candidateRemovedAfterVerification=True)
                    del raw, actual
            except Exception as error:
                case["error"] = str(error)
            print(source.name + " " + str(case["passed"]), flush=True)
    finally:
        receipt["inputsUnchanged"] = before == [identity(path) for path in inputs]
        receipt["sourcesUnchanged"] = sources == [identity(path["path"]) for path in sources]
        receipt["passed"] = (len(receipt["cases"]) == len(inputs) and all(case["passed"] for case in receipt["cases"])
                             and receipt["inputsUnchanged"] and receipt["sourcesUnchanged"])
        (out / "receipt.json").write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return 0 if receipt["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
