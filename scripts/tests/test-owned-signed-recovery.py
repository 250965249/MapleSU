#!/usr/bin/env python3
"""Narrowly compile the signed owned-removal fix and replay its consumers."""
import argparse
import hashlib
import json
import pathlib
import re
import shutil
import subprocess
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
BASE = ROOT / "docs/dual-mode/impl/_work/2026-11-16/evidence/owned-removal-current-core-r1"
OWNED = ROOT / "docs/dual-mode/impl/_work/2026-11-16/evidence/owned-environment-removal-r1"


def read(path):
    return json.loads(pathlib.Path(path).read_text(encoding="utf-8-sig"))


def identity(path):
    path = pathlib.Path(path)
    return {"path": str(path.resolve()), "bytes": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def verify(record):
    actual = identity(record["path"])
    if (record["bytes"], record["sha256"]) != (actual["bytes"], actual["sha256"]):
        raise ValueError("identity changed: " + record["path"])
    return actual


def class_first(name, entries):
    for entry in entries:
        path = pathlib.Path(entry)
        if path.is_dir():
            candidate = path / name
            if candidate.is_file():
                return identity(candidate)
        else:
            with zipfile.ZipFile(path) as archive:
                if name in archive.namelist():
                    data = archive.read(name)
                    return {"path": str(path), "member": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    raise FileNotFoundError(name)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=pathlib.Path, required=True)
    parser.add_argument("--writer-receipt", type=pathlib.Path, required=True)
    parser.add_argument("--recovery-receipt", type=pathlib.Path, required=True)
    parser.add_argument("--recovery-overlay", type=pathlib.Path)
    args = parser.parse_args()
    args.out = args.out.resolve()
    args.writer_receipt = args.writer_receipt.resolve()
    args.recovery_receipt = args.recovery_receipt.resolve()
    if args.recovery_overlay:
        args.recovery_overlay = args.recovery_overlay.resolve()
    args.out.mkdir(parents=True, exist_ok=False)
    base = read(BASE / "green-final/runtime-manifest.json")
    writer, recovery = read(args.writer_receipt), read(args.recovery_receipt)
    inputs = {}
    for receipt in (writer, recovery):
        for record in receipt["sources"] + receipt["classes"]:
            inputs[record["path"]] = verify(record)
    writer_jar = pathlib.Path(writer["writerOverlay"]["path"])
    inputs[str(writer_jar)] = verify(writer["writerOverlay"])
    recovery_classes = pathlib.Path(recovery["classes"][0]["path"])
    while recovery_classes.name != "classes":
        recovery_classes = recovery_classes.parent
    recovery_runtime = recovery_classes
    if args.recovery_overlay:
        actual = identity(args.recovery_overlay)
        expected = recovery["overlay"]
        if (actual["bytes"], actual["sha256"]) != (expected["bytes"], expected["sha256"]):
            raise ValueError("retained recovery overlay differs")
        inputs[actual["path"]] = actual
        recovery_runtime = args.recovery_overlay
    for record in base["inputs"]:
        # Live sources intentionally replaced by this separately recorded generation.
        if record["path"] in {x["path"] for x in writer["sources"] + recovery["sources"]}:
            continue
        if record["path"].endswith(("StockOriginalResolver.kt", "NativeInstallTransaction.kt", "replay-owned-removal-runtime.py")):
            continue
        inputs[record["path"]] = verify(record)
    sources = [ROOT / "manager/src/main/java/dev/maplesu/manager/installer" / name for name in
               ("StockOriginalResolver.kt", "NativeInstallTransaction.kt")]
    probe = ROOT / "scripts/tests/fixtures/OwnedSignedRecoveryRedMain.java"
    fixture = ROOT / "image-core/src/test/resources/lenovo-avb-fixtures.zip"
    for source in sources + [probe, fixture, pathlib.Path(__file__)]:
        inputs[str(source)] = identity(source)
    for source in sources + [probe]:
        target = args.out / "source" / source.relative_to(ROOT)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    layers = [str(recovery_runtime), str(writer_jar)]
    cp = layers + base["runs"][0]["classpath"]
    old = read(OWNED / "core-final/receipt.json")["commands"][0]["argv"]
    compile_argv = [x for x in old if not x.endswith(".kt")]
    compile_argv[compile_argv.index("-classpath") + 1] = ";".join(cp)
    compile_argv[compile_argv.index("-d") + 1] = str(args.out / "classes")
    compile_argv = [("-Xfriend-paths=" + ",".join(cp)) if x.startswith("-Xfriend-paths=") else x for x in compile_argv]
    compile_argv.extend(str(args.out / "source" / x.relative_to(ROOT)) for x in sources)
    receipt = {"schema": "maplesu-owned-signed-recovery/1", "inputs": list(inputs.values()),
               "baseManifest": identity(BASE / "green-final/runtime-manifest.json"),
               "writerReceipt": identity(args.writer_receipt), "recoveryReceipt": identity(args.recovery_receipt),
               "commands": [], "compiledProductionFiles": 2, "SDKOrAPKBuild": False,
               "deviceOperations": False, "partitionWrites": False}

    def run(name, argv):
        result = subprocess.run(argv, cwd=ROOT / "manager", capture_output=True, text=True, encoding="utf-8", errors="replace")
        (args.out / (name + ".stdout.log")).write_text(result.stdout, encoding="utf-8")
        (args.out / (name + ".stderr.log")).write_text(result.stderr, encoding="utf-8")
        command = {"name": name, "argv": argv, "cwd": str(ROOT / "manager"), "exitCode": result.returncode}
        count = re.search(r"OK \((\d+) tests?\)", result.stdout)
        if count:
            command["tests"] = int(count.group(1))
        receipt["commands"].append(command)
        print(name, result.returncode, command.get("tests", ""), flush=True)
        return result.returncode

    code = run("compile", compile_argv)
    if code == 0:
        cp.insert(0, str(args.out / "classes"))
        run("signed-probe", [base["runs"][0]["argv"][0], "-Xmx256m", "-cp", ";".join(cp),
            str(args.out / "source" / probe.relative_to(ROOT)), str(args.out / "work"), str(fixture)])
        for original in base["runs"]:
            argv = original["argv"][:]
            entries = original["classpath"][:]
            position = 1 if original["name"] == "public" else 0
            entries[position:position] = [str(args.out / "classes")] + layers
            argv[argv.index("-cp") + 1] = ";".join(entries)
            run(original["name"], argv)
        names = ["dev/maplesu/manager/ultrakernel/UltraKernelStructOffsets.class",
                 "dev/maplesu/manager/ultrakernel/UltraKernelRecipe.class", "dev/maplesu/manager/ultrakernel/UltraKernelOriginalRecovery.class",
                 "dev/maplesu/image/BootImageRebuilder.class", "dev/maplesu/manager/installer/StockOriginalResolver.class",
                 "dev/maplesu/manager/installer/NativeInstallTransaction.class"]
        receipt["firstDefinitions"] = {name: class_first(name, cp) for name in names}
        receipt["classes"] = [identity(x) for x in (args.out / "classes").rglob("*.class")]
    receipt["inputsUnchanged"] = all(verify(x) for x in inputs.values())
    receipt["passed"] = all(x["exitCode"] == 0 for x in receipt["commands"])
    (args.out / "receipt.json").write_text(json.dumps(receipt, indent=2), encoding="utf-8")
    return 0 if receipt["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
