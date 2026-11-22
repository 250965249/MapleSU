"""Exercise real read-only credential/subject host entries and freeze their evidence."""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[2]
LOADER = ROOT / "jailbreak-providers/root-loader"
TARGETS = (
    "android12-5.10-9465fbb7", "android13-5.15-2f109982", "android14-6.1-71c55acc",
    "android15-6.6-346d51ea", "android15-6.6-ddd760da", "android16-6.12-6679e3fb",
    "android17-6.18-4f47635b",
)
BOOT_FIELDS = {"task_struct.cred", "cred.uid", "cred.euid", "cred.suid", "cred.sgid",
               "cred.usage", "cred.securebits"}
SUBJECT_FIELDS = {"task_struct.cred", "cred.uid", "cred.euid", "cred.group_info",
                  "group_info.usage", "cred.usage"}


def identity(path, raw=None):
    path = Path(path).resolve()
    raw = path.read_bytes() if raw is None else raw
    return {"path": str(path), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def class_versions(path):
    with zipfile.ZipFile(path) as archive:
        return {name: struct.unpack(">H", archive.read(name)[6:8])[0]
                for name in archive.namelist() if name.endswith(".class")}


def btf_credential_oracle(btf):
    """Project the legacy Python parser's actual task -> cred graph, not a named cred copy."""
    def plain(type_id):
        for _ in range(64):
            value = btf.types[type_id]
            if value["kind"] not in (8, 9, 10, 11, 18):
                return value
            type_id = value["size"]
        raise AssertionError("oracle modifier cycle")

    def field(owner, name):
        member = btf.member(owner, name)
        value = plain(member["type"])
        width = 8 if value["kind"] == 2 else value["size"]
        bits = member["bit"]
        width_bits = member["bitfield_bits"] or width * 8
        if value["kind"] == 1:
            encoding = value["int_encoding"]
            bits += (encoding >> 16) & 0xff
            width_bits = member["bitfield_bits"] or (encoding & 0xff)
        assert bits % 8 == 0 and width_bits > 0 and width_bits % 8 == 0, name
        assert bits + width_bits <= owner["size"] * 8, name
        return bits // 8, width_bits // 8, value

    projections = []
    for _, task in btf.structs("task_struct"):
        if not task["size"] or not task["vlen"]:
            continue
        offset, width, pointer = field(task, "cred")
        assert pointer["kind"] == 2 and width == 8, "task.cred pointer"
        cred = plain(pointer["size"])
        assert cred["kind"] == 4 and cred["name"] == "cred" and cred["size"] > 0
        values = {"task_struct.cred": dict(offsetBytes=offset, widthBytes=width,
                                          ownerSizeBytes=task["size"])}
        for name in ("uid", "euid", "suid", "sgid", "usage", "securebits"):
            offset, width, value = field(cred, name)
            if name == "usage":
                for _ in range(16):
                    if value["kind"] == 1:
                        break
                    nested = [member["name"] for member in value["members"]
                              if member["name"] in ("refs", "counter")]
                    assert value["kind"] == 4 and len(nested) == 1, "usage counter"
                    relative, width, value = field(value, nested[0])
                    offset += relative
                assert value["kind"] == 1 and width in (4, 8), "usage integer"
            values["cred." + name] = dict(offsetBytes=offset, widthBytes=width,
                                         ownerSizeBytes=cred["size"])
        projections.append(values)
    assert projections and all(value == projections[0] for value in projections), "task graph ambiguity"
    return projections[0]


def validate_description(description, operation, names, has_btf):
    assert description["schemaVersion"] == 1
    assert description["operation"] == operation
    assert description["implementation"] == "manager/ultrakernel"
    assert set(description["fields"]) == names, sorted(description["fields"])
    for name, field in description["fields"].items():
        offset, width, owner = (field[key] for key in ("offsetBytes", "widthBytes", "ownerSizeBytes"))
        assert type(offset) is int and offset >= 0, name
        assert type(width) is int and width > 0, name
        assert owner is None or (type(owner) is int and offset + width <= owner), name
        assert type(field["parserVersion"]) is int and field["parserVersion"] > 0, name
        if has_btf:
            assert field["source"] == "btf", name
        else:
            assert field["source"].startswith("accessor"), name
        if name in ("task_struct.cred", "cred.group_info"):
            assert width == 8, name
        elif name.endswith(".usage"):
            assert width in (4, 8), name
        else:
            assert width == 4, name


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    out = parser.parse_args().out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(LOADER))
    import build_root_module as builder
    product = builder.layout_product
    paths = [Path(__file__).resolve(), LOADER / "build_root_module.py", LOADER / "legacy_cfi.py",
             LOADER / "policy_hook_build.py", LOADER / "boot_sdk_build.py",
             ROOT / "tools/native_toolchain.py", ROOT / "tools/specgen/HostMain.kt",
             Path(product.__file__)]
    paths += sorted((ROOT / "manager/src/main/java/dev/maplesu/manager/ultrakernel").glob("*.kt"))
    paths += sorted((ROOT / "image-core/src/main/java").rglob("*.java"))
    sources = []
    for path in paths:
        raw = path.read_bytes()
        sources.append(identity(path, raw))
        snapshot = out / "source" / path.relative_to(ROOT)
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        snapshot.write_bytes(raw)
    inputs = [identity(ROOT / "native-inputs/kernels" / target / name)
              for target in TARGETS for name in ("Image", "symbols.tsv")]
    commands, observations, failures = [], [], []
    runtime = None
    original_run = subprocess.run

    def traced_run(command, *positional, **kwargs):
        argv = list(map(str, command))
        row = {"argv": argv, "stdinClosed": kwargs.get("stdin") == subprocess.DEVNULL,
               "inputProvided": kwargs.get("input") is not None}
        if "--kernel" in argv:
            row["kernel"] = identity(argv[argv.index("--kernel") + 1])
        commands.append(row)
        try:
            result = original_run(command, *positional, **kwargs)
        except Exception as error:
            row.update(errorType=type(error).__name__, error=str(error))
            raise
        row.update(exitCode=result.returncode, stdout=result.stdout, stderr=result.stderr)
        return result

    subprocess.run = traced_run
    try:
        java, jar, classpath = product._host_runtime()
        dependencies = [Path(path) for path in classpath.split(os.pathsep)]
        suffix = ".exe" if os.name == "nt" else ""
        compiler = product.cached_jar("org.jetbrains.kotlin", "kotlin-compiler-embeddable", "2.4.20")
        coroutines = product.cached_jar("org.jetbrains.kotlinx", "kotlinx-coroutines-core-jvm", "1.11.0")
        tools = [Path(java).parent / (name + suffix) for name in ("javac", "jar")]
        kotlin_sources = sorted((ROOT / "manager/src/main/java/dev/maplesu/manager/ultrakernel").glob("*.kt"))
        kotlin_sources.append(ROOT / "tools/specgen/HostMain.kt")
        fingerprint = product._fingerprint([Path(java), *kotlin_sources, *dependencies, compiler, coroutines],
                                           product.JVM_FLAGS)
        versions = class_versions(jar)
        image_jars = [path for path in dependencies if path.name.startswith("image-core-")]
        assert len(image_jars) == 1, "source image-core cache"
        image_sources = sorted((ROOT / "image-core/src/main/java").rglob("*.java"))
        image_fingerprint = product._fingerprint([*tools, *image_sources],
                                                ["--release", "17", "-encoding", "UTF-8"])
        image_versions = class_versions(image_jars[0])
        runtime = {"java": identity(java), "jar": identity(jar), "classpath": classpath,
                   "dependencies": [identity(path) for path in dependencies],
                   "buildDependencies": [identity(path) for path in [*tools, compiler, coroutines]],
                   "jvmFlags": product.JVM_FLAGS, "sourceFingerprint": fingerprint,
                   "imageCoreSourceFingerprint": image_fingerprint,
                   "hostClassVersions": versions, "imageCoreClassVersions": image_versions}
        assert jar.name == fingerprint + ".jar", "host source cache identity"
        assert image_jars[0].name == "image-core-" + image_fingerprint + ".jar", "image-core source cache identity"
        assert versions and set(versions.values()) == {61}, "host Java17 class target"
        assert image_versions and set(image_versions.values()) == {61}, "image-core Java17 class target"
        assert product.JVM_FLAGS[product.JVM_FLAGS.index("-jvm-target") + 1] == "17"
        version = subprocess.run([java, "-version"], stdin=subprocess.DEVNULL,
                                 capture_output=True, text=True, encoding="utf-8", errors="replace")
        assert version.returncode == 0, "java version command"
        runtime["javaVersion"] = version.stdout + version.stderr
        shutil.copyfile(jar, out / "host.jar")
        descriptions = {}
        for target in TARGETS:
            row = {"target": target, "operation": "describe-boot-credentials", "passed": False}
            observations.append(row)
            try:
                image_path = ROOT / "native-inputs/kernels" / target / "Image"
                image = image_path.read_bytes()
                row["image"] = identity(image_path, image)
                has_btf = target != TARGETS[0]
                btf_offset = image.find(builder.BTF_MAGIC)
                row["btfMagicOffset"] = btf_offset
                assert (btf_offset >= 0) == has_btf, "actual BTF presence"
                description = product.describe_boot_credentials(image)
                validate_description(description, "PRO_LAYOUT_BOOT_CREDENTIALS_DESCRIBE", BOOT_FIELDS, has_btf)
                if has_btf:
                    oracle = btf_credential_oracle(builder.Btf(image))
                    for name, expected in oracle.items():
                        actual = {key: description["fields"][name][key] for key in expected}
                        assert actual == expected, (name, actual, expected)
                    row["independentBtfOracle"] = oracle
                else:
                    # Independent prior byte observation, used only as this sample's test oracle.
                    assert description["fields"]["cred.securebits"]["offsetBytes"] == 36
                    assert description["fields"]["cred.securebits"]["source"] == "accessor:cap_task_prctl(27)"
                    row["sampleOracle"] = {"cred.securebits": 36, "scope": "test-only prior byte observation"}
                row.update(passed=True, description=description)
                descriptions[target] = description
            except Exception as error:
                row.update(errorType=type(error).__name__, error=str(error))
        for target in (TARGETS[0], TARGETS[3]):
            row = {"target": target, "operation": "describe-subject", "passed": False}
            observations.append(row)
            try:
                image = (ROOT / "native-inputs/kernels" / target / "Image").read_bytes()
                description = product.describe_subject(image)
                validate_description(description, "PRO_LAYOUT_SUBJECT_DESCRIBE", SUBJECT_FIELDS, target != TARGETS[0])
                for name in BOOT_FIELDS & SUBJECT_FIELDS:
                    assert description["fields"][name] == descriptions[target]["fields"][name], name
                row.update(passed=True, description=description)
            except Exception as error:
                row.update(errorType=type(error).__name__, error=str(error))
        calls = [row for row in commands if "--operation" in row["argv"]]
        assert len(calls) == 9, "nine actual read-only host calls"
        for row, target in zip(calls, (*TARGETS, TARGETS[0], TARGETS[3])):
            assert row["stdinClosed"] and not row["inputProvided"], "read-only stdin contract"
            assert row["argv"][row["argv"].index("-cp") + 1] == str(jar) + os.pathsep + classpath
            expected = next(value for value in inputs
                            if Path(value["path"]).parent.name == target and Path(value["path"]).name == "Image")
            assert all(row["kernel"][key] == expected[key] for key in ("bytes", "sha256")), "actual host input"
            assert not any(option in row["argv"] for option in
                           ("--key", "--credential", "--patched-kernel", "--patched-boot", "--receipt"))
    except Exception as error:
        failures.append({"errorType": type(error).__name__, "error": str(error)})
    finally:
        subprocess.run = original_run

    def changed(rows):
        differences = []
        for row in rows:
            try:
                if identity(row["path"]) != row:
                    differences.append(row["path"])
            except OSError:
                differences.append(row["path"])
        return differences

    source_drift, input_drift = changed(sources), changed(inputs)
    passed = sum(row["passed"] for row in observations)
    status = 0 if len(observations) == 9 and passed == 9 and not failures else 1
    if source_drift or input_drift:
        status = 2
    receipt = {"schemaVersion": 1, "capturedAtUtc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "invocation": [sys.executable, *sys.argv], "python": identity(sys.executable),
               "pythonVersion": sys.version, "sources": sources, "sourcesUnchanged": not source_drift,
               "sourceDrift": source_drift, "inputs": inputs, "inputsUnchanged": not input_drift,
               "inputDrift": input_drift, "runtime": runtime, "commands": commands,
               "observations": observations, "setupFailures": failures, "passed": passed,
               "total": len(observations), "exitCode": status, "hostOnly": True,
               "deviceTest": False, "formalArtifactBuilt": False, "partitionWrites": False,
               "scope": "seven credential descriptions and two subject schema regressions; not complete CONFIGURE or NGKI startup"}
    (out / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    lines = [f"exit={status} observations={passed}/{len(observations)}",
             f"sourcesUnchanged={not source_drift} inputsUnchanged={not input_drift}"]
    lines += [f"{'PASS' if row['passed'] else 'FAIL'} {row['target']} {row['operation']}"
              + (" " + row.get("error", "") if not row["passed"] else "") for row in observations]
    lines += [row["errorType"] + ": " + row["error"] for row in failures]
    summary = "\n".join(lines) + "\n"
    (out / "summary.txt").write_text(summary, encoding="utf-8")
    print(summary, end="", flush=True)
    return status


if __name__ == "__main__":
    raise SystemExit(main())
