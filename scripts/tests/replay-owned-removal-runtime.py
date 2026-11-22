#!/usr/bin/env python3
"""Replay frozen removal consumers against the explicitly selected tested core."""
import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import time
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / "docs/dual-mode/impl/_work"
OWNED = EVIDENCE / "2026-11-16/evidence/owned-environment-removal-r1"
R2 = EVIDENCE / "2026-11-15-p2/evidence/embedded-real-lifecycle-r2"
IMAGE = EVIDENCE / "2026-11-15-p2/evidence/owned-recovery-union-r1/green"
RECIPE = EVIDENCE / "2026-11-15-p2/evidence/static-scs-entry-r1/final"
WALKER = EVIDENCE / "2026-11-16/evidence/saved-id-frame-r1/final"
REMOVED = {
    "910e904f5daef2a7440020c1192cb7537cb67d768f8a19350e26c34b14bb7ec4.jar": "r2 is the retained complete merged product jar",
    "image-core-ee5bd65e7596f6359dc03b6cd354bc232bb6832397cc415220737b1786783dbf.jar": "the retained 56 image classes replace this historical build dependency",
}


def read(path):
    return json.loads(pathlib.Path(path).read_text(encoding="utf-8-sig"))


def identity(path):
    path = pathlib.Path(path)
    return {"path": str(path.resolve()), "bytes": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def check(record, actual=None):
    found = identity(actual or record["path"])
    if (record["bytes"], record["sha256"]) != (found["bytes"], found["sha256"]):
        raise ValueError("identity changed: " + found["path"])
    return found


def junit(receipt):
    return next(x["argv"] for x in receipt["commands"] if "org.junit.runner.JUnitCore" in x["argv"])


def class_entries(path, wanted=None):
    path = pathlib.Path(path)
    if path.is_dir():
        result = {}
        for entry in path.rglob("*.class"):
            name = entry.relative_to(path).as_posix()
            if wanted is None or name in wanted:
                result[name] = identity(entry)["sha256"]
        return result
    with zipfile.ZipFile(path) as archive:
        return {x: hashlib.sha256(archive.read(x)).hexdigest() for x in archive.namelist()
                if x.endswith(".class") and (wanted is None or x in wanted)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=pathlib.Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    core = read(OWNED / "core-final/receipt.json")
    public = read(OWNED / "public-final/receipt.json")
    image, recipe, walker = read(IMAGE / "OVERLAY.json"), read(RECIPE / "receipt.json"), read(WALKER / "receipt.json")
    checked = {}
    substitutions = {}
    # Check all retained historical dependencies, not just the entries selected by the JVM.
    for receipt in (core, public):
        for item in receipt.get("frozenInputs", []) + receipt.get("classpathInputs", []):
            path = pathlib.Path(item["path"])
            if path.name in REMOVED:
                substitutions[path.name] = {"historical": item, "reason": REMOVED[path.name]}
                continue
            checked[str(path.resolve())] = check(item)
    source_sets = []
    for name, receipt in (("frozen-consumer-core", core), ("frozen-consumer-public", public),
                          ("frozen-56-image-classes", image), ("tested-static-scs-recipe", recipe),
                          ("tested-saved-id-walker", walker)):
        sources = receipt.get("sources", receipt.get("sourceInputs", []))
        source_sets.append({"scope": name, "sources": [check(x) for x in sources]})
        for item in source_sets[-1]["sources"]:
            checked[item["path"]] = item
    for receipt, folder, key in ((core, OWNED / "core-final/classes", "classes"),
                                 (public, OWNED / "public-final/classes", "classes"),
                                 (image, IMAGE / "classes", "imageClasses")):
        for item in receipt[key]:
            suffix = pathlib.Path(item["path"]).as_posix().split("/classes/", 1)[1]
            checked[str((folder / suffix).resolve())] = check(item, folder / suffix)
    layers = [WALKER / "tested-walker-overlay.jar", RECIPE / "tests.jar", IMAGE / "classes", R2 / "tested-product-overlay.jar"]
    checked[str(layers[0])] = check(walker["overlay"], layers[0])
    checked[str(layers[1])] = check(walker["recipeJar"], layers[1])
    checked[str(layers[3])] = check(core["effectiveRuntime"]["runtime"]["jar"], layers[3]) if "runtime" in core["effectiveRuntime"] else check(recipe["runtime"]["jar"], layers[3])
    fixture = identity(ROOT / "image-core/src/test/resources/lenovo-avb-fixtures.zip")
    checked[fixture["path"]] = fixture
    checked[str(pathlib.Path(__file__).resolve())] = identity(__file__)
    runs = []
    for name, receipt in (("core", core), ("public", public)):
        old = junit(receipt)
        cp = old[old.index("-cp") + 1].split(";")
        new = []
        for entry in cp:
            path = pathlib.Path(entry)
            if path.name in REMOVED or path.resolve() == (IMAGE / "classes").resolve():
                continue
            if path.resolve() == (R2 / "tested-product-overlay.jar").resolve():
                new.extend(str(x.resolve()) for x in layers)
            elif str(path).replace("\\", "/").endswith("MapleSU-P2-owned-removal-r1/final/classes"):
                new.append(str((OWNED / "core-final/classes").resolve()))
            elif str(path).replace("\\", "/").endswith("MapleSU-P2-owned-removal-r1/public-final/classes"):
                new.append(str((OWNED / "public-final/classes").resolve()))
            else:
                new.append(str(path.resolve()))
        for entry in new:
            if not pathlib.Path(entry).exists():
                raise FileNotFoundError(entry)
        providers = {}
        wanted = set().union(*(class_entries(x) for x in layers))
        for entry in new:
            for class_name, digest in class_entries(entry, wanted).items():
                if class_name in wanted and class_name not in providers:
                    providers[class_name] = {"path": entry, "sha256": digest}
        argv = old[:]
        argv[argv.index("-cp") + 1] = ";".join(new)
        runs.append({"name": name, "argv": argv, "cwd": str(ROOT / "manager"), "classpath": new, "firstProviders": providers,
                     "expectedTests": 123 if name == "core" else 13})
    manifest = {"schema": "maplesu-owned-removal-runtime-replay/1", "scope": "frozen consumer and r2, tested current Recipe/Shellcode overlays, frozen 56 Java classes; not a whole-current-tree build",
                "sourceSets": source_sets, "inputs": list(checked.values()), "substitutions": substitutions,
                "runs": runs, "compilations": 0, "deviceOperations": False, "partitionWrites": False}
    manifest_path = args.out / "runtime-manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    results = []
    for run in runs:
        start = time.monotonic()
        process = subprocess.run(run["argv"], cwd=run["cwd"], capture_output=True, text=True, encoding="utf-8", errors="replace")
        (args.out / (run["name"] + ".stdout.log")).write_text(process.stdout, encoding="utf-8")
        (args.out / (run["name"] + ".stderr.log")).write_text(process.stderr, encoding="utf-8")
        passed = re.search(r"OK \((\d+) tests?\)", process.stdout)
        count = int(passed.group(1)) if passed else None
        results.append({"name": run["name"], "exitCode": process.returncode, "tests": count,
                        "elapsedSeconds": round(time.monotonic() - start, 3),
                        "passed": process.returncode == 0 and count == run["expectedTests"]})
    for record in checked.values():
        check(record)
    result = {"schema": "maplesu-owned-removal-replay-result/1", "manifest": identity(manifest_path),
              "runs": results, "passed": all(x["passed"] for x in results), "inputsUnchanged": True,
              "compilations": 0, "deviceOperations": False, "partitionWrites": False}
    (args.out / "RESULT.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
