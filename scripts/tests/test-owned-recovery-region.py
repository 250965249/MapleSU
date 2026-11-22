#!/usr/bin/env python3
"""Compile only image-core Java sources and record an isolated red/green carrier run."""
import argparse, datetime, hashlib, json, os, pathlib, shutil, subprocess, sys

sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
sys.stderr.reconfigure(encoding="utf-8", errors="backslashreplace")
root = pathlib.Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser()
parser.add_argument("--out", required=True, type=pathlib.Path)
parser.add_argument("--phase", choices=("red", "green"), required=True)
parser.add_argument("--suite", action="append", choices=("BootImageRebuilderTest", "RecoveryRegionRebuilderTest", "RamdiskRebuilderTest", "RamdiskComponentWriterTest", "BootImageEquivalenceTest", "LenovoAvbSignerTest"))
args = parser.parse_args()
args.out = args.out.resolve()
args.out.mkdir(parents=True, exist_ok=False)
classes = args.out / "classes"
classes.mkdir()
shutil.copyfile(__file__, args.out / "runner.py")
names = ["BootImageRebuilderTest", "RecoveryRegionRebuilderTest"]
if args.phase == "green":
    names += ["RamdiskRebuilderTest", "RamdiskComponentWriterTest", "BootImageEquivalenceTest", "LenovoAvbSignerTest"]
if args.suite:
    names = args.suite
sources = sorted((root / "image-core/src/main/java").rglob("*.java"))
sources += [root / "image-core/src/test/java/dev/maplesu/image" / (name + ".java") for name in sorted(set(names + ["BootImageRebuilderTest"]))]
def absolute_identity(path):
    data = path.read_bytes()
    return {"path": str(path.resolve()), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}

def identity(path):
    data = path.read_bytes()
    return {"path": str(path.relative_to(root)), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
receipt = {"phase": args.phase, "recordedAtUtc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
           "scope": "image-core Java only; ordinary synthetic files; no SDK/APK/device", "sourceBefore": [identity(p) for p in sources], "commands": []}
for p in sources:
    dest = args.out / "source" / p.relative_to(root)
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(p, dest)
def run(name, command):
    result = subprocess.run(command, cwd=root, capture_output=True, text=True, encoding="utf-8", errors="replace")
    (args.out / (name + ".stdout.log")).write_text(result.stdout, encoding="utf-8")
    (args.out / (name + ".stderr.log")).write_text(result.stderr, encoding="utf-8")
    receipt["commands"].append({"name": name, "command": command, "exitCode": result.returncode})
    print(name, "exit=" + str(result.returncode), result.stdout.strip()[-350:])
    if result.returncode: print(result.stderr.strip()[-1400:])
    return result.returncode
javac, java = shutil.which("javac"), shutil.which("java")
code = run("compile", [javac, "-J-Duser.language=en", "-J-Dfile.encoding=UTF-8", "-encoding", "UTF-8", "--release", "17", "-d", str(classes)] + [str(p) for p in sources])
if code == 0:
    for name in (names if args.suite or args.phase == "green" else ["RecoveryRegionRebuilderTest"]):
        code = run(name, [java, "-cp", os.pathsep.join([str(classes), str(root / "image-core/src/test/resources")]),
                          "-Dmaplesu.root=" + str(root), "dev.maplesu.image." + name])
        if code: break
receipt["sourceAfter"] = [identity(p) for p in sources]
receipt["sourcesUnchanged"] = receipt["sourceBefore"] == receipt["sourceAfter"]
receipt["exitCode"] = code
execution_path = args.out / "EXECUTION.json"
execution_path.write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
overlay = {"schemaVersion": 1, "kind": "IMAGE_CORE_JAVA_OVERLAY", "exitCode": code,
           "sourcesUnchanged": receipt["sourcesUnchanged"], "sources": [absolute_identity(p) for p in sources],
           "imageClassesDirectory": str(classes),
           "imageClasses": [absolute_identity(p) for p in sorted(classes.rglob("*.class"))],
           "java": absolute_identity(pathlib.Path(java)), "execution": absolute_identity(execution_path),
           "runner": absolute_identity(pathlib.Path(__file__))}
(args.out / "OVERLAY.json").write_text(json.dumps(overlay, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
sys.exit(code)
