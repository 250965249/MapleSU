import argparse
import hashlib
import json
from pathlib import Path
import re
import tempfile
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]


def public_inputs(root):
    busybox = json.loads((root / "third_party/busybox/SOURCE.json").read_text(encoding="utf-8"))
    records = [busybox]
    provider = root / "jailbreak-providers/dirtyfrag"
    manifest = json.loads((provider / "source-manifest.json").read_text(encoding="utf-8-sig"))
    for item in manifest["files"]:
        if item["path"].startswith("upstream/stock-artifacts/ko/") and item["path"].endswith(".ko"):
            records.append({
                "repository": item["upstreamRepository"],
                "commit": item["sourceCommit"],
                "source_path": item["sourcePath"],
                "path": "jailbreak-providers/dirtyfrag/" + item["path"],
                "sha256": item["sha256"], "bytes": item["bytes"],
                "license_status": item["licenseStatus"],
            })
    return records


def source_url(record):
    repository = record["repository"]
    if not re.fullmatch(r"https://github.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("Expected a fixed GitHub repository")
    if not re.fullmatch(r"[a-f0-9]{40}", record["commit"]):
        raise ValueError("Expected a full source commit")
    source = record["source_path"]
    if source.startswith("/") or ".." in source.split("/"):
        raise ValueError("Invalid upstream source path")
    return repository.replace("https://github.com/", "https://raw.githubusercontent.com/") + "/" + record["commit"] + "/" + source


def verify_bytes(data, record):
    if len(data) != record["bytes"] or hashlib.sha256(data).hexdigest() != record["sha256"]:
        raise ValueError("Pinned input digest or size mismatch: " + record["path"])


def prepare(root, record, check_only=False):
    root = root.resolve()
    target = root / record["path"]
    if target.is_symlink() or not target.resolve().is_relative_to(root):
        raise ValueError("Input path leaves the workspace: " + record["path"])
    if target.exists():
        verify_bytes(target.read_bytes(), record)
        return "verified"
    if check_only:
        raise ValueError("Missing pinned input: " + record["path"])
    with urlopen(source_url(record), timeout=45) as response:
        data = response.read(record["bytes"] + 1)
    verify_bytes(data, record)
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=target.parent, delete=False) as output:
        temporary = Path(output.name)
        output.write(data)
    try:
        temporary.replace(target)
    finally:
        temporary.unlink(missing_ok=True)
    return "downloaded"


def main():
    parser = argparse.ArgumentParser(description="Verify retained native build inputs and prepare pinned BusyBox/provider inputs.")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="Verify existing inputs without downloading")
    mode.add_argument("--refresh-manifest", action="store_true", help="Record updated identities for the listed retained inputs")
    args = parser.parse_args()
    results = []
    for record in public_inputs(ROOT):
        status = prepare(ROOT, record, args.check)
        results.append({"path": record["path"], "status": status, "sha256": record["sha256"],
                        "source": source_url(record)})
    policy = json.loads((ROOT / "release/source-policy.json").read_text(encoding="utf-8"))
    from release_audit import native_inputs
    retained = native_inputs(ROOT, policy)
    if args.refresh_manifest:
        for record in retained:
            path = ROOT / record["path"]
            if path.is_symlink() or not path.resolve().is_relative_to(ROOT):
                raise ValueError("Input path leaves the workspace: " + record["path"])
            data = path.read_bytes()
            record.update(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
        path = ROOT / policy["native_input_manifest"]
        manifest = json.loads(path.read_text(encoding="utf-8"))
        sdk = json.loads((ROOT / "runtime/maplesu-sdk/SDK-RELEASE.json").read_text(encoding="utf-8"))
        manifest.update(files=retained, sdk_build_id=sdk["sdkBuildId"],
                        sdk_archive_sha256=sdk["archive"]["sha256"], helper_sha256=sdk["helper"]["sha256"],
                        policy_backend_sha256=sdk["environmentPolicyBoot"]["backend"]["sha256"])
        path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")
    for record in retained:
        prepare(ROOT, record, check_only=True)
    report = {"public_inputs": results, "retained_inputs_verified": len(retained),
              "ultra_sdk_included": any(r["path"] == "runtime/maplesu-sdk/lib/arm64-v8a/libkernel_module_kit_static.a"
                                        for r in retained)}
    destination = ROOT / "build/native-inputs.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
