"""Verify retained provider files without the research checkout or network."""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent

def verify(root=ROOT):
    results = {}
    for provider, manifest_name in (("ghostlock", "upstream-manifest.json"), ("dirtyfrag", "source-manifest.json")):
        directory = (root / provider).resolve()
        manifest = json.loads((directory / manifest_name).read_text(encoding="utf-8-sig"))
        checked = set()
        for record in manifest["files"]:
            relative = record["path"]
            original = directory / relative
            path = original.resolve()
            if not path.is_relative_to(directory / "upstream") or path in checked:
                raise ValueError("Invalid or duplicate manifest path: " + relative)
            checked.add(path)
            if original.is_symlink() or not path.is_file():
                raise ValueError("Missing ordinary source file: " + relative)
            content = path.read_bytes()
            if len(content) != record["bytes"] or hashlib.sha256(content).hexdigest() != record["sha256"]:
                raise ValueError("Source identity mismatch: " + relative)
        actual = {path.resolve() for path in (directory / "upstream").rglob("*") if path.is_file()}
        if actual != checked:
            raise ValueError("Unmanifested upstream inputs: " + provider)
        results[provider] = {"files": len(checked), "bytes": sum(record["bytes"] for record in manifest["files"]),
                             "manifestSha256": hashlib.sha256((directory / manifest_name).read_bytes()).hexdigest()}
    return results

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = verify()
    text = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    print(text, end="")
