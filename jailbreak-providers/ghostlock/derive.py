"""Produce a hash-checked source overlay; never modify retained upstream bytes."""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def derive(output, root=ROOT):
    manifest = json.loads((root / "upstream-manifest.json").read_text(encoding="utf-8"))
    records = {item["path"]: item for item in manifest["files"]}
    output = Path(output).resolve()
    if output.is_relative_to(root.resolve()):
        raise ValueError("Overlay output must be outside retained provider sources")
    result = {}
    transforms = {
        "src/core/main.cpp": ("int main(int argc, char **argv)", "int maplesu_ghostlock_upstream_main(int argc, char **argv)"),
        "src/core/attack/ops.cpp": None,
    }
    staged = {}
    for relative, rename in transforms.items():
        source = root / "upstream" / relative
        content = source.read_bytes()
        record = records["upstream/" + relative]
        if hashlib.sha256(content).hexdigest() != record["sha256"] or len(content) != record["bytes"]:
            raise ValueError("Overlay source identity mismatch: " + relative)
        text = content.decode("utf-8")
        if rename:
            if text.count(rename[0]) != 1:
                raise ValueError("Entry signature changed")
            text = text.replace(*rename)
        else:
            start = "    void write_root_script(void) {"
            end = "    /* Find a task through perf sample records. */"
            if text.count(start) != 1 or text.count(end) != 1:
                raise ValueError("Script boundary changed")
            left, right = text.index(start), text.index(end)
            if right <= left:
                raise ValueError("Script boundary order changed")
            text = text[:left] + "    /* MapleSU downstream is defined in adapter/handoff.cpp. */\n\n" + text[right:]
        data = text.encode("utf-8")
        staged[relative] = data
        result[relative] = {"upstreamSha256": record["sha256"], "derivedSha256": hashlib.sha256(data).hexdigest()}
    # Validate all inputs before publishing any generated source.
    for relative, data in staged.items():
        target = output / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists() or target.read_bytes() != data:
            target.write_bytes(data)
    (output / "overlay.json").write_text(json.dumps({"upstreamCommit": manifest["upstreamCommit"], "files": result}, indent=2) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    print(json.dumps(derive(parser.parse_args().output), indent=2))
