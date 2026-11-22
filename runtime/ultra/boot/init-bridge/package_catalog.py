#!/usr/bin/env python3
"""Aggregate actual strict-built bundles; never generate or qualify a module from catalog hints."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil

HASH = re.compile(r"[0-9a-f]{64}")
COMPONENTS = ("targetBoot", "handoff", "bridge", "config", "moduleSymvers", "targetContract",
              "btf", "sessionAbi", "taskProfileAbi", "bundleSources", "ksuInit")


def require(condition, code):
    if not condition:
        raise ValueError(code)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def identity(path):
    data = path.read_bytes()
    return {"bytes": len(data), "sha256": sha(data)}


def same(actual, declared, code):
    require(isinstance(declared, dict) and all(actual.get(k) == declared.get(k) for k in ("bytes", "sha256")), code)


def relative(value):
    require(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9._/-]{1,240}", value)
            and all(x not in ("", ".", "..") for x in value.split("/")), "ULTRA_CATALOG_PATH")
    return value


def selected_path(base, value):
    path = Path(value)
    return path.resolve() if path.is_absolute() else (base / path).resolve()


def selection_sources(selection):
    common = {}
    dependencies = []
    rows = selection.get("inputs")
    require(isinstance(rows, list) and rows, "ULTRA_CATALOG_SOURCE_INPUTS")
    for row in rows:
        name = relative(row["repositoryPath"].replace("\\", "/"))
        actual = row["selected"]
        require(isinstance(actual.get("bytes"), int) and actual["bytes"] > 0 and
                isinstance(actual.get("sha256"), str) and HASH.fullmatch(actual["sha256"]), "ULTRA_CATALOG_SOURCE_IDENTITY")
        source = Path(actual["path"])
        same(identity(source), actual, "ULTRA_CATALOG_SELECTED_SOURCE_CHANGED:" + name)
        dependencies.append((source, {k: actual[k] for k in ("bytes", "sha256")}))
        # A DDK-private header is a per-target ABI input, not a different software generation.
        if row.get("selection") == "native-kernel-private-header":
            continue
        value = {k: actual[k] for k in ("bytes", "sha256")}
        require(name not in common or common[name] == value, "ULTRA_CATALOG_SOURCE_CONFLICT:" + name)
        common[name] = value
    require(common, "ULTRA_CATALOG_SOURCE_GENERATION_EMPTY")
    return dict(sorted(common.items())), dependencies


def inspect_variant(row, plan_root):
    root = selected_path(plan_root, row["bundle"])
    selection_file = selected_path(plan_root, row["sourceSelection"])
    build_file = selected_path(plan_root, row["strictBuild"])
    manifest_file = root / "manifest.json"
    manifest = read_json(manifest_file)
    require(manifest.get("schemaVersion") == 1, "ULTRA_CATALOG_MANIFEST_SCHEMA")
    require(all(isinstance(manifest.get(field), str) and HASH.fullmatch(manifest[field]) for field in
                ("kernelSha256", "targetBootSha256")), "ULTRA_CATALOG_TARGET_IDENTITY")
    files = {"manifest.json": identity(manifest_file)}
    for field in COMPONENTS:
        if field not in manifest:
            continue
        name = relative(manifest[field])
        require(name not in files, "ULTRA_CATALOG_COMPONENT_CONFLICT")
        component = root / name
        require(not component.is_symlink() and component.resolve().is_relative_to(root), "ULTRA_CATALOG_COMPONENT_SYMLINK")
        files[name] = identity(component)
        require(files[name]["sha256"] == manifest.get(field + "Sha256"), "ULTRA_CATALOG_COMPONENT_HASH:" + field)
    require(all(x in manifest for x in ("targetBoot", "bridge", "handoff", "config", "moduleSymvers", "targetContract", "bundleSources")),
            "ULTRA_CATALOG_COMPONENT_REQUIRED")
    sources = read_json(root / manifest["bundleSources"])
    require(sources.get("schemaVersion") == 1 and isinstance(sources.get("inputs"), dict), "ULTRA_CATALOG_BUNDLE_SOURCES")
    for name, item in sources["inputs"].items():
        bundled = item.get("bundledAs")
        if bundled is not None:
            bundled = relative(bundled)
            actual = identity(root / bundled)
            require(actual["sha256"] == item.get("bundledSha256") and actual["bytes"] == item.get("bundledBytes"),
                    "ULTRA_CATALOG_BUNDLED_SOURCE:" + name)
            files[bundled] = actual
    bridge = sources["inputs"]["bridge"]
    same(identity(Path(bridge["path"])), bridge, "ULTRA_CATALOG_ORIGINAL_MODULE_CHANGED")
    selection_identity = identity(selection_file)
    build_identity = identity(build_file)
    build = read_json(build_file)
    require(build.get("exitCode") == 0 and build.get("inputsUnchanged") is True, "ULTRA_CATALOG_STRICT_BUILD")
    require(any(x.get("path", "").replace("\\", "/").endswith("/SOURCE-SELECTION.json") and
                all(x.get(k) == selection_identity[k] for k in ("bytes", "sha256")) for x in build.get("sources", [])),
            "ULTRA_CATALOG_STRICT_SOURCE_SELECTION")
    artifacts = build.get("artifacts", [])
    if isinstance(artifacts, dict):
        artifacts = [artifacts]
    require(any(all(x.get(k) == bridge[k] for k in ("bytes", "sha256")) for x in artifacts),
            "ULTRA_CATALOG_STRICT_MODULE")
    selection = read_json(selection_file)
    common, dependencies = selection_sources(selection)
    for field, provenance_key in (("sessionAbi", "bridgeProvenance"), ("taskProfileAbi", "provenance")):
        if field not in manifest:
            continue
        abi = read_json(root / manifest[field])
        provenance = abi.get(provenance_key, {})
        same({k: bridge[k] for k in ("bytes", "sha256")}, provenance.get("bridge"), "ULTRA_CATALOG_ABI_MODULE:" + field)
        same(selection_identity, provenance.get("sourceSelection"), "ULTRA_CATALOG_ABI_SOURCE:" + field)
        same(build_identity, provenance.get("strictBuild"), "ULTRA_CATALOG_ABI_BUILD:" + field)
        require(abi.get("bundledModuleSha256") == manifest["bridgeSha256"], "ULTRA_CATALOG_ABI_BUNDLED:" + field)
    generation_inputs = {"moduleSources": common, "handoffSha256": manifest["handoffSha256"]}
    generation = sha(encoded(generation_inputs))
    proof = {"schema": "maplesu-init-bridge-variant/1", "manifestSha256": files["manifest.json"]["sha256"],
             "sourceGenerationSha256": generation, "targetBootSha256": manifest["targetBootSha256"],
             "kernelSha256": manifest["kernelSha256"], "sourceSelection": selection_identity,
             "strictBuild": build_identity, "originalModule": {k: bridge[k] for k in ("bytes", "sha256")},
             "bundledModule": files[manifest["bridge"]], "generationInputs": generation_inputs,
             "targetInputs": {field: manifest[field + "Sha256"] for field in
                              ("config", "moduleSymvers", "targetContract", "btf", "sessionAbi", "taskProfileAbi") if field in manifest},
             "artifactQualified": False, "deviceQualified": False}
    dependencies += [(selection_file, selection_identity), (build_file, build_identity),
                     (Path(bridge["path"]), {k: bridge[k] for k in ("bytes", "sha256")})]
    dependencies += [(root / name, value) for name, value in files.items()]
    return {"root": root, "files": files, "proof": proof, "generation": generation, "dependencies": dependencies}


def package(plan_path, output, append=False):
    plan = read_json(plan_path)
    require(plan.get("schema") == "maplesu-init-bridge-catalog-plan/1", "ULTRA_CATALOG_PLAN_SCHEMA")
    rows = plan.get("variants", [])
    require(isinstance(rows, list) and 1 <= len(rows) <= 64, "ULTRA_CATALOG_PLAN_VARIANTS")
    variants = [inspect_variant(row, plan_path.parent) for row in rows]
    generations = {item["generation"] for item in variants}
    require(len(generations) == 1, "ULTRA_CATALOG_MIXED_GENERATIONS")
    manifests = [item["proof"]["manifestSha256"] for item in variants]
    require(len(set(manifests)) == len(manifests), "ULTRA_CATALOG_DUPLICATE_MANIFEST")
    default = plan.get("defaultManifestSha256")
    require(default in manifests, "ULTRA_CATALOG_DEFAULT_REQUIRED")
    chosen = variants[manifests.index(default)]
    if append:
        require(output.is_dir() and identity(output / "manifest.json")["sha256"] == default, "ULTRA_CATALOG_DEFAULT_CHANGED")
        for name, expected in chosen["files"].items():
            same(identity(output / name), expected, "ULTRA_CATALOG_DEFAULT_COMPONENT_CHANGED:" + name)
        require(not (output / "catalog.json").exists() and not (output / "variants").exists()
                and not (output / "catalog-proofs").exists(), "ULTRA_CATALOG_OUTPUT_NOT_FRESH")
    else:
        require(not output.exists(), "ULTRA_CATALOG_OUTPUT_NOT_FRESH")
    # All identities are checked before writing; the index is published last, never a partial choice.
    output.mkdir(parents=True, exist_ok=True)
    entries = []
    for item in variants:
        proof = item["proof"]
        manifest = proof["manifestSha256"]
        prefix = "" if manifest == default else "variants/" + manifest + "/"
        if not append or prefix:
            for name, expected in item["files"].items():
                destination = output / prefix / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(item["root"] / name, destination)
                same(identity(destination), expected, "ULTRA_CATALOG_COPY_CHANGED:" + name)
        proof_path = "catalog-proofs/" + manifest + ".json"
        proof_bytes = encoded(proof)
        (output / "catalog-proofs").mkdir(exist_ok=True)
        (output / proof_path).write_bytes(proof_bytes)
        entries.append({"manifestSha256": manifest, "prefix": prefix, "targetBootSha256": proof["targetBootSha256"],
                        "kernelSha256": proof["kernelSha256"], "sourceGenerationSha256": item["generation"],
                        "proof": proof_path, "proofSha256": sha(proof_bytes)})
    for item in variants:
        for path, expected in item["dependencies"]:
            same(identity(path), expected, "ULTRA_CATALOG_INPUT_CHANGED:" + str(path))
    catalog = {"schema": "maplesu-init-bridge-catalog/1", "sourceGenerationSha256": next(iter(generations)),
               "defaultManifestSha256": default, "variants": sorted(entries, key=lambda x: x["manifestSha256"])}
    (output / "catalog.json").write_bytes(encoded(catalog))
    return catalog


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--append-to-default", action="store_true")
    args = parser.parse_args()
    print(json.dumps(package(args.plan.resolve(), args.output.resolve(), args.append_to_default), sort_keys=True))


if __name__ == "__main__":
    main()
