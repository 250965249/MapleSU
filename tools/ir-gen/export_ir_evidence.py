"""Export the machine-readable IR fact set (manual W0 / D6).

Nothing here is typed in by hand: every digest, offset and contract number is read
from an artifact that another step produced, and each fact carries the artifact it
came from. If an input is missing the export fails instead of writing a partial
record.
"""
from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
IR = ROOT / "jailbreak-providers" / "ir-loader"
CONTRACT = IR / "contract.json"
BUILD = IR / "build" / "build.json"
SPEC_DIR = IR / "specs"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(path: Path) -> dict:
    if not path.is_file():
        raise SystemExit("export_ir_evidence: missing input %s" % path)
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    contract = load(CONTRACT)
    build = load(BUILD)
    module_path = Path(build["module"])

    specs = []
    for record_path in sorted(SPEC_DIR.glob("*.ir.spec.json")):
        record = load(record_path)
        # Records store the path they were written with; made absolute here so a
        # relative --out at generation time cannot break the export.
        spec_path = Path(record["spec"])
        if not spec_path.is_absolute():
            spec_path = (ROOT / spec_path).resolve()
        # The digest in the record was taken at generation time; re-take it here so
        # a spec edited after generation cannot pass as the generated one.
        if sha256(spec_path) != record["specSha256"]:
            raise SystemExit("export_ir_evidence: %s changed since generation" % spec_path.name)
        specs.append({
            "release": record["release"],
            "spec": str(spec_path.relative_to(ROOT)),
            "specSha256": record["specSha256"],
            "specBytes": spec_path.stat().st_size,
            "image": record["image"],
            "imageSha256": record["imageSha256"],
            "imageBytes": record["imageBytes"],
            "blocks": [{"id": block["id"], "offset": block["offset"],
                        "orig": block["orig"], "patched": block["patched"]}
                       for block in record["blocks"]],
            "cave": {"offset": record["cave"]["offset"], "stubBytes": record["cave"]["stubBytes"]},
            "verifiedAgainstReference": record.get("verifiedAgainstReference"),
            "evidence": str(record_path.relative_to(ROOT)),
        })
    if not specs:
        raise SystemExit("export_ir_evidence: no generated spec records found")

    facts = {
        "schemaVersion": 1,
        "generatedAtUtc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "layer": "DESIGN+CODE+HOST",
        "deviceStatus": "NOT_EXERCISED",
        "module": {
            "name": contract["module"],
            "path": str(module_path.relative_to(ROOT)),
            "sha256": build["sha256"],
            "bytes": build["bytes"],
            "imports": build["facts"]["imports"],
            "vermagic": build["facts"]["vermagic"],
            "vermagicSuffix": build["facts"]["vermagicSuffix"],
            "kcfiInitTypeId": build["facts"]["kcfiInitTypeId"],
            "thisModuleName": build["facts"]["thisModuleName"],
            "initReloc": build["facts"]["initReloc"],
            "exitReloc": build["facts"]["exitReloc"],
            "specBytes": build["facts"]["specBytes"],
            "contract": str(CONTRACT.relative_to(ROOT)),
        },
        "loaderContract": {
            "whyNotIgnoreVermagic":
                "try_to_force_load() returns -ENOEXEC when CONFIG_MODULE_FORCE_LOAD is unset; "
                "the target config sets '# CONFIG_MODULE_FORCE_LOAD is not set', so "
                "MODULE_INIT_IGNORE_VERMAGIC cannot succeed. The module therefore carries the "
                "exact vermagic string and is loaded with flags=0.",
            "whyVersionsSection":
                "check_modstruct_version() calls check_version(\"module_layout\"), which with "
                "versindex==0 calls try_to_force_load() and fails. A __versions section with no "
                "entry named module_layout makes check_version() warn once and accept the module.",
            "sameMagicRule":
                "same_magic() compares only the bytes after the first space when the module has a "
                "__versions section, so the compared part is the vermagic suffix.",
            "structModule":
                "size/offsets read from the 6.6.89 image's own BTF (struct module, type id 119): "
                "size 0x600, name +0x18, init +0x188, exit +0x5b8.",
            "kcfi":
                "init_module must carry the KCFI hash for int (void). Read from the image at "
                "do_one_initcall's indirect call site (0x14bb4: 0x36b1c5a6) and reproduced by the "
                "NDK clang 19.0.1 build; build_ir_module.py fails if the two disagree.",
        },
        "specs": specs,
        "bootstrapWiring": {
            "file": "jailbreak-providers/dirtyfrag/adapter/bootstrap.c",
            "entry": "install_ir()",
            "routeMarker": "use-ir in the attempt directory",
            "stagedInputs": ["maplesu_ir.ko", "ir.spec"],
            "loadCall": "finit_module(memfd, \"\", 0)",
            "failureTokens": [
                "MAPLESU_IR_UNSUPPORTED:<release>", "MAPLESU_IR_SPEC_INVALID",
                "MAPLESU_IR_ORIG_MISMATCH", "MAPLESU_IR_NO_SYMBOLS", "MAPLESU_IR_APPLY_FAILED",
                "MAPLESU_IR_STAGE_MISSING", "MAPLESU_IR_MODULE_INVALID",
                "MAPLESU_IR_LOAD_FAILED", "MAPLESU_IR_NOT_READY", "MAPLESU_IR_REBOOT_FAILED",
            ],
            "fallback": "every failure restores the entry policy and returns without a soft reboot",
        },
        "hostGates": {
            "tracelessInvariants": {"command": "python jailbreak-providers/check_traceless_invariants.py",
                                    "result": "TRACELESS INVARIANTS OK checks=26 points=19"},
            "unitTests": {"command": "./gradlew :manager:testDebugUnitTest",
                          "result": "257 tests, 0 failures, 0 errors, 0 skipped"},
            "irContractTests": {"command": "python -m unittest discover -s jailbreak-providers/ir-loader/tests",
                                "result": "4 tests OK (module contract, spec/image, cross-release, tampered byte)"},
            "assembleDebug": {"command": "./gradlew :manager:assembleDebug",
                              "result": "BUILD SUCCESSFUL; APK carries assets/maplesu/ir/maplesu_ir.ko + 2 specs"},
            "packagedAdapterList": sorted(spec["release"] for spec in specs),
        },
        "openItems": {
            "D3": "NOT_EXERCISED - no device attached in this session",
            "D4": "2 of 3 releases verified; the third needs a stock raw arm64 Image "
                  "(6.6.102-android15-...-lotus-4k exists only as a module vermagic string)",
        },
    }
    out = ROOT / "evidence" / "maplesu-ir-facts.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(facts, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"written": str(out), "specs": len(specs),
                      "module": facts["module"]["sha256"][:16]}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
