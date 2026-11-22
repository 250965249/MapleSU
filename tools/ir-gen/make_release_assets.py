"""Build the per-release IR asset set for one or more kernel images.

For each `(release, image, kallsyms dump)` this writes, into `--out`:

  <release>.ir.spec            the v1 spec (P1/P3/P3c) - the shipped format. For
                               6.6.89 it is byte-identical to the published spec,
                               which the tool asserts when `expectRef` is given.
  <release>.ir2.spec           the extended spec: the same three blocks plus
                               R-execve / R-filldir / R-audit / R-cfi, with
                               `#struct.*`, `#abi.*` and `#rule.*` meta.
  <release>.KernelSymbolOffset.json
                               symbols + spans + task_struct offsets, i.e. what
                               `SymbolAnalyze` resolves, for offline adapters.
  <release>.readback.json      per-block readback, dry-run result, engine
                               `--plan` outcome, and the sha256 of every asset.
  index.json                   the registry: release -> assets + results.

The engine is not re-implemented here: `--plan` is executed for real when
`--engine` points at `maplesu-kernel-analyze`, and its verdict is what the
index reports as the plan status.

Usage:
  make_release_assets.py --manifest manifest.json --out <dir> \
      [--engine <maplesu-kernel-analyze>] [--index-only] [--check-only]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import build_ir_spec              # noqa: E402
import resolve_struct_offsets     # noqa: E402
import rules                      # noqa: E402

# The symbol set the C++ SymbolAnalyze resolves; the asset carries the same
# names so a manager-side adapter can be a table lookup.
SYMBOL_NAMES = (
    "_text", "_stext", "_etext", "die", "__drm_puts_coredump", "__drm_printfn_coredump",
    "__do_execve_file", "do_execveat_common", "do_execve_common", "do_execveat",
    "do_execve", "avc_denied", "audit_log_start", "filldir64", "compat_filldir",
    "sys_getuid", "__arm64_sys_getuid", "prctl_get_seccomp", "__cfi_check",
    "__cfi_check_fail", "__cfi_slowpath", "__cfi_slowpath_diag",
    "__ubsan_handle_cfi_check_fail", "__ubsan_handle_cfi_check_fail_abort",
    "report_cfi_failure", "kti_randomize_init", "hkip_check_uid_root",
    "hkip_check_gid_root", "hkip_check_xid_root", "init_task", "init_cred",
    "commit_creds", "prepare_kernel_cred", "aarch64_insn_patch_text",
    "kallsyms_lookup_name", "vectors", "_printk", "printk", "vprintk",
)

RULE_ORDER = rules.RULE_ORDER      # single definition lives in rules.py
ENTRY_BLOCKS = ("P3", "R-execve.entry", "R-filldir.entry", "R-audit.entry")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_spec(path: Path) -> tuple:
    """Spec -> ({meta}, [block dicts]) for re-rendering the extended format."""
    meta, blocks = {}, []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#"):
            if line.startswith("#sym."):
                key, _, value = line[5:].partition("=")
                meta[key] = int(value, 16)
            elif line.startswith("#sig."):
                key, _, value = line[5:].partition("=")
                meta[key] = int(value, 16)
            elif line.startswith("#kernel="):
                meta["kernel"] = line.split("=", 1)[1]
            elif line.startswith("#") and " @0x" in line and line[2:3] != " ":
                pass
            continue
        offset, orig, patched = line.split("|")
        blocks.append({"offset": int(offset), "orig": orig, "patched": patched,
                       "note": "", "id": "?"})
    # Re-attach the id/note comment that precedes each block line.
    pending = None
    index = 0
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line.startswith("#") and " @0x" in line:
            head = line[1:].strip()
            block_id, _, rest = head.partition(" @0x")
            offset_text, _, note = rest.partition("  ")
            pending = (block_id.strip(), note.strip())
        elif line and not line.startswith("#") and index < len(blocks):
            if pending:
                blocks[index]["id"], blocks[index]["note"] = pending
            pending = None
            index += 1
    return meta, blocks


def run_engine(engine: Path, image: Path) -> dict:
    if not engine or not engine.exists():
        return {"ok": False, "error": "engine not provided"}
    completed = subprocess.run([str(engine), "--plan", str(image)],
                               capture_output=True, text=True, timeout=1800)
    output = (completed.stdout or "") + (completed.stderr or "")
    plan = next((line for line in output.splitlines() if line.startswith("PATCH_PLAN_OK")), None)
    replay = next((line for line in output.splitlines() if line.startswith("PLAN_REPLAY_OK")), None)
    error = next((line for line in reversed(output.splitlines())
                  if line.startswith(("SYMBOL_", "PATCH_")) and "OK" not in line), None)
    return {
        "ok": completed.returncode == 0 and plan is not None and replay is not None,
        "returncode": completed.returncode,
        "plan": plan,
        "replay": replay,
        "error": error,
        "edits": int(plan.split("edits=")[1].split()[0]) if plan else None,
        "changedBytes": int(replay.split("changedBytes=")[1]) if replay else None,
    }


def symbol_record(table: rules.SymbolTable) -> dict:
    symbols, missing = {}, []
    for name in SYMBOL_NAMES:
        offset = table.get(name)
        if offset is None:
            missing.append(name)
            continue
        symbols[name] = {"offset": offset, "size": table.span(offset)}
    return {"symbols": symbols, "missing": missing}


def build_release(entry: dict, out_dir: Path, engine: Path | None) -> dict:
    image_path = Path(entry["image"])
    symbols_path = Path(entry["symbols"])
    image = image_path.read_bytes()
    symbols = resolve_struct_offsets.load_symbols(symbols_path)
    table = rules.SymbolTable(symbols)
    release = entry.get("release") or build_ir_spec.kernel_release(image)

    # 1) v1 spec: the untouched generator, so its bytes stay comparable. It is
    #    written straight into the asset directory: it is the compatibility
    #    artifact k21/k22 and the shipped ir-loader spec consume.
    legacy_dir = out_dir
    argv = ["build_ir_spec.py", "--image", str(image_path), "--symbols", str(symbols_path),
            "--out", str(legacy_dir), "--name", release + ".ir.spec"]
    expect_ref = entry.get("expectRef")
    if expect_ref:
        argv += ["--expect-ref", str(entry["expectRef"])]
    saved, sys.argv = sys.argv, argv
    try:
        if build_ir_spec.main() != 0:
            raise SystemExit("build_ir_spec failed for %s" % release)
    finally:
        sys.argv = saved
    legacy_spec = legacy_dir / (release + ".ir.spec")
    legacy_json = legacy_dir / (release + ".ir.spec.json")
    meta, legacy_blocks = parse_spec(legacy_spec)
    legacy_bytes = legacy_spec.read_bytes()

    reference_check = None
    if expect_ref:
        reference_check = {"reference": str(expect_ref),
                           "byteIdentical": legacy_bytes == Path(expect_ref).read_bytes()}

    # 2) task_struct offsets, resolved from the image.
    struct_record = resolve_struct_offsets.resolve(image, symbols, release)
    struct = resolve_struct_offsets.struct_offsets(struct_record)

    # 3) extended rules on top of the same three blocks. The v1 stub already owns
    #    a slice of the cave run, so reserve it before any rule allocates.
    allocator = rules.CaveAllocator(image, table)
    for block in legacy_blocks:
        if len(bytes.fromhex(block["orig"])) > 4:
            allocator.reserve(block["offset"], len(bytes.fromhex(block["orig"])),
                              "P3c.legacy")
    context = rules.RuleContext(image, table, release, struct, allocator)
    outcomes = context.apply(RULE_ORDER)
    rule_blocks = [block for outcome in outcomes for block in outcome.blocks]

    all_blocks = [rules.Block(block["id"], block["offset"],
                              bytes.fromhex(block["orig"]), bytes.fromhex(block["patched"]),
                              block["note"]) for block in legacy_blocks]
    all_blocks += rule_blocks
    all_blocks.sort(key=lambda block: block.offset)
    verification = rules.dry_run(image, all_blocks, ENTRY_BLOCKS)
    verification["caveProblems"] = allocator.verify()

    # 4) v2 spec: same renderer, extra meta, rules appended.
    extra_meta = rules.render_meta(outcomes, struct, release, allocator)
    extra_meta.insert(0, "# rules: " + ", ".join(
        "%s=%s" % (outcome.rule, outcome.status) for outcome in outcomes))
    vectors_at = symbols["vectors"]
    vectors_sig = int.from_bytes(image[vectors_at:vectors_at + 4], "little")
    printk = build_ir_spec.resolve_printk(symbols)
    v2_text = build_ir_spec.render(
        release, symbols,
        [{"id": block.id, "offset": block.offset, "orig": block.orig.hex(),
          "patched": block.patched.hex(), "note": block.note} for block in all_blocks],
        all_blocks[0].offset if all_blocks else 0, b"", vectors_sig, printk, extra_meta)
    v2_spec = out_dir / (release + ".ir2.spec")
    v2_spec.write_text(v2_text, encoding="utf-8", newline="\n")

    # 5) KernelSymbolOffset.json (the offline adapter table).
    symbols_record = symbol_record(table)
    ksym = {
        "schemaVersion": 1,
        "release": release,
        "image": image_path.name,
        "image_sha256": sha256(image),
        "image_bytes": len(image),
        "kallsyms": {
            "num_symbols": len(symbols),
            "relative_base": "0xffffffc080000000",
            "symbols_in_image": len(symbols),
        },
        "symbols": symbols_record["symbols"],
        "missing": symbols_record["missing"],
        "task_struct": {
            "cred_offset": struct["cred"] if struct else None,
            "cred_uid_offset": struct["cred_uid"] if struct else None,
            "seccomp_offset": struct["seccomp"] if struct else None,
        },
        "task_struct_evidence": {
            "getuid": struct_record.get("getuid"),
            "cred_anchor": struct_record["cred"].get("anchor"),
            "cred_uid_rule": struct_record["cred_uid"].get("rule"),
            "seccomp_anchor": struct_record["seccomp"].get("anchor"),
            "uid_min_offset": struct_record["uid_min_offset"],
        },
        "source": {"symbols": symbols_path.name, "symbolFormat": "offset<TAB>type<TAB>name"},
    }
    ksym_path = out_dir / (release + ".KernelSymbolOffset.json")
    ksym_path.write_text(json.dumps(ksym, indent=2, sort_keys=True) + "\n",
                         encoding="utf-8", newline="\n")

    # 6) engine verdict (the real C++ plan, not a simulation).
    engine_result = run_engine(engine, image_path)

    assets = {
        "irSpec": legacy_spec.name,
        "irSpecSha256": sha256(legacy_bytes),
        "irSpecJson": legacy_json.name,
        "ir2Spec": v2_spec.name,
        "ir2SpecSha256": sha256(v2_spec.read_bytes()),
        "kernelSymbolOffset": ksym_path.name,
        "readback": release + ".readback.json",
    }
    readback = {
        "schemaVersion": 1,
        "release": release,
        "image_sha256": sha256(image),
        "image_bytes": len(image),
        "structOffsets": struct,
        "uidMinOffset": struct_record["uid_min_offset"],
        "rules": [outcome.as_dict() for outcome in outcomes],
        "blocks": [block.as_dict() for block in all_blocks],
        "verification": verification,
        "engine": engine_result,
        "reference": reference_check,
        "assets": assets,
        "flashableCandidate": False,
        "note": "dry-run + engine plan only; nothing here was flashed or booted",
    }
    readback_path = out_dir / (release + ".readback.json")
    readback_path.write_text(json.dumps(readback, indent=2, sort_keys=True) + "\n",
                             encoding="utf-8", newline="\n")

    summary = {
        "release": release,
        "image": image_path.name,
        "imageSha256": sha256(image),
        "imageBytes": len(image),
        "symbols": len(symbols),
        "struct": struct,
        "rules": {outcome.rule: outcome.status for outcome in outcomes},
        "ruleDetail": {outcome.rule: outcome.detail for outcome in outcomes},
        "blocks": len(all_blocks),
        "dryRun": verification["ok"],
        "engine": engine_result,
        "byteIdenticalToReference": (reference_check or {}).get("byteIdentical"),
        "assets": assets,
    }
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True,
                        help="JSON list of {label, image, symbols, release?, expectRef?}")
    parser.add_argument("--out", required=True)
    parser.add_argument("--engine", default=None)
    args = parser.parse_args()

    entries = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    engine = Path(args.engine) if args.engine else None

    index = {"schemaVersion": 1, "releases": {}, "order": []}
    failures = []
    for entry in entries:
        summary = build_release(entry, out_dir, engine)
        release = summary["release"]
        index["releases"][release] = {"label": entry.get("label", release), **summary}
        index["order"].append(release)
        ok = summary["dryRun"] and summary["engine"]["ok"]
        print("%-58s rules=%s dryRun=%s engine=%s blocks=%d" % (
            release, "".join(
                {"applied": "+", "not_applicable": "-", "failed": "!"}[status]
                for status in summary["rules"].values()),
            summary["dryRun"], "OK" if summary["engine"]["ok"] else summary["engine"].get("error"),
            summary["blocks"]))
        if not ok:
            failures.append(release)
    (out_dir / "index.json").write_text(
        json.dumps(index, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print("%d/%d releases built cleanly" % (len(index["order"]) - len(failures),
                                            len(index["order"])))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
