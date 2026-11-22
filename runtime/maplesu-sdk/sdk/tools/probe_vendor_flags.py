"""Flag-matrix probe for vendor members.

The vendor archive was produced by a different producer than the pinned NDK, so
the same upstream source compiled here can differ in instruction selection.  This
probe compiles one vendor member under a small matrix of optimisation recipes and
reports, for each recipe, how close the result is to the frozen member (function
inventory, call targets, instruction-multiset similarity).

Usage:
    py tools/probe_vendor_flags.py --member 123 [--json out.json]
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

SDK = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SDK / "tools"))
import sdk_common as S  # noqa: E402
import verify_equiv as VE  # noqa: E402

RULES = SDK / "third_party" / "build_rules.json"


def load_rules() -> dict:
    return json.loads(RULES.read_text(encoding="utf-8"))


def member_spec(rules: dict, idx: int) -> tuple[dict, Path]:
    """Find the vendor library rule that owns the member at this ordinal."""
    manifest = json.loads(next(SDK.glob(f"manifest/{idx:04d}_*.json")).read_text(encoding="utf-8"))
    lib = manifest["group"]
    rule = next(r for r in rules["libs"] if r["lib"] == lib)
    source_rel = Path(manifest["sources"][0]).relative_to(f"third_party/{lib}/{rule['version']}")
    src = SDK / "third_party" / lib / rule["version"] / source_rel
    return (rule, src, manifest)


def build(tc, rule: dict, src: Path, out: Path, cflags: list[str], defines: list[str],
          include_dirs: list[str], c_compiler: bool) -> bool:
    compiler = tc.tool("clang") if c_compiler else tc.tool("clang++")
    base = SDK / "third_party" / rule["lib"] / rule["version"]
    argv = [str(compiler), *cflags, *defines]
    for inc in include_dirs:
        argv += ["-I", str(base / inc)]
    argv += ["-c", str(src), "-o", str(out)]
    done = subprocess.run(argv, capture_output=True, text=True)
    if done.returncode != 0:
        print("   compile failed:", done.stderr.strip().splitlines()[-1][:160] if done.stderr else "?")
    return done.returncode == 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--member", type=int, required=True)
    ap.add_argument("--json", default="")
    args = ap.parse_args()

    tc = S.resolve_toolchain()
    rules = load_rules()
    rule, src, manifest = member_spec(rules, args.member)
    cxx = not rule["profile"].startswith("vendor-c-")
    ref_archive = S.read_archive(S.find_freeze().archive)
    ref_member = next(m for m in ref_archive.members if m.idx == args.member)

    base_flags = [f for f in rule["cflags"] if not f.startswith("-O")]
    variants = {
        "shipped(-Oz,-flto)": rule["cflags"],
        "-O2,-flto": [*base_flags, "-O2", "-flto"],
        "-O3,-flto": [*base_flags, "-O3", "-flto"],
        "-O2": [*base_flags, "-O2"],
        "-Oz": [*base_flags, "-Oz"],
        "-Os": [*base_flags, "-Os"],
    }

    work = Path(tempfile.mkdtemp(prefix="flagprobe-", dir=str(SDK)))
    results = {}
    try:
        ref_path = work / "ref.bc"
        ref_path.write_bytes(ref_member.data)
        ref_funcs = VE.disassemble(ref_path)
        for name, flags in variants.items():
            out = work / f"{name.replace('/', '_').replace(',', '_')}.bc"
            if not build(tc, rule, src, out, flags, rule.get("defines") or [],
                         rule.get("includeDirs") or [], c_compiler=not cxx):
                results[name] = {"status": "compile-failed"}
                continue
            try:
                new_funcs = VE.disassemble(out)
            except Exception as exc:  # noqa: BLE001
                results[name] = {"status": "disasm-failed", "error": str(exc)[:120]}
                continue
            cmp = VE.compare(ref_funcs, new_funcs)
            results[name] = {"status": "ok", **{k: cmp[k] for k in
                             ("ref_functions", "new_functions", "matched", "call_target_match",
                              "seq_mean", "bag_mean", "bag_min") if k in cmp},
                             "missing": len(cmp["missing"]), "extra": len(cmp["extra"])}
        print(f"member {args.member} {manifest['name']}  source {S.rel(src)}")
        for name, r in results.items():
            if r.get("status") == "ok":
                print(f"  {name:22s} matched={r['matched']}/{r['ref_functions']} "
                      f"calls={r['call_target_match']}/{r['matched']} "
                      f"bag_mean={r['bag_mean']:.4f} bag_min={r['bag_min']:.4f}")
            else:
                print(f"  {name:22s} {r['status']}")
        if args.json:
            Path(args.json).write_text(json.dumps(
                {"member": args.member, "name": manifest["name"], "results": results},
                indent=1), encoding="utf-8")
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
