#!/usr/bin/env python3
"""Build a flashable patched kernel / boot image from a kernel profile.

Input : a kernel profile (image-core/profiles/<version>.json) + a variant name.
Output: <variant>-kernel.bin, <variant>-boot.img, <variant>-spec.txt (+ a JSON
        receipt) in the output directory, with every sha256 / size printed.

The patcher is *not* re-implemented here.  This script composes the patch spec
from the profile and then drives the existing image-core based tool
`ProBootSpec` (verifyraw -> applyraw -> rebuild), exactly the sequence the
k7/k15/k18/k20/k21/k22 builds used by hand.  It adds the parts that were
manual before: profile validation, fail-closed orig checking, spec generation,
post-build geometry/replay checks and expected-hash comparison.

Usage
-----
    python image-core/tools/build_flash_kernel.py --variant k7 --out build/flash
    python image-core/tools/build_flash_kernel.py --list
    python image-core/tools/build_flash_kernel.py --check
    python image-core/tools/build_flash_kernel.py --self-test
    python image-core/tools/build_flash_kernel.py --variant k23 --out build/flash --allow-unverified

Options of note
---------------
--base-boot PATH   override profile.base_image.reference_path (a copy of the
                   same bytes; the sha256 is still enforced)
--key KEY          substitute the 48-char probe key in the replacement blobs
                   (ProBootSpec's own key substitution; default: none, bytes
                   are emitted exactly as the profile declares them)
--tool-src PATH    ProBootSpec.java to compile (default: the reference
                   implementation under .analysis/pro-integration-...)
--tool-classes DIR use prebuilt ProBootSpec classes instead of compiling
--no-expected      do not fail when the produced sha256 differs from the
                   profile's recorded artifact (k23 has no recorded artifact)

Exit codes: 0 ok, 2 usage, 3 profile invalid, 4 base image mismatch,
5 record orig missing, 6 tool failure, 7 product mismatch.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import kernel_profile as kp  # noqa: E402

TOOLS_DIR = Path(__file__).resolve().parent
REPO = TOOLS_DIR.parents[1]
DEFAULT_PROFILE = REPO / "image-core" / "profiles" / "6.6.89.json"
DEFAULT_JAR = REPO / "image-core" / "build" / "libs" / "image-core.jar"
DEFAULT_TOOL_SRC = (REPO / ".analysis" / "pro-integration-implementation-20261027"
                    / "tools" / "ProBootSpec.java")
CACHE_DIR = REPO / "build" / "flash-pipeline"

EXIT_OK, EXIT_USAGE, EXIT_PROFILE, EXIT_BASE, EXIT_ORIG, EXIT_TOOL, EXIT_PRODUCT = range(7)


class BuildFailure(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code


# --------------------------------------------------------------------- logging

class Log:
    def __init__(self, quiet: bool = False):
        self.quiet = quiet

    def __call__(self, message: str = "") -> None:
        if not self.quiet:
            print(message, flush=True)

    def step(self, message: str) -> None:
        if not self.quiet:
            print(message, flush=True)


def human(size: int) -> str:
    return f"{size:,}"


# ----------------------------------------------------------------------- tools

def find_java(explicit: str | None) -> Path:
    candidates = []
    if explicit:
        candidates.append(Path(explicit))
    if os.environ.get("JAVA_HOME"):
        candidates.append(Path(os.environ["JAVA_HOME"]) / "bin" / "java.exe")
        candidates.append(Path(os.environ["JAVA_HOME"]) / "bin" / "java")
    if os.environ.get("MAPLESU_JAVA"):
        candidates.append(Path(os.environ["MAPLESU_JAVA"]))
    which = shutil.which("java")
    if which:
        candidates.append(Path(which))
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise BuildFailure(EXIT_TOOL, "java not found; pass --java or set JAVA_HOME")


def find_javac(java: Path, explicit: str | None) -> Path:
    candidates = []
    if explicit:
        candidates.append(Path(explicit))
    candidates.append(java.parent / ("javac.exe" if java.suffix.lower() == ".exe" else "javac"))
    which = shutil.which("javac")
    if which:
        candidates.append(Path(which))
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise BuildFailure(EXIT_TOOL, "javac not found (needed to compile ProBootSpec); pass --javac")


def resolve_tool(args, log: Log) -> tuple[Path, Path, dict]:
    """Return (java, classpath, identity) for the ProBootSpec CLI."""
    java = find_java(args.java)
    jar = Path(args.image_core_jar).resolve()
    if not jar.is_file():
        raise BuildFailure(
            EXIT_TOOL,
            f"image-core jar not found: {jar}\n  build it with: ./gradlew :image-core:jar")

    if args.tool_classes:
        classes = Path(args.tool_classes).resolve()
        if not (classes / "ProBootSpec.class").is_file():
            raise BuildFailure(EXIT_TOOL, f"no ProBootSpec.class under {classes}")
        identity = {"mode": "prebuilt", "classes": str(classes), "source_sha256": None}
    else:
        source = Path(args.tool_src).resolve()
        if not source.is_file():
            raise BuildFailure(
                EXIT_TOOL,
                f"ProBootSpec.java not found: {source}\n"
                "  pass --tool-src, or --tool-classes with prebuilt classes")
        source_sha = kp.sha256_file(source)
        classes = CACHE_DIR / "probootspec" / source_sha[:12]
        if not (classes / "ProBootSpec.class").is_file():
            javac = find_javac(java, args.javac)
            classes.mkdir(parents=True, exist_ok=True)
            command = [str(javac), "-encoding", "UTF-8", "-cp", str(jar),
                       "-d", str(classes), str(source)]
            log(f"  compiling ProBootSpec: {source.relative_to(REPO) if source.is_relative_to(REPO) else source}")
            result = subprocess.run(command, capture_output=True, text=True)
            if result.returncode != 0:
                raise BuildFailure(EXIT_TOOL,
                                   "javac failed:\n" + (result.stderr or result.stdout))
        identity = {"mode": "compiled", "classes": str(classes),
                    "source": str(source), "source_sha256": source_sha}

    classpath = os.pathsep.join([str(jar), str(classes)])
    return java, classpath, identity


JAVA_TMP = CACHE_DIR / "javatmp"


def run_tool(java: Path, classpath: str, argv: list[str]) -> dict:
    JAVA_TMP.mkdir(parents=True, exist_ok=True)
    command = [str(java), f"-Djava.io.tmpdir={JAVA_TMP}", "-cp", classpath, "ProBootSpec"] + argv
    result = subprocess.run(command, capture_output=True, text=True)
    stdout = (result.stdout or "").strip()
    if result.returncode != 0 or not stdout:
        raise BuildFailure(
            EXIT_TOOL,
            "ProBootSpec failed\n  command: " + " ".join(command) +
            f"\n  exit: {result.returncode}\n  stdout: {stdout}\n  stderr: {result.stderr.strip()}")
    last = stdout.splitlines()[-1]
    try:
        return json.loads(last)
    except json.JSONDecodeError:
        raise BuildFailure(EXIT_TOOL, f"ProBootSpec returned non-JSON: {last[:400]}")


# -------------------------------------------------------------------- pipeline

def load_profile(args, log: Log) -> dict:
    path = Path(args.profile).resolve()
    profile = kp.load(path)
    profile["_path"] = str(path)
    profile["_sha256"] = kp.sha256_file(path)

    base_boot = Path(args.base_boot).resolve() if args.base_boot else \
        (REPO / profile["base_image"]["reference_path"])
    boot = None
    if base_boot.is_file():
        boot = base_boot.read_bytes()
    elif args.base_boot:
        raise BuildFailure(EXIT_BASE, f"--base-boot not found: {base_boot}")

    problems = kp.validate(profile, boot=boot)
    if args.base_boot and boot is not None and profile["kernel_version"].get("kernel_sha256"):
        # a caller-supplied base is fine as long as the kernel digest still matches
        header = kp.parse_boot_header(boot)
        kernel = kp.extract_kernel(boot, header["kernel_offset"], header["kernel_size"])
        if kp.sha256_bytes(kernel) != profile["kernel_version"]["kernel_sha256"]:
            problems.append("--base-boot: kernel sha256 does not match the profile")
    if problems:
        raise BuildFailure(EXIT_PROFILE,
                           "profile validation failed:\n  - " + "\n  - ".join(problems))
    return profile, base_boot, boot


def compose_and_check(profile: dict, variant: str, kernel: bytes, log: Log) -> list[dict]:
    records = kp.compose(profile, variant)
    problems = []
    for record in records:
        window = kernel[record["offset"]:record["offset"] + len(record["orig"])]
        if window != record["orig"]:
            problems.append(
                f"{record['id']}@{record['offset']:#x}: orig not present "
                f"(kernel has {window.hex()[:32]}..., spec wants {record['orig'].hex()[:32]}...)")
    if problems:
        raise BuildFailure(EXIT_ORIG,
                           f"variant {variant}: {len(problems)} record(s) do not match the pristine "
                           "kernel:\n  - " + "\n  - ".join(problems))
    for note in kp.overlap_report(records):
        log(f"  overlap   {note[0]} / {note[1]}: {note[2]} B (later record wins)")
    return records


def build(args, log: Log) -> dict:
    profile, base_path, base_boot = load_profile(args, log)
    variant_name = args.variant
    if variant_name not in profile["variants"]:
        raise BuildFailure(EXIT_USAGE,
                           f"unknown variant {variant_name!r}; known: "
                           f"{', '.join(sorted(profile['variants']))}")
    variant = profile["variants"][variant_name]

    version = profile["kernel_version"]
    geometry = profile["boot_geometry"]
    log(f"profile   {Path(profile['_path']).relative_to(REPO) if Path(profile['_path']).is_relative_to(REPO) else profile['_path']}")
    log(f"          schema {profile['schema']} revision {profile.get('revision')} "
        f"sha256 {profile['_sha256'][:16]}")
    log(f"kernel    {version['uname']}")
    log(f"          {version['kernel_sha256']}  {human(version['kernel_size'])} B")
    log(f"variant   {variant_name}  status={variant.get('status')}")
    log(f"          {variant.get('summary', '')}")
    log(f"base      {base_path.name}  "
        f"{profile['base_image']['boot_sha256'][:16]}  {human(geometry['total_size'])} B")

    if base_boot is None:
        raise BuildFailure(EXIT_BASE,
                           f"base boot image not found: {base_path}\n"
                           "  pass --base-boot with a copy of the same bytes")
    header = kp.parse_boot_header(base_boot)
    kernel = kp.extract_kernel(base_boot, header["kernel_offset"], header["kernel_size"])
    if kp.sha256_bytes(kernel) != version["kernel_sha256"]:
        raise BuildFailure(EXIT_BASE,
                           f"kernel inside the base image is {kp.sha256_bytes(kernel)[:16]}..., "
                           f"profile says {version['kernel_sha256'][:16]}...")

    records = compose_and_check(profile, variant_name, kernel, log)
    digest = kp.record_digest(records)
    log(f"records   {len(records)}  digest {digest[:16]}  "
        f"declared bytes {human(sum(len(r['repl']) for r in records))}")

    java, classpath, tool = resolve_tool(args, log)
    tool_label = tool.get("mode") + ("/" + tool["source_sha256"][:12] if tool.get("source_sha256") else "")

    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    spec_path = out_dir / f"{variant_name}-spec.txt"
    kernel_path = out_dir / f"{variant_name}-kernel.bin"
    boot_path = out_dir / f"{variant_name}-boot.img"

    spec_text = kp.render_spec(profile, variant_name, records)
    spec_path.write_text(spec_text, encoding="utf-8", newline="\n")
    spec_sha = kp.sha256_file(spec_path)

    work_root = CACHE_DIR / "work"
    work_root.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix=f"flash-{variant_name}-", dir=work_root))
    pristine = work / "pristine-kernel.bin"
    pristine.write_bytes(kernel)
    try:
        log(f"tool      ProBootSpec [{tool_label}]")

        log("[1/4] verifyraw  spec vs pristine kernel")
        verified = run_tool(java, classpath, ["verifyraw", str(spec_path), str(pristine)])
        if verified.get("originalMatches") != len(records) or verified.get("problems"):
            raise BuildFailure(EXIT_ORIG,
                               f"verifyraw: {verified.get('originalMatches')}/{len(records)} orig, "
                               f"problems={verified.get('problems')!r}")
        log(f"        {verified['originalMatches']}/{len(records)} orig present, "
            f"kernelMatchesSpec={verified.get('kernelMatchesSpec')}")

        log("[2/4] applyraw   spec -> kernel")
        applied = run_tool(java, classpath,
                           ["applyraw", str(spec_path), str(pristine), str(kernel_path)]
                           + ([args.key] if args.key else []))
        if not applied.get("applied"):
            raise BuildFailure(EXIT_ORIG, f"applyraw refused: {applied}")
        if applied.get("outsideSites"):
            raise BuildFailure(EXIT_PRODUCT,
                               f"applyraw touched {applied['outsideSites']} byte(s) outside the "
                               f"declared ranges (first at {applied.get('firstOutside')})")
        log(f"        differingBytes={applied.get('differingBytes')} "
            f"outsideSites={applied.get('outsideSites')} "
            f"sha256={applied.get('outputSha256', '')[:16]}")

        log("[3/4] rebuild    boot image with the patched kernel")
        # image-core's rebuilder refuses to overwrite, so build beside the target and swap in.
        staged_boot = boot_path.with_name(boot_path.name + ".tmp")
        staged_boot.unlink(missing_ok=True)
        rebuilt = run_tool(java, classpath,
                           ["rebuild", str(base_path), str(kernel_path), str(staged_boot)])
        os.replace(staged_boot, boot_path)
        if not rebuilt.get("ramdiskPreserved"):
            log(f"        note: ramdisk {rebuilt.get('sourceRamdiskBytes')} -> "
                f"{rebuilt.get('outputRamdiskBytes')} B")
        log(f"        boot sha256={rebuilt.get('outputSha256', '')[:16]}")

        log("[4/4] post-checks")
        product = boot_path.read_bytes()
        product_header = kp.parse_boot_header(product)
        geometry_problems = kp.same_geometry(product_header, geometry, (
            "magic", "header_version", "header_size", "page_size", "kernel_offset",
            "kernel_size", "ramdisk_size", "second_offset", "total_size"))
        if geometry_problems:
            raise BuildFailure(EXIT_PRODUCT, "boot geometry drifted: " + "; ".join(geometry_problems))
        product_kernel = kp.extract_kernel(product, product_header["kernel_offset"],
                                           product_header["kernel_size"])
        product_kernel_path = work / "product-kernel.bin"
        product_kernel_path.write_bytes(product_kernel)
        replay = run_tool(java, classpath, ["verifyraw", str(spec_path), str(product_kernel_path)])
        expected_repl = declared_replacement_matches(profile, variant_name, records, product_kernel)
        if replay.get("replacementMatches") != expected_repl:
            raise BuildFailure(EXIT_PRODUCT,
                               f"replay: replacementMatches={replay.get('replacementMatches')}, "
                               f"declared-override replay expects {expected_repl}")
        log(f"        boot header/geometry identical to profile; replay "
            f"{replay.get('replacementMatches')}/{expected_repl} replacements present "
            f"({len(records)} records, later records may override earlier ones)")

        kernel_sha = kp.sha256_bytes(product_kernel)
        boot_sha = kp.sha256_file(boot_path)
        expected = (profile.get("validation", {}).get("expected_artifacts", {})
                    .get(variant_name) or {})
        expected_status = "no recorded artifact"
        if expected:
            matches = (expected.get("kernel_sha256") == kernel_sha
                       and expected.get("boot_sha256") == boot_sha)
            expected_status = "MATCH" if matches else "MISMATCH"
            if args.no_expected:
                expected_status += " (ignored)"
            elif not matches:
                raise BuildFailure(
                    EXIT_PRODUCT,
                    f"artifact mismatch for {variant_name}: kernel {kernel_sha[:16]} vs "
                    f"{expected.get('kernel_sha256', '')[:16]}, boot {boot_sha[:16]} vs "
                    f"{expected.get('boot_sha256', '')[:16]}")
    finally:
        if not args.keep_work:
            shutil.rmtree(work, ignore_errors=True)

    receipt = {
        "mode": "build",
        "variant": variant_name,
        "status": variant.get("status"),
        "profile": {
            "path": str(Path(profile["_path"]).relative_to(REPO))
            if Path(profile["_path"]).is_relative_to(REPO) else profile["_path"],
            "sha256": profile["_sha256"],
            "schema": profile["schema"],
            "revision": profile.get("revision"),
            "profile_id": profile.get("profile_id"),
        },
        "kernel_version": {
            "uname": version["uname"],
            "kernel_sha256": version["kernel_sha256"],
            "kernel_size": version["kernel_size"],
        },
        "base_image": {
            "path": str(base_path),
            "boot_sha256": profile["base_image"]["boot_sha256"],
            "kernel_sha256": version["kernel_sha256"],
        },
        "spec": {
            "path": spec_path.name,
            "sha256": spec_sha,
            "records": len(records),
            "record_digest": digest,
            "overlaps": kp.overlap_report(records),
            "record_ids": [record["id"] for record in records],
        },
        "tool": {
            "name": "ProBootSpec",
            "identity": tool,
            "image_core_jar": str(Path(args.image_core_jar).resolve()),
            "image_core_jar_sha256": kp.sha256_file(Path(args.image_core_jar).resolve()),
            "sequence": ["verifyraw", "applyraw", "rebuild", "verifyraw(product)"],
        },
        "artifacts": {
            "kernel": {"path": kernel_path.name, "bytes": kernel_path.stat().st_size,
                       "sha256": kernel_sha},
            "boot": {"path": boot_path.name, "bytes": boot_path.stat().st_size,
                     "sha256": boot_sha},
            "spec": {"path": spec_path.name, "bytes": spec_path.stat().st_size,
                     "sha256": spec_sha},
        },
        "checks": {
            "orig_present": f"{verified['originalMatches']}/{len(records)}",
            "differing_bytes": applied.get("differingBytes"),
            "outside_sites": applied.get("outsideSites"),
            "replacement_matches": replay.get("replacementMatches"),
            "expected_artifact": expected_status,
            "boot_geometry": "match",
        },
        "device_verified": variant_name in ("k7", "k17b", "k20", "k21", "k22"),
    }
    receipt_path = out_dir / f"{variant_name}-build.json"
    receipt_path.write_text(json.dumps(receipt, indent=1) + "\n", encoding="utf-8")

    log("")
    log("artifacts")
    for key, label in (("kernel", "kernel.bin"), ("boot", "boot.img"), ("spec", "spec.txt")):
        item = receipt["artifacts"][key]
        log(f"  {item['path']:<24} {human(item['bytes']):>14} B  {item['sha256']}")
    log(f"  {receipt_path.name:<24} {human(receipt_path.stat().st_size):>14} B  "
        f"(expected artifact: {expected_status})")
    return receipt


def declared_replacement_matches(profile: dict, variant_name: str, records: list[dict],
                                 kernel: bytes) -> int:
    """How many records' replacement bytes must be readable in the product.

    A replacement that a later record overwrote cannot be checked; replaying the
    declared override order is the only honest count (the k21 spec documents the
    same accounting: 16/17 because record 12 is partially rewritten by record 16).
    """
    patched = bytearray(kernel)
    for record in records:
        start, end = record["offset"], record["offset"] + len(record["repl"])
        patched[start:end] = record["repl"]
    count = 0
    for record in records:
        start, end = record["offset"], record["offset"] + len(record["repl"])
        if bytes(patched[start:end]) == record["repl"]:
            count += 1
    return count


# ------------------------------------------------------------------------ modes

def mode_list(args, log: Log) -> int:
    profile, _, _ = load_profile(args, log)
    print(f"{profile.get('profile_id')}  {profile['kernel_version']['uname']}")
    print(f"{'variant':<8} {'status':<22} {'records':>7} {'record digest':<18} expected")
    for name in profile["variants"]:
        summary = kp.variant_summary(profile, name)
        expected = summary["expected"]
        mark = expected.get("kernel_sha256", "")[:12] if expected else "-"
        print(f"{name:<8} {str(summary['status']):<22} {summary['records']:>7} "
              f"{summary['record_digest'][:16]:<18} {mark}")
    return EXIT_OK


def mode_check(args, log: Log) -> int:
    profile, base_path, base_boot = load_profile(args, log)
    print(f"profile  {profile['_path']}")
    print(f"         schema={profile['schema']} revision={profile.get('revision')} "
          f"sha256={profile['_sha256']}")
    print(f"kernel   {profile['kernel_version']['uname']}  "
          f"{profile['kernel_version']['kernel_sha256'][:16]}")
    print(f"base     {base_path}  {'present' if base_boot else 'MISSING (only structural checks ran)'}")
    if base_boot:
        header = kp.parse_boot_header(base_boot)
        kernel = kp.extract_kernel(base_boot, header["kernel_offset"], header["kernel_size"])
        problems = kp.validate(profile, kernel=kernel, boot=base_boot)
        if problems:
            print("FAIL")
            for problem in problems:
                print("  -", problem)
            return EXIT_PROFILE
        print(f"         kernel bytes {human(len(kernel))} ok, geometry/header ok")
    for name in profile["variants"]:
        summary = kp.variant_summary(profile, name)
        print(f"variant  {name:<8} records={summary['records']:>2} "
              f"digest={summary['record_digest'][:16]} status={summary['status']}")
    print("OK")
    return EXIT_OK


def mode_self_test(args, log: Log) -> int:
    profile, _, _ = load_profile(args, log)
    expected_all = profile.get("validation", {}).get("expected_artifacts", {})
    results = []
    for name in profile["variants"]:
        if name not in expected_all:
            results.append((name, "SKIP", "no recorded artifact", "", ""))
            continue
        out = CACHE_DIR / "work" / "self-test" / name
        build_args = argparse.Namespace(**vars(args))
        build_args.variant = name
        build_args.out = str(out)
        try:
            receipt = build(build_args, Log(quiet=True))
            expected = expected_all[name]
            same = (receipt["artifacts"]["kernel"]["sha256"] == expected["kernel_sha256"]
                    and receipt["artifacts"]["boot"]["sha256"] == expected["boot_sha256"])
            results.append((name, "PASS" if same else "FAIL",
                            receipt["artifacts"]["kernel"]["sha256"][:16],
                            expected["kernel_sha256"][:16],
                            receipt["artifacts"]["boot"]["sha256"][:16]))
        except BuildFailure as error:
            results.append((name, "FAIL", str(error).splitlines()[0][:60], "", ""))
        finally:
            shutil.rmtree(out, ignore_errors=True)
    print(f"{'variant':<8} {'result':<6} {'kernel sha256':<18} {'expected':<18} boot sha256")
    failures = sum(verdict == "FAIL" for _, verdict, _, _, _ in results)
    passed = sum(verdict == "PASS" for _, verdict, _, _, _ in results)
    skipped = sum(verdict == "SKIP" for _, verdict, _, _, _ in results)
    for name, verdict, got, want, boot in results:
        print(f"{name:<8} {verdict:<6} {got:<18} {want:<18} {boot}")
    print(f"\n{'PASS' if not failures else 'FAIL'}: {passed}/{passed + failures} variants with a "
          f"recorded artifact reproduce byte-identical output ({skipped} skipped)")
    return EXIT_OK if not failures else EXIT_PRODUCT


# ------------------------------------------------------------------------- main

def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a patched kernel / boot image from a kernel profile.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    parser.add_argument("--profile", default=str(DEFAULT_PROFILE),
                        help="kernel profile JSON (default: image-core/profiles/6.6.89.json)")
    parser.add_argument("--variant", help="variant name, e.g. k7 / k21 / k23")
    parser.add_argument("--out", default=str(REPO / "build" / "flash"),
                        help="output directory (default: build/flash)")
    parser.add_argument("--base-boot", help="override the profile's base boot image path")
    parser.add_argument("--key", help="substitute this 48-char probe key into the replacement blobs")
    parser.add_argument("--java")
    parser.add_argument("--javac")
    parser.add_argument("--image-core-jar", default=str(DEFAULT_JAR))
    parser.add_argument("--tool-src", default=str(args_default_tool_src()),
                        help="ProBootSpec.java to compile")
    parser.add_argument("--tool-classes", help="prebuilt ProBootSpec classes directory")
    parser.add_argument("--no-expected", action="store_true",
                        help="do not fail if the artifact differs from the recorded one")
    parser.add_argument("--allow-unverified", action="store_true",
                        help="permit a variant with status 'candidate' (no recorded artifact)")
    parser.add_argument("--keep-work", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--list", action="store_true", help="list the profile's variants")
    parser.add_argument("--check", action="store_true", help="validate the profile only")
    parser.add_argument("--self-test", action="store_true",
                        help="rebuild every variant with a recorded artifact and compare")
    args = parser.parse_args(argv)

    if not (args.list or args.check or args.self_test or args.variant):
        parser.error("one of --variant / --list / --check / --self-test is required")
    return args


def args_default_tool_src() -> str:
    return os.environ.get("MAPLESU_PROBOOTSPEC_SRC", str(DEFAULT_TOOL_SRC))


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    log = Log(quiet=args.quiet)
    try:
        if args.list:
            return mode_list(args, log)
        if args.check:
            return mode_check(args, log)
        if args.self_test:
            return mode_self_test(args, log)
        profile = kp.load(Path(args.profile).resolve())
        status = (profile["variants"].get(args.variant) or {}).get("status", "")
        if str(status).startswith("candidate") and not (args.allow_unverified or args.no_expected):
            raise BuildFailure(
                EXIT_USAGE,
                f"variant {args.variant} is a candidate (no recorded artifact); "
                "pass --allow-unverified to build it anyway")
        build(args, log)
        return EXIT_OK
    except BuildFailure as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return error.code
    except kp.ProfileError as error:
        print(f"ERROR: profile: {error}", file=sys.stderr)
        return EXIT_PROFILE
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
