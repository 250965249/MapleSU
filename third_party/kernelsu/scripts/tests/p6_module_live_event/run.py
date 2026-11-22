"""Actual Normal hot-install TU, generator replay and Linux rename event regression.

The two explicit boundaries are Android policy/namespace providers and one failing
staged->live rename. KernelSU source, stash/rollback, callbacks and event writer run.
"""
import argparse
import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
parser = argparse.ArgumentParser()
parser.add_argument("--output", type=Path, required=True)
parser.add_argument("--rustc", type=Path, required=True)
parser.add_argument("--linker", type=Path, required=True)
parser.add_argument("--dependencies", type=Path, required=True)
parser.add_argument("--image", required=True)
args = parser.parse_args()
sys.stdout.reconfigure(encoding="utf-8")
here = Path(__file__).resolve().parent
repo = here.parents[4]
out = args.output.resolve()
out.mkdir(parents=True, exist_ok=False)
ksu = repo / "third_party/kernelsu"
work = repo / "docs/dual-mode/impl/_work/2026-11-15-p5-p7/typed-state-chain-20261118"
source = ksu / "applied/userspace/ksud/src"
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
inputs = [ksu / "scripts/patch_defs_module_removal_transaction.py",
          ksu / "scripts/gen_patches.py", ksu / "scripts/ksu_common.py",
          *[source / name for name in ["module.rs", "hot_install.rs",
              "module_install_transaction.rs", "module_removal_transaction.rs", "metamodule.rs"]],
          here / "hot_cases.rs", Path(__file__).resolve()]
initial = {str(p): sha(p) for p in inputs}
commands, cases = [], []
container = None


def run(name, command):
    result = subprocess.run(list(map(str, command)), capture_output=True, timeout=55)
    (out / (name + ".stdout")).write_bytes(result.stdout)
    (out / (name + ".stderr")).write_bytes(result.stderr)
    commands.append({"name": name, "argv": list(map(str, command)), "exitCode": result.returncode})
    if result.returncode:
        raise RuntimeError(name + ": " + result.stderr.decode("utf-8", "replace")[-3000:])
    return result


try:
    # Execute the real full 0027 patch function on its recorded 0026 preimages.
    generated = out / "generator"
    rows = json.loads((work / "normal-remove-boot-recovery/SOURCE-FREEZE.json").read_text(encoding="utf-8"))["files"]
    for row in rows:
        if "/applied/" in row["path"] and row.get("baselinePath"):
            dest = generated / row["path"].split("applied/", 1)[1]
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(Path(row["baselinePath"]).read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
    dest = generated / "userspace/ksud/src/hot_install.rs"
    dest.write_text((work / "normal-metadata-lock/baseline/third_party/kernelsu/applied/userspace/ksud/src/hot_install.rs").read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
    common_spec = importlib.util.spec_from_file_location("ksu_common", ksu / "scripts/ksu_common.py")
    common = importlib.util.module_from_spec(common_spec)
    common_spec.loader.exec_module(common)
    generator = ast.parse((ksu / "scripts/gen_patches.py").read_text(encoding="utf-8"))
    tree_class = next(n for n in generator.body if isinstance(n, ast.ClassDef) and n.name == "Tree")
    scope = {"Path": Path, "C": common}
    exec(compile(ast.Module(body=[tree_class], type_ignores=[]), "actual Tree", "exec"), scope)
    patch = ksu / "scripts/patch_defs_module_removal_transaction.py"
    patch_scope = {}
    exec(compile(patch.read_text(encoding="utf-8"), str(patch), "exec"), patch_scope)
    touched = patch_scope["patch_module_removal_transaction"](scope["Tree"](generated), None)
    for relative in touched:
        assert (generated / relative).read_text(encoding="utf-8") == (ksu / "applied" / relative).read_text(encoding="utf-8"), relative
    assert (source / "module.rs").read_text(encoding="utf-8").count('.env_remove("KSUD_MODULE_LIVE_EVENT")') == 1

    text = (source / "hot_install.rs").read_text(encoding="utf-8")
    anchor = "if let Err(e) = rename(&staged_dir, &live_dir) {"
    assert text.count(anchor) == 1
    (out / "actual_hot_install.rs").write_text(text.replace(anchor,
        "if let Err(e) = crate::publish_rename(&staged_dir, &live_dir) {", 1), encoding="utf-8", newline="\n")
    (out / "hot_cases.rs").write_bytes((here / "hot_cases.rs").read_bytes())
    externs = []
    for name in ["anyhow", "libc", "log"]:
        libraries = list(args.dependencies.glob("lib" + name + "-*.rlib"))
        assert len(libraries) == 1, name
        externs += ["--extern", name + "=" + str(libraries[0])]
    run("compile", [args.rustc, "--edition=2024", "--target", "x86_64-unknown-linux-musl",
        "-C", "linker=" + str(args.linker), "-L", "dependency=" + str(args.dependencies),
        *externs, out / "hot_cases.rs", "-o", out / "hot-cases"])
    started = run("container", ["docker", "run", "--rm", "-d", "--pull", "never", "--network", "none",
        "--read-only", "--tmpfs", "/work:rw,exec,size=32m", "-v", str(out) + ":/tests:ro",
        "--entrypoint", "/bin/sh", args.image, "-c", "exec sleep 180"])
    container = started.stdout.decode().strip()
    nonce = "a" * 32
    for name, env, expected in [
        ("success", {"KSUD_MODULE_LIVE_EVENT": nonce}, 1),
        ("script", {"KSUD_MODULE_LIVE_EVENT": nonce}, 1),
        ("rollback", {"KSUD_MODULE_LIVE_EVENT": nonce, "FIXTURE_RENAME": "failed"}, 0),
        ("restore-failed", {"KSUD_MODULE_LIVE_EVENT": nonce, "FIXTURE_RENAME": "restore-failed"}, 1),
        ("metamodule", {"KSUD_MODULE_LIVE_EVENT": nonce}, 0),
        ("safe-mode", {"KSUD_MODULE_LIVE_EVENT": nonce, "FIXTURE_SAFE_MODE": "1"}, 0),
        ("invalid-script", {"KSUD_MODULE_LIVE_EVENT": nonce}, 0),
        ("old-client", {}, 0),
        ("invalid-nonce", {"KSUD_MODULE_LIVE_EVENT": "bad nonce"}, 0),
    ]:
        command = ["docker", "exec"]
        for key, value in env.items():
            command += ["-e", key + "=" + value]
        result = run(name, [*command, container, "/tests/hot-cases", name])
        stderr = result.stderr.decode("utf-8")
        assert stderr.count("__MAPLESU_MODULE_LIVE_V1__" + nonce + ":alpha\n") == expected, (name, stderr)
        if name == "script":
            assert "SCRIPT_ENV_CLEARED" in result.stdout.decode("utf-8")
        cases.append({"name": name, "eventCount": expected, "passed": True})
    print("PASS generator 5 outputs; actual hot-install TU; 9 Linux causal cases")
finally:
    if container:
        subprocess.run(["docker", "rm", "-f", container], capture_output=True, timeout=30)
    stable = initial == {str(p): sha(p) for p in inputs}
    (out / "RESULT.json").write_text(json.dumps({"passed": len(cases) == 9 and stable,
        "inputs": initial, "sourceInputsStable": stable, "commands": commands, "cases": cases,
        "scope": "Actual full hot_install.rs and full 0027 generator replay. Linux stash/swap/rollback and configured /bin/sh callback. Android policy/namespace boundaries are fixtures; one publication rename fault seam; no formal ksud/APK, device or cross-process authentication result."}, indent=2), encoding="utf-8")
