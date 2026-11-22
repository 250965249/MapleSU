"""Run the real resident B1 gateway without building an SDK, APK or device image."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
sys.dont_write_bytecode = True

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
LOADER = HERE.parent
sys.path.insert(0, str(ROOT / "jailbreak-providers/dirtyfrag/tests"))
from test_l3_arm import definition


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--phase", choices=("red", "green"), default="green")
    parser.add_argument("--ndk-compiler", type=Path)
    parser.add_argument("--layout-header", type=Path, default=ROOT / ".tmp/p1-delivery-r7/gradle-build/manager/jailbreakProviders/l3/l3-staging/boot_sdk_layout.h")
    options = parser.parse_args()
    output = options.out.resolve()
    if output.drive.upper() != "C:":
        parser.error("all generated files must be on C:")
    output.mkdir(parents=True, exist_ok=True)
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    source_path = LOADER / "module/maplesu_boot_sdk.c"
    protocol = ROOT / "runtime/ultra/authorization/request_protocol.h"
    inputs = [source_path, protocol, LOADER / "boot_sdk_build.py", LOADER / "build_root_module.py",
              LOADER / "boot_sdk_abi.h", LOADER / "module/boot_sdk_protocol.h",
              LOADER / "module/boot_sdk_allocator.h", LOADER / "module/policy_hook_dispatch.h",
              LOADER / "policy_hook_abi.h",
              Path(__file__), HERE / "boot_sdk_v2_test.c", HERE / "boot_sdk_v2_bootstrap_test.c",
              HERE / "test_boot_sdk_user_pointer.py", HERE / "boot_sdk_user_pointer_test.c",
              HERE / "test_boot_sdk_image.py", HERE / "boot_sdk_image_test.c"]
    before = {str(path.relative_to(ROOT)): digest(path) for path in inputs}
    receipt = {"phase": options.phase, "source_before": before, "commands": [], "failures": 0}

    def run(command):
        result = subprocess.run([str(item) for item in command], capture_output=True, text=True, timeout=90)
        receipt["commands"].append({"argv": [str(item) for item in command], "returncode": result.returncode,
                                    "stdout": result.stdout, "stderr": result.stderr})
        return result

    spec = importlib.util.spec_from_file_location("boot_sdk_v2_build", LOADER / "boot_sdk_build.py")
    build = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(build)
    if options.phase == "green":
        build.stage_protocol(output)
        assert any((LOADER / name).resolve() == protocol.resolve() for name in build.SOURCES)
        assert "boot_sdk_build.stage_protocol(out_dir)" in (LOADER / "build_root_module.py").read_text(encoding="utf-8")
    else:
        shutil.copyfile(protocol, output / "request_protocol.h")
    receipt["staged_header_sha256"] = digest(output / "request_protocol.h")
    assert receipt["staged_header_sha256"] == digest(protocol)
    source = source_path.read_text(encoding="utf-8")
    scope_start = source.index("struct sdk_legacy_scope {")
    scope_end = source.index("};", scope_start) + 2
    functions = [source[scope_start:scope_end]]
    for name in ("zero", "legacy_scope_begin", "legacy_scope_end", "request_v2_init",
                 "request_v2_close", "request_v2_management", "request_v2", "sdk_execve"):
        part = definition(source, name)
        if part:
            functions.append(part)
        elif name in ("zero", "sdk_execve") or options.phase == "green":
            raise AssertionError("missing production function: " + name)
    (output / "boot_sdk_v2_gateway.inc").write_text("\n".join(functions), encoding="utf-8")
    fixture_path = HERE / "boot_sdk_v2_test.c"
    compiler = Path("C:/msys64/ucrt64/bin/gcc.exe")
    os.environ["PATH"] = str(compiler.parent) + os.pathsep + os.environ.get("PATH", "")
    run([compiler, "--version"])
    binary = output / "gateway.exe"
    flags = ["-DMSU_B1_IMPLEMENTED=1"] if options.phase == "green" else []
    result = run([compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-Wno-unused-function", *flags,
                  "-I" + str(output), "-I" + str(LOADER / "module"), fixture_path, "-o", binary])
    if result.returncode:
        receipt["failures"] += 1
    else:
        result = run([binary, options.phase])
        receipt["gateway"] = json.loads(result.stdout)
        receipt["failures"] += result.returncode != 0
        receipt["host_executable_sha256"] = digest(binary)
    if options.phase == "green":
        (output / "boot_sdk_v2_bootstrap.inc").write_text("\n".join(
            definition(source, name) for name in ("zero", "request_v2_init", "bootstrap")), encoding="utf-8")
        image = "ghcr.io/ylarod/ddk-min:android15-6.6-20260828"
        inspected = run(["docker", "image", "inspect", image, "--format", "{{.Id}}"])
        receipt["docker_image_id"] = inspected.stdout.strip()
        docker = ["docker", "run", "--rm", "--pull", "never", "--network", "none", "--cap-drop", "ALL",
                  "--security-opt", "no-new-privileges", "--mount", f"type=bind,source={ROOT},target=/source,readonly",
                  "--mount", f"type=bind,source={output},target=/output"]
        receipt["bootstrap"] = []
        for environment in (0, 1):
            name = "bootstrap-" + str(environment)
            compiled = run(docker + [image, "cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-Wno-unused-function",
                          "-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-DMSU_BS_ENVIRONMENT=" + str(environment),
                          "-I/output", "-I/source/jailbreak-providers/root-loader/module",
                          "/source/jailbreak-providers/root-loader/tests/boot_sdk_v2_bootstrap_test.c", "-o", "/output/" + name])
            if compiled.returncode:
                receipt["failures"] += 1
                continue
            executed = run(docker + [image, "/output/" + name])
            receipt["failures"] += executed.returncode != 0
            if executed.stdout:
                receipt["bootstrap"].append(json.loads(executed.stdout))
        (output / "legacy-temp").mkdir(exist_ok=True)
        legacy = run(docker + ["--env", "PYTHONDONTWRITEBYTECODE=1", "--env", "TMPDIR=/output/legacy-temp",
                     "--env", "MAPLESU_HOST_CC=/usr/bin/cc", "--workdir", "/source", image,
                     "python3", "-m", "unittest", "jailbreak-providers/root-loader/tests/test_boot_sdk_user_pointer.py",
                     "jailbreak-providers/root-loader/tests/test_boot_sdk_image.py"])
        receipt["failures"] += legacy.returncode != 0
        receipt["legacy_regression_passed"] = legacy.returncode == 0
        if options.ndk_compiler:
            run([options.ndk_compiler, "--version"])
            receipt["android_tu"] = []
            layout = options.layout_header.read_text(encoding="utf-8")
            receipt["layout_source_sha256"] = digest(options.layout_header)
            for environment in (0, 1):
                stage = output / ("android-" + str(environment))
                stage.mkdir(exist_ok=True)
                build.stage_protocol(stage)
                (stage / "boot_sdk_layout.h").write_text(layout.replace("#define MSU_BS_ENVIRONMENT 1",
                    "#define MSU_BS_ENVIRONMENT " + str(environment)), encoding="utf-8")
                obj = stage / "maplesu_boot_sdk.o"
                compiled = run([options.ndk_compiler, "--target=aarch64-linux-gnu", "-ffreestanding", "-nostdlib",
                               "-fno-builtin", "-fno-stack-protector", "-ffixed-x18", "-mgeneral-regs-only",
                               "-mno-outline-atomics", "-fsanitize=kcfi", "-mbranch-protection=pac-ret", "-O2",
                               "-Wall", "-Wextra", "-Werror", "-c", source_path, "-I" + str(stage), "-o", obj])
                receipt["failures"] += compiled.returncode != 0
                receipt["android_tu"].append({"environment": environment, "exit_code": compiled.returncode,
                    "bytes": obj.stat().st_size if obj.is_file() else None,
                    "sha256": digest(obj) if obj.is_file() else None})
        bootstrap = definition(source, "bootstrap")
        assert bootstrap.index("request_v2_init(audit_published)") < bootstrap.index("__atomic_store_n(&state, MSU_BOOT_SDK_READY")
    receipt["source_after"] = {str(path.relative_to(ROOT)): digest(path) for path in inputs}
    receipt["inputs_stable"] = receipt["source_before"] == receipt["source_after"]
    if not receipt["inputs_stable"]:
        receipt["failures"] += 1
    (output / "receipt.json").write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"phase": options.phase, "failures": receipt["failures"],
                      "gateway": receipt.get("gateway"), "receipt": str(output / "receipt.json")}))
    return 1 if receipt["failures"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
