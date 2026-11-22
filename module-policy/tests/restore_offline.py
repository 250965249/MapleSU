"""Exercise real policy restore in an offline container without touching SELinux."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--save", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="maplesu-policy-restore-") as temporary:
        commands = [
            "echo STAGE_BUILD_LIBSEPOL; mkdir /output/build; cd /output/build; "
            "cc -D_GNU_SOURCE -DHAVE_REALLOCARRAY -Wno-unused-result -I/source/.deps/selinux/libsepol/include "
            "-I/source/.deps/selinux/libsepol/src "
            "-c /source/.deps/selinux/libsepol/src/*.c && ar rcs libsepol.a *.o",
            "echo STAGE_BUILD_RESTORE && c++ -std=c++17 -D_GNU_SOURCE -UNDEBUG -Wall -Wextra -Werror "
            "-Wno-calloc-transposed-args -Wno-unused-function "
            "-fsanitize=address,undefined -fno-omit-frame-pointer "
            "-I/source/module-policy/derived -I/source/module-policy/src "
            "-I/source/runtime/ultra/policy "
            "-I/source/third_party/kernelsu/applied "
            "-I/source/.deps/selinux/libsepol/include "
            "/source/module-policy/tests/restore_tests.cpp /source/module-policy/derived/sepolicy.cpp "
            "/source/module-policy/src/jailbreak_selinux_hide.cpp /source/module-policy/src/ksu_manager_fd.cpp "
            "/source/runtime/ultra/policy/kernel_layout.cpp /source/runtime/ultra/policy/jailbreak_status_layout.cpp "
            "/source/runtime/ultra/policy/module_policy_config.cpp "
            "/source/runtime/ultra/policy/kernel_policy_gate.cpp /source/runtime/ultra/policy/environment_policy.cpp "
            "/output/build/libsepol.a -Wl,--wrap=open -Wl,--wrap=write -Wl,--wrap=close -o /output/probe",
            "echo STAGE_BUILD_POLICY && c++ -std=c++17 -D_GNU_SOURCE -UNDEBUG -Wall -Wextra -Werror "
            "-Wno-calloc-transposed-args -Wno-unused-function "
            "-I/source/module-policy/derived -I/source/module-policy/src "
            "-I/source/runtime/ultra/policy "
            "-I/source/third_party/kernelsu/applied "
            "-I/source/.deps/selinux/libsepol/include "
            "/source/module-policy/tests/policy_tests.cpp /source/module-policy/derived/sepolicy.cpp "
            "/source/module-policy/src/jailbreak_selinux_hide.cpp /source/module-policy/src/ksu_manager_fd.cpp "
            "/source/runtime/ultra/policy/kernel_layout.cpp /source/runtime/ultra/policy/jailbreak_status_layout.cpp "
            "/source/runtime/ultra/policy/module_policy_config.cpp "
            "/output/build/libsepol.a -o /output/policy-tests",
            "echo STAGE_RUN_RESTORE && /output/probe /source/evidence/zygisk-startup-window-20261106/product-v5-policy/actual-policy.bin /output/fixture",
            "mkdir /output/original-tests && /output/policy-tests "
            "/source/evidence/zygisk-startup-window-20261106/product-v5-policy/actual-policy.bin /output/original-tests",
        ]
        name = "maplesu-policy-restore-" + uuid.uuid4().hex[:12]
        command = [
            "docker", "run", "--name", name, "--rm", "--pull", "never", "--network", "none", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--mount", f"type=bind,source={ROOT},target=/source,readonly",
            "--mount", f"type=bind,source={temporary},target=/output",
            "ghcr.io/ylarod/ddk-min:android15-6.6-20260828", "sh", "-c", " && ".join(commands),
        ]
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=180)
        except subprocess.TimeoutExpired as error:
            def text(value):
                return value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value or ""
            result = subprocess.CompletedProcess(command, 124, text(error.stdout), text(error.stderr) + "\nTIMEOUT:180s\n")
            subprocess.run(["docker", "rm", "--force", name], capture_output=True, timeout=20)
        receipt = {"deviceAccess": False, "exitCode": result.returncode,
                   "sanitizers": {"restore": ["ASan", "UBSan"], "originalSuite": []},
                   "sourceSha256": hashlib.sha256((ROOT / "module-policy/src/main.cpp").read_bytes()).hexdigest(),
                   "sourceInputs": {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in (
                       "module-policy/src/main.cpp", "module-policy/tests/restore_tests.cpp",
                       "module-policy/src/jailbreak_selinux_hide.cpp", "module-policy/src/ksu_manager_fd.cpp",
                       "runtime/ultra/policy/kernel_layout.cpp", "runtime/ultra/policy/jailbreak_status_layout.cpp",
                       "runtime/ultra/policy/module_policy_config.cpp", "runtime/ultra/policy/module_policy_config.h",
                       "runtime/ultra/policy/kernel_policy_gate.cpp", "runtime/ultra/policy/environment_policy.cpp")},
                   "stdout": result.stdout, "stderr": result.stderr}
        if args.save:
            args.save.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(receipt, indent=2))
        assert result.returncode == 0


if __name__ == "__main__":
    main()
