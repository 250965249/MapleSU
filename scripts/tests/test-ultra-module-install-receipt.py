"""Offline host regression for the production JNI module-install receipt.

Requires an existing local DDK image and an NDK; never downloads an image.
SDK callbacks are fixtures, while JNI serialization and call admission are real.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--ndk", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    build = args.build.resolve()
    headers = build / "host-include"
    (headers / "sys").mkdir(parents=True, exist_ok=True)
    shutil.copyfile(args.ndk / "toolchains/llvm/prebuilt/windows-x86_64/sysroot/usr/include/jni.h",
                    headers / "jni.h")
    (headers / "sys/system_properties.h").write_text(
        '#pragma once\n#define PROP_VALUE_MAX 92\nextern "C" int __system_property_get(const char*, char*);\n',
        encoding="utf-8")
    script = """set -eu
ulimit -c 0
cd /case
C=/opt/ddk/clang/clang-r510928
$C/bin/clang++ -std=c++20 -O1 -stdlib=libc++ -pthread -fexceptions \\
 -ffunction-sections -fdata-sections -Wall -Wextra -Werror \\
 -I/case/host-include -I/repo/runtime/ultra/bridge \\
 -isystem /repo/runtime/maplesu-sdk/include \\
 -isystem /repo/runtime/ultra/third_party/include -isystem /repo/runtime/ultra/third_party/cJSON \\
 -Wl,--gc-sections -Wl,--wrap=close -Wl,-rpath,$C/lib/x86_64-unknown-linux-gnu \\
 /repo/runtime/tests/pro_module_install_receipt_test.cpp \\
 /repo/runtime/ultra/bridge/sdk_call_scope.cpp /repo/runtime/ultra/third_party/cJSON/cJSON.cpp \\
 -o module-install-receipt.test
timeout 12s ./module-install-receipt.test
echo 'PASS normal and once: accepted, callback declined, SDK error, missing worker receipt'
"""
    sources = [
        "runtime/tests/pro_module_install_receipt_test.cpp",
        "runtime/ultra/bridge/native_lib_ultra.cpp",
        "runtime/ultra/bridge/sdk_call_scope.cpp",
        "runtime/ultra/bridge/sdk_call_scope.h",
        "runtime/ultra/third_party/cJSON/cJSON.cpp",
        "runtime/maplesu-sdk/include/third_party/____DO_NOT_EDIT____/private_maplesu_api_runtime_helper.h",
    ]
    hashes = {path: hashlib.sha256((root / path).read_bytes()).hexdigest() for path in sources}
    result = subprocess.run([
        "docker", "run", "--rm", "--pull=never", "--network", "none",
        "--mount", f"type=bind,source={root},target=/repo,readonly",
        "--mount", f"type=bind,source={build},target=/case", "--entrypoint", "sh",
        "ghcr.io/ylarod/ddk-min:android15-6.6-20260828", "-c", script,
    ], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
    output = result.stdout + result.stderr
    (build / "module-install-receipt.log").write_text(output, encoding="utf-8")
    (build / "module-install-receipt.json").write_text(json.dumps({
        "passed": result.returncode == 0, "exitCode": result.returncode,
        "sourceHashes": hashes, "productionJniAndAdmission": True,
        "sdkCallbacks": "fixtures; archived fork transport is not exercised",
        "network": "none", "kernelExecuted": False, "deviceVerification": False,
    }, indent=2) + "\n", encoding="utf-8")
    print(output, end="")
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
