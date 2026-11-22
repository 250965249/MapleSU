"""Record POSIX baseline failures in the real helper platform TU; no device use."""
from __future__ import annotations
import argparse
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    names = ["runtime/maplesu-sdk/sdk/src/helper/helper_platform_android.cpp",
             "runtime/maplesu-sdk/sdk/src/helper/private/helper_ops.h",
             "runtime/maplesu-sdk/sdk/tests/test_helper_platform_baseline.cpp",
             "runtime/maplesu-sdk/sdk/tests/run_helper_platform_baseline.py"]
    hashes = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in names}
    command = ["docker", "run", "--rm", "--pull", "never", "--network", "none",
               "--mount", f"type=bind,source={ROOT},target=/repo,readonly", "--mount",
               f"type=bind,source={out},target=/out", "--entrypoint", "sh",
               "ghcr.io/ylarod/ddk-min:android15-6.6-20260828", "-c",
               "set -eu\nmkdir -p /system/bin\nln -s /bin/sh /system/bin/sh\n"
               "C=/opt/ddk/clang/clang-r510928\n"
               "$C/bin/clang++ -stdlib=libc++ -std=c++20 -g -O1 -fsanitize=address,undefined "
               "-fno-omit-frame-pointer -Wall -Wextra -Werror -Wl,--wrap=waitpid "
               "-Wl,-rpath,$C/lib/x86_64-unknown-linux-gnu "
               "/repo/runtime/maplesu-sdk/sdk/tests/test_helper_platform_baseline.cpp "
               "-o /out/helper-platform.test\n/out/helper-platform.test\n"]
    result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8",
                            errors="replace", timeout=55)
    stable = hashes == {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in names}
    report = {"schema": "maplesu-helper-platform-baseline/1", "exitCode": result.returncode,
              "recordedAt": datetime.now(timezone.utc).isoformat(),
              "checksPassed": result.stdout.count("PASS "), "checksFailed": result.stdout.count("FAIL "),
              "sourceSha256": hashes, "inputsUnchanged": stable, "command": command,
              "stdout": result.stdout, "stderr": result.stderr, "sanitizers": ["ASan", "UBSan"],
              "evidence": "H", "deviceAccess": False, "productionArtifactsModified": False,
              "sourceTreeReadOnlyDuringTest": True,
              "scope": "Actual POSIX platform TU; ordinary host files, child stdout and waitpid fault injection"}
    (out / "verification.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(result.stdout + result.stderr)
    return result.returncode if stable else 2


if __name__ == "__main__":
    raise SystemExit(main())
