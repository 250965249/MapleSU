"""Exercise actual shared-context preparation without Android or live SELinux."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
IMAGE = "sha256:272ada1e61c525116032246df2a790d1ccec1804b7a9e0b09203c5e650dcb78e"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--save", type=Path)
    parser.add_argument("--candidate-root", type=Path)
    args = parser.parse_args()
    source = args.candidate_root.resolve() if args.candidate_root else ROOT
    inputs = [source / "module-policy/src/main.cpp", source / "module-policy/src/shared_file_contract.h",
              ROOT / "module-policy/tests/shared_context_tests.cpp"]
    hashes = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in inputs}
    with tempfile.TemporaryDirectory(prefix="maplesu-shared-context-") as temporary:
        out = Path(temporary)
        (out / "libsepol.lsan").write_text("leak:policydb_role_cache\n", encoding="utf-8")
        source_main = "/candidate/module-policy/src/main.cpp" if args.candidate_root else "/source/module-policy/src/main.cpp"
        original = (ROOT / "module-policy/tests/policy_tests.cpp").read_text(encoding="utf-8")
        (out / "policy_tests.cpp").write_text(original.replace('"../src/main.cpp"', f'"{source_main}"'), encoding="utf-8")
        include = ("-I/source/module-policy/derived -I/source/module-policy/src "
                   "-I/source/runtime/ultra/policy -I/source/third_party/kernelsu/applied "
                   "-I/source/.deps/selinux/libsepol/include ")
        script = ("set -eu\nmkdir -p /output/build /output/fixture /output/original "
                  "/data/adb/modules/zygisk_lsposed /data/adb/modules/maplesu_zygisk/lib64\n"
                  "chmod 700 /data/adb /data/adb/modules/zygisk_lsposed\ncd /output/build\n"
                  "cc -D_GNU_SOURCE -DHAVE_REALLOCARRAY -Wno-unused-result "
                  "-I/source/.deps/selinux/libsepol/include -I/source/.deps/selinux/libsepol/src "
                  "-c /source/.deps/selinux/libsepol/src/*.c\nar rcs libsepol.a *.o\n"
                  "c++ -std=c++17 -D_GNU_SOURCE -UNDEBUG -Wall -Wextra -Werror "
                  "-Wno-calloc-transposed-args -Wno-unused-function "
                  "-fsanitize=address,undefined -fno-omit-frame-pointer " + include +
                  f"-DMAPLE_POLICY_MAIN='\"{source_main}\"' "
                  "/source/module-policy/tests/shared_context_tests.cpp /source/module-policy/derived/sepolicy.cpp "
                  "/source/runtime/ultra/policy/module_policy_config.cpp /output/build/libsepol.a "
                  "-Wl,--wrap=open -Wl,--wrap=write -Wl,--wrap=close -o /output/shared-probe\n"
                  "LSAN_OPTIONS=suppressions=/output/libsepol.lsan /output/shared-probe "
                  "/source/evidence/zygisk-startup-window-20261106/product-v5-policy/actual-policy.bin /output/fixture\n"
                  "c++ -std=c++17 -D_GNU_SOURCE -UNDEBUG -Wall -Wextra -Werror "
                  "-Wno-calloc-transposed-args -Wno-unused-function " + include +
                  "/output/policy_tests.cpp /source/module-policy/derived/sepolicy.cpp "
                  "/source/module-policy/src/jailbreak_selinux_hide.cpp /source/module-policy/src/ksu_manager_fd.cpp "
                  "/source/runtime/ultra/policy/kernel_layout.cpp /source/runtime/ultra/policy/jailbreak_status_layout.cpp "
                  "/source/runtime/ultra/policy/module_policy_config.cpp /output/build/libsepol.a -o /output/policy-tests\n"
                  "/output/policy-tests /source/evidence/zygisk-startup-window-20261106/product-v5-policy/actual-policy.bin /output/original\n")
        command = ["docker", "run", "--rm", "--pull", "never", "--network", "none", "--cap-drop", "ALL",
                   "--security-opt", "no-new-privileges", "--mount", f"type=bind,source={ROOT},target=/source,readonly",
                   "--mount", f"type=bind,source={out},target=/output"]
        if args.candidate_root:
            command.extend(["--mount", f"type=bind,source={source},target=/candidate,readonly"])
        command.extend([IMAGE, "sh", "-c", script])
        run = subprocess.run(command, capture_output=True, text=True, timeout=180)
    checks = [json.loads(line) for line in run.stdout.splitlines() if line.startswith('{"test":')]
    record = {"sourceSha256": hashes, "deviceAccess": False, "actualCliCallsite": True,
              "simulatedBoundaries": ["selinuxfs"], "sanitizers": ["ASan", "UBSan"],
              "leakSuppression": "existing libsepol policydb_role_cache allocations rebuilt by add_type",
              "exitCode": run.returncode, "checks": checks, "stdout": run.stdout, "stderr": run.stderr,
              "sourceInputsStable": all(hashlib.sha256(path.read_bytes()).hexdigest() == hashes[str(path)] for path in inputs)}
    record["passed"] = run.returncode == 0 and len(checks) >= 7 and record["sourceInputsStable"]
    if args.save:
        args.save.parent.mkdir(parents=True, exist_ok=True)
        args.save.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(record, indent=2))
    assert record["passed"]


if __name__ == "__main__":
    main()
