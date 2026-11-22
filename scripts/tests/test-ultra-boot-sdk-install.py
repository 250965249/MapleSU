"""Run the production boot SDK session/install state machines on the host JVM."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "tools/specgen"))
import native_toolchain
from specgen.product import cached_jar


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    product = ROOT / "manager/build/intermediates/built_in_kotlinc/debug/compileDebugKotlin/classes"
    deps = [cached_jar(*item) for item in [
        ("org.jetbrains.kotlin", "kotlin-stdlib", "2.4.20"), ("org.jetbrains", "annotations", "13.0"),
        ("org.jetbrains.kotlinx", "kotlinx-coroutines-core-jvm", "1.11.0"),
        ("org.jetbrains.kotlinx", "kotlinx-serialization-core-jvm", "1.11.0"),
        ("org.jetbrains.kotlinx", "kotlinx-serialization-json-jvm", "1.11.0"),
        ("junit", "junit", "4.13.2"), ("org.hamcrest", "hamcrest-core", "1.3"),
        ("org.json", "json", "20240303")]]
    tests = ["UltraBootSdkInstallTest", "UltraBootSdkSessionTest", "UltraBootSdkRestoreTest"]
    sources = [ROOT / "manager/src/main/java/dev/maplesu/manager/runtime/ultra/UltraBootSdkSession.kt"]
    sources += [ROOT / f"manager/src/test/java/dev/maplesu/manager/runtime/ultra/{test}.kt" for test in tests]
    digests = {path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
               for path in sources}
    cp = os.pathsep.join(map(str, [out, product, *deps, native_toolchain.android_jar()]))
    compiler = cached_jar("org.jetbrains.kotlin", "kotlin-compiler-embeddable", "2.4.20")
    java = str(native_toolchain.jdk_tool("java"))
    commands = [
        [java, "-Xmx512m", "-cp", os.pathsep.join(map(str, [compiler, *deps])),
         "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler", "-no-stdlib", "-no-reflect", "-jvm-target", "21",
         "-Xfriend-paths=" + str(product), "-classpath", cp, "-d", str(out), *map(str, sources)],
        [java, "-Dfile.encoding=UTF-8", "-cp", cp, "org.junit.runner.JUnitCore",
         *["dev.maplesu.manager.runtime.ultra." + test for test in tests]],
    ]
    logs = []
    for command in commands:
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True,
                                encoding="utf-8", errors="replace", timeout=90)
        logs.append(result.stdout + result.stderr)
        if result.returncode:
            break
    unchanged = all(hashlib.sha256((ROOT / path).read_bytes()).hexdigest() == digest
                    for path, digest in digests.items())
    output = "\n".join(logs)
    (out / "regression.log").write_text(output, encoding="utf-8")
    (out / "verification.json").write_text(json.dumps(dict(
        passed=result.returncode == 0 and unchanged, exitCode=result.returncode, tests=tests,
        deviceAccess=False, inputsUnchanged=unchanged, sources=digests,
    ), indent=2) + "\n", encoding="utf-8")
    print(output)
    return result.returncode if unchanged else 1


if __name__ == "__main__":
    raise SystemExit(main())
