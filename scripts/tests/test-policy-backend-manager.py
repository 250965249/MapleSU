"""Run focused JVM tests against freshly compiled production manager classes."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
import native_toolchain  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/specgen"))
from specgen.product import cached_jar


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--classes", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    classes, out = args.classes.resolve(), args.out.resolve()
    assert classes.is_dir()
    out.mkdir(parents=True, exist_ok=True)
    deps = [cached_jar(*item) for item in [
        ("org.jetbrains.kotlin", "kotlin-stdlib", "2.4.20"), ("org.jetbrains", "annotations", "13.0"),
        ("org.jetbrains.kotlinx", "kotlinx-coroutines-core-jvm", "1.11.0"),
        ("junit", "junit", "4.13.2"), ("org.hamcrest", "hamcrest-core", "1.3"),
        ("org.json", "json", "20240303")]]
    deps += [native_toolchain.android_jar()]
    compiler = cached_jar("org.jetbrains.kotlin", "kotlin-compiler-embeddable", "2.4.20")
    tests = ["UltraPolicyBackendArtifactTest", "UltraPolicyBackendInstallTest", "UltraEnvironmentInstallRecheckTest",
             "UltraMaintenanceRootReceiptTest"]
    sources = [ROOT / "manager/src/test/java/dev/maplesu/manager/runtime/ultra" / (name + ".kt") for name in tests]
    cp = os.pathsep.join(map(str, [out, classes] + deps))
    logs = []
    for command in [
        [str(native_toolchain.jdk_tool("java")), "-Xmx512m", "-cp", os.pathsep.join(map(str, [compiler] + deps)),
         "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler", "-no-stdlib", "-no-reflect", "-jvm-target", "21",
         "-Xfriend-paths=" + str(classes), "-classpath", cp, "-d", str(out), *map(str, sources)],
        [str(native_toolchain.jdk_tool("java")), "-Dfile.encoding=UTF-8", "-cp", cp, "org.junit.runner.JUnitCore",
         *["dev.maplesu.manager.runtime.ultra." + name for name in tests]]]:
        result = subprocess.run(command, cwd=ROOT / "manager", capture_output=True, text=True,
                                encoding="utf-8", errors="replace", timeout=55)
        logs.append(result.stdout + result.stderr)
        if result.returncode:
            break
    output = "\n".join(logs)
    (out / "regression.log").write_text(output, encoding="utf-8")
    record = dict(passed=result.returncode == 0, recordedAt=datetime.now(timezone.utc).isoformat(),
        exitCode=result.returncode, stdout=output,
        sourceSha256={p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources},
        productionClassSha256={str(p.relative_to(classes)): hashlib.sha256(p.read_bytes()).hexdigest() for p in
            [classes / "dev/maplesu/manager/runtime/ultra" / (n + ".class") for n in
             ["UltraPolicyBackendArtifact", "UltraEnvironmentInstaller"]]}, deviceAccess=False,
        scope="Actual compiled manager orchestration and file integrity; SDK submit, root, and Android runtime are fixtures")
    (out / "verification.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(output)
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
