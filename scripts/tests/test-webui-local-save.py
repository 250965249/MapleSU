"""Exercise the real DownloadManager local-save state lifecycle with Android service stubs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/specgen"))
from specgen.product import cached_jar


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    java = shutil.which("java")
    if not java:
        parser.error("Java 21 is required")
    base = ROOT / ".tmp/p1-delivery-r7/gradle-build/manager"
    cached = base / "intermediates/built_in_kotlinc/debug/compileDebugKotlin/classes"
    sources = [ROOT / "manager/src/main/java/com/maplesu/core/ui/util/DownloadManager.kt"]
    sources += sorted((ROOT / "scripts/fixtures/normal-webui-static").glob("LocalSave*.kt"))
    dependencies = [cached_jar(*item) for item in [
        ("org.jetbrains.kotlin", "kotlin-stdlib", "2.4.20"), ("org.jetbrains", "annotations", "13.0"),
        ("org.jetbrains.kotlinx", "kotlinx-coroutines-core-jvm", "1.11.0"),
        ("junit", "junit", "4.13.2"), ("org.hamcrest", "hamcrest-core", "1.3")]] + [cached]
    compiler = cached_jar("org.jetbrains.kotlin", "kotlin-compiler-embeddable", "2.4.20")
    before = {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}
    jar = out / "tests.jar"
    commands = [[java, "-Xmx768m", "-cp", os.pathsep.join(map(str, [compiler] + dependencies)),
        "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler", "-no-stdlib", "-no-reflect", "-jvm-target", "21",
        "-classpath", os.pathsep.join(map(str, dependencies)), "-d", str(jar), *map(str, sources)],
        [java, "-cp", os.pathsep.join(map(str, [jar] + dependencies)), "org.junit.runner.JUnitCore",
         "com.maplesu.core.ui.util.LocalSaveTest"]]
    result = None
    try:
        for index, command in enumerate(commands):
            result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=120)
            log = result.stdout + result.stderr
            (out / ("compile.log" if index == 0 else "tests.log")).write_text(log, "utf-8")
            print(log)
            if result.returncode:
                break
    finally:
        after = {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}
        passed = result is not None and result.returncode == 0 and before == after
        (out / "verification.json").write_text(json.dumps(dict(passed=passed,
            sourceSha256Before=before, sourceSha256After=after,
            platformServiceStubbed=True, productionLogicSubstituted=False,
            deviceTestsPerformed=False, networkAccess=False), indent=2) + "\n", "utf-8")
    raise SystemExit(0 if passed else 1)


if __name__ == "__main__":
    main()
