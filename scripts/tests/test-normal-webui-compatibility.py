"""Run production callback/CSP regressions and export their real JavaScript for rendering."""
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
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    dependencies = [cached_jar(*item) for item in [
        ("org.jetbrains.kotlin", "kotlin-stdlib", "2.4.20"),
        ("org.jetbrains", "annotations", "13.0"),
        ("org.jetbrains.kotlinx", "kotlinx-coroutines-core-jvm", "1.11.0"),
        ("org.json", "json", "20240303"),
        ("junit", "junit", "4.13.2"), ("org.hamcrest", "hamcrest-core", "1.3")]]
    compiler = cached_jar("org.jetbrains.kotlin", "kotlin-compiler-embeddable", "2.4.20")
    name = "com/maplesu/core/ui/webui"
    sources = [ROOT / "manager/src/main/java" / name / "NormalWebUiCompatibility.kt",
               ROOT / "manager/src/test/java" / name / "NormalWebUiCompatibilityTest.kt"]
    hashes = {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}
    jar = out / "tests.jar"
    cp = os.pathsep.join(map(str, [jar] + dependencies))
    java = shutil.which("java")
    commands = [
        [java, "-Xmx768m", "-cp", os.pathsep.join(map(str, [compiler] + dependencies)),
         "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler", "-no-stdlib", "-no-reflect", "-jvm-target", "21",
         "-classpath", os.pathsep.join(map(str, dependencies)), "-d", str(jar), *map(str, sources)],
        [java, "-cp", cp, "org.junit.runner.JUnitCore", "com.maplesu.core.ui.webui.NormalWebUiCompatibilityTest"],
        [java, "-cp", cp, "com.maplesu.core.ui.webui.NormalWebUiCompatibilityFixture", str(out / "compatibility.json")],
    ]
    for log_name, command in zip(["compile.log", "tests.log", "export.log"], commands):
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True,
                                encoding="utf-8", errors="replace", timeout=120)
        log = result.stdout + result.stderr
        (out / log_name).write_text(log, encoding="utf-8")
        print(log)
        if result.returncode:
            break
    unchanged = hashes == {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}
    (out / "verification.json").write_text(json.dumps(dict(
        passed=result.returncode == 0 and unchanged, exitCode=result.returncode,
        sourcesUnchanged=unchanged, sourceSha256=hashes,
        androidWebViewTested=False, deviceTestsPerformed=False,
    ), indent=2) + "\n", encoding="utf-8")
    raise SystemExit(result.returncode if unchanged else 1)


if __name__ == "__main__":
    main()
