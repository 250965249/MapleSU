"""Run production switch-policy and cold-start detector regressions on the host JVM."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/specgen"))
from specgen.product import cached_jar


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    java = shutil.which("java")
    dependencies = [cached_jar(*item) for item in [
        ("org.jetbrains.kotlin", "kotlin-stdlib", "2.4.20"),
        ("org.jetbrains", "annotations", "13.0"),
        ("org.jetbrains.kotlinx", "kotlinx-coroutines-core-jvm", "1.11.0"),
        ("org.jetbrains.kotlinx", "kotlinx-serialization-core-jvm", "1.11.0"),
        ("org.jetbrains.kotlinx", "kotlinx-serialization-json-jvm", "1.11.0"),
        ("junit", "junit", "4.13.2"), ("org.hamcrest", "hamcrest-core", "1.3")]]
    compiler = cached_jar("org.jetbrains.kotlin", "kotlin-compiler-embeddable", "2.4.20")
    plugin = cached_jar("org.jetbrains.kotlin", "kotlin-serialization-compiler-plugin-embeddable", "2.4.20")
    base = ROOT / "manager/src/main/java/dev/maplesu/manager/workmode"
    names = ["WorkMode.kt", "Hashes.kt", "detect/ModeState.kt", "detect/Probes.kt",
             "detect/DetectionFacts.kt", "detect/DetectionRules.kt", "detect/RecoveryReadiness.kt",
             "detect/ModeDetector.kt", "control/ControlJson.kt", "control/AtomicControlFile.kt",
             "control/ControlPaths.kt", "switch/BaselineStore.kt", "switch/ModeSwitchTypes.kt",
             "switch/ModeSwitchPreflight.kt", "switch/SwitchStateNames.kt",
             "switch/HiddenSwitchPolicy.kt", "switch/HiddenSwitchCoordinator.kt"]
    tests = ["switch.ModeSwitchPreflightTest", "switch.HiddenSwitchPolicyTest",
             "detect.ModeDetectionRulesTest", "detect.UltraColdStartDetectorTest"]
    test_base = ROOT / "manager/src/test/java/dev/maplesu/manager/workmode"
    sources = [base / name for name in names] + sorted((base / "control/schema").glob("*.kt"))
    sources += [test_base / "TestFixtures.kt"]
    sources += [test_base / (name.replace(".", "/") + ".kt") for name in tests]
    digests = {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}
    classpath = os.pathsep.join(map(str, dependencies))
    jar = out / "tests.jar"
    commands = [
        [java, "-Xmx768m", "-cp", os.pathsep.join(map(str, [compiler] + dependencies)),
         "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler", "-no-stdlib", "-no-reflect", "-jvm-target", "21",
         "-Xplugin=" + str(plugin), "-classpath", classpath, "-d", str(jar), *map(str, sources)],
        [java, "-cp", str(jar) + os.pathsep + classpath, "org.junit.runner.JUnitCore",
         *["dev.maplesu.manager.workmode." + name for name in tests]],
    ]
    for index, command in enumerate(commands):
        result = subprocess.run(command, cwd=ROOT / "manager", capture_output=True,
                                text=True, encoding="utf-8", errors="replace", timeout=90)
        log = result.stdout + result.stderr
        (out / ("compile.log" if index == 0 else "regression.log")).write_text(log, encoding="utf-8")
        print(log)
        if result.returncode:
            break
    unchanged = digests == {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}
    (out / "verification.json").write_text(json.dumps(dict(
        passed=result.returncode == 0 and unchanged, exitCode=result.returncode,
        deviceAccess=False, partitionWrites=False, sourcesUnchanged=unchanged,
        sourceSha256=digests, tests=tests,
    ), indent=2) + "\n", encoding="utf-8")
    raise SystemExit(result.returncode if unchanged else 1)


if __name__ == "__main__":
    main()
