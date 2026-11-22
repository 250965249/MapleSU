"""Compile the real ZIP inspector and run strict and Normal preflight regressions."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/specgen"))
from specgen.product import cached_jar

JAR_HASHES = {
    'kotlin-stdlib:2.4.20': '2226de463d309d4a5500a481320b3dea515a6981dcae1def531fbc158884e25f',
    'annotations:13.0': 'ace2a10dc8e2d5fd34925ecac03e4988b2c0f851650c94b8cef49ba1bd111478',
    'junit:4.13.2': '8e495b634469d64fb8acfa3495a065cbacc8a0fff55ce1e31007be4c16dc57d3',
    'hamcrest-core:1.3': '66fdef91e9739348df7a096aa384a5685f4e875584cce89386a7a47251c4d8e9',
    'commons-compress:1.28.0': 'e1522945218456f3649a39bc4afd70ce4bd466221519dba7d378f2141a4642ca',
    'commons-io:2.20.0': 'df90bba0fe3cb586b7f164e78fe8f8f4da3f2dd5c27fa645f888100ccc25dd72',
    'commons-lang3:3.18.0': '4eeeae8d20c078abb64b015ec158add383ac581571cddc45c68f0c9ae0230720',
    'xz:1.12': '3e158a87bd73d8afb4b6e8239c013b7d049c48563f45860ce99cd2e448cf4a6b',
    'kotlin-compiler-embeddable:2.4.20': 'cf97161430683fb9af96dc6a7017ffae1fe8737b80d12eee11f2fe3e76f8ded8',
    'kotlinx-coroutines-core-jvm:1.11.0': 'd1d75aa01dffbb4d1c520e67e4c4e7f5f6174718e7cb4632412503f2f0e604fa',
}


def dependency(group, artifact, version, output):
    expected = JAR_HASHES[artifact + ':' + version]
    try:
        path = cached_jar(group, artifact, version)
    except RuntimeError:
        path = output / 'dependencies' / (artifact + '-' + version + '.jar')
        if not path.is_file():
            url = 'https://repo.maven.apache.org/maven2/' + group.replace('.', '/') + '/' + artifact + '/' + version + '/' + path.name
            with urllib.request.urlopen(url, timeout=120) as response:
                data = response.read()
            if hashlib.sha256(data).hexdigest() != expected:
                raise ValueError('MODULE_TEST_DEPENDENCY_HASH:' + artifact)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
    if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        raise ValueError('MODULE_TEST_DEPENDENCY_HASH:' + artifact)
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    java, javac = shutil.which("java"), shutil.which("javac")
    if not java or not javac:
        parser.error("Java 21 JDK is required")
    dependencies = [dependency(*item, out) for item in [
        ("org.jetbrains.kotlin", "kotlin-stdlib", "2.4.20"),
        ("org.jetbrains", "annotations", "13.0"),
        ("junit", "junit", "4.13.2"), ("org.hamcrest", "hamcrest-core", "1.3"),
        ("org.apache.commons", "commons-compress", "1.28.0"),
        ("commons-io", "commons-io", "2.20.0"),
        ("org.apache.commons", "commons-lang3", "3.18.0"),
        ("org.tukaani", "xz", "1.12")]]
    compiler = dependency("org.jetbrains.kotlin", "kotlin-compiler-embeddable", "2.4.20", out)
    coroutines = dependency("org.jetbrains.kotlinx", "kotlinx-coroutines-core-jvm", "1.11.0", out)
    sources = [ROOT / "manager/src/main/java/dev/maplesu/manager" / (name + ".java")
               for name in ["ModuleArchiveInspector", "MapleSuModuleMetadata", "compat/NativeModuleAbi"]]
    test = ROOT / "manager/src/test/java/dev/maplesu/manager/ModuleArchiveInspectorTest.kt"
    sources.append(test)
    digests = {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
               for p in sources}
    classes = out / "classes"
    classes.mkdir(exist_ok=True)
    jar = out / "tests.jar"
    classpath = os.pathsep.join(map(str, [classes] + dependencies))
    commands = [
        [javac, "-encoding", "UTF-8", "-cp", classpath, "-d", str(classes),
         *map(str, sources[:-1])],
        [java, "-Xmx768m", "-cp", os.pathsep.join(map(str, [compiler, coroutines] + dependencies)),
         "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler", "-no-stdlib", "-no-reflect", "-jvm-target", "21",
         "-classpath", classpath, "-d", str(jar), str(test)],
        [java, "-Xmx768m", "-cp", str(jar) + os.pathsep + classpath,
         "org.junit.runner.JUnitCore", "dev.maplesu.manager.ModuleArchiveInspectorTest"],
    ]
    for name, command in zip(["java-compile.log", "kotlin-compile.log", "tests.log"], commands):
        result = subprocess.run(command, cwd=ROOT / "manager", capture_output=True,
                                text=True, encoding="utf-8", errors="replace", timeout=120)
        log = result.stdout + result.stderr
        (out / name).write_text(log, encoding="utf-8")
        print(log)
        if result.returncode:
            break
    unchanged = digests == {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                            for p in sources}
    (out / "verification.json").write_text(json.dumps(dict(
        passed=result.returncode == 0 and unchanged, exitCode=result.returncode,
        sourcesUnchanged=unchanged, sourceSha256=digests,
        tests=["dev.maplesu.manager.ModuleArchiveInspectorTest"],
        deviceTestsPerformed=False, partitionWrites=False,
    ), indent=2) + "\n", encoding="utf-8")
    raise SystemExit(result.returncode if unchanged else 1)


if __name__ == "__main__":
    main()
