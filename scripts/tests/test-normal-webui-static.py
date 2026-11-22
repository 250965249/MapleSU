"""Run actual static-WebUI readiness code; optionally exercise the real Java file handler.

The optional handler fixture substitutes Android/root file I/O only. On Windows it
uses Linux Java in Docker so canonical paths have the same separators as Android.
It exports actual response bytes/MIME for a separate browser renderer check.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "scripts/fixtures/normal-webui-static"
sys.path.insert(0, str(ROOT / "tools/specgen"))
from specgen.product import cached_jar


def run(command, log, timeout=120):
    result = subprocess.run(command, cwd=ROOT / "manager", capture_output=True,
                            text=True, encoding="utf-8", errors="replace", timeout=timeout)
    log.write_text(result.stdout + result.stderr, "utf-8")
    if result.returncode:
        raise RuntimeError(f"{log.name}: exit={result.returncode}\n{result.stdout}{result.stderr}")
    return result.stdout


def digests(paths):
    return {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}


def readiness(args, out, java):
    inputs = json.loads(args.compile_inputs.read_text("utf-8"))
    cached = args.manager_build / "intermediates/built_in_kotlinc/debug/compileDebugKotlin/classes"
    sources = [ROOT / "manager" / name for name in [
        "src/main/java/com/maplesu/core/ui/webui/WebUiModules.kt",
        "src/main/java/dev/maplesu/manager/modules/ModuleStartupGate.kt",
        "src/main/java/dev/maplesu/manager/modules/ModuleModeRouter.kt",
        "src/main/java/dev/maplesu/manager/workmode/ModeRuntime.kt",
        "src/test/java/com/maplesu/core/ui/webui/WebUiModulesTest.kt",
        "src/test/java/dev/maplesu/manager/workmode/TestFixtures.kt",
    ]]
    compiler = [cached_jar(*item) for item in [
        ("org.jetbrains.kotlin", "kotlin-compiler-embeddable", "2.4.20"),
        ("org.jetbrains.kotlin", "kotlin-stdlib", "2.4.20"),
        ("org.jetbrains", "annotations", "13.0"),
        ("org.jetbrains.kotlinx", "kotlinx-coroutines-core-jvm", "1.11.0")]]
    deps = [cached,
            args.manager_build / "intermediates/javac/debug/compileDebugJavaWithJavac/classes",
            *map(Path, inputs["libraries"]), *compiler[1:],
            cached_jar("junit", "junit", "4.13.2"), cached_jar("org.hamcrest", "hamcrest-core", "1.3")]
    before = digests(sources)
    jar = out / "tests.jar"
    run([str(java), "-Xmx768m", "-cp", os.pathsep.join(map(str, compiler)),
         "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler", "-no-stdlib", "-no-reflect", "-jvm-target", "21",
         "-Xfriend-paths=" + str(cached), "-classpath", os.pathsep.join(map(str, deps)),
         "-d", str(jar), *map(str, sources)], out / "compile.log")
    result = run([str(java), "-cp", os.pathsep.join(map(str, [jar] + deps)), "org.junit.runner.JUnitCore",
                  "com.maplesu.core.ui.webui.WebUiModulesTest"], out / "tests.log")
    assert before == digests(sources), "Readiness sources changed during verification"
    print(result.strip())
    return before


def handler(out, java):
    work = out / "handler"
    classes = work / "classes"
    classes.mkdir(parents=True, exist_ok=True)
    stubs = []
    for name, source in json.loads((FIXTURES / "platform-stubs.json").read_text("utf-8")).items():
        target = work / "platform" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(source, "utf-8")
        stubs.append(target)
    sources = [ROOT / "manager/src/main/java/com/maplesu/core/ui/webui" / name
               for name in ["SuFilePathHandler.java", "MimeUtil.java"]]
    before = digests(sources)
    javac = java.with_name("javac.exe" if os.name == "nt" else "javac")
    run([str(javac), "--release", "21", "-encoding", "UTF-8", "-d", str(classes),
         *map(str, stubs + sources), str(FIXTURES / "StaticHandlerMain.java")], work / "compile.log")
    if os.name == "nt":
        relative = work.relative_to(ROOT).as_posix()
        directory = "/workspace/" + relative
        command = ("apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "
                   "openjdk-21-jre-headless >" + directory + "/java-install.log 2>&1 && java -cp " +
                   directory + "/classes StaticHandlerMain " + directory + "/webroot")
        execution = ["docker", "run", "--rm", "--entrypoint", "sh", "--mount",
                     "type=bind,source=" + str(ROOT) + ",target=/workspace", "ubuntu:22.04", "-c", command]
    else:
        execution = [str(java), "-cp", str(classes), "StaticHandlerMain", str(work / "webroot")]
    output = run(execution, work / "tests.log", timeout=300)
    responses = []
    for line in output.splitlines():
        url, mime, body = line.split("\t")
        data = None if body == "NULL" else base64.b64decode(body)
        responses.append(dict(url=base64.b64decode(url).decode(), mimeType=mime or None,
                              bodyBase64=None if data is None else body,
                              bodyText=None if data is None else data.decode("utf-8", errors="replace"),
                              status=404 if data is None else 200))
    (work / "responses.json").write_text(json.dumps(responses, indent=2) + "\n", "utf-8")
    assert before == digests(sources), "Handler sources changed during verification"
    print(f"PASS: production Java handler, {len(responses)} responses plus traversal/MIME checks")
    return dict(sourceSha256=before, platformIoStubbed=True, handlerLogicSubstituted=False,
                realAndroidWebView=False, filesystemPlatform="Linux" if os.name == "nt" else os.name,
                responseCount=len(responses))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True, help="output directory inside the workspace")
    parser.add_argument("--handler", action="store_true", help="also execute Java handler; Windows requires Docker/network")
    parser.add_argument("--compile-inputs", type=Path, default=ROOT / ".tmp/p0-mode-a-tests/compile-inputs.json")
    parser.add_argument("--manager-build", type=Path, default=ROOT / ".tmp/p1-delivery-r7/gradle-build/manager")
    args = parser.parse_args()
    out = args.out.resolve()
    out.relative_to(ROOT)
    out.mkdir(parents=True, exist_ok=True)
    java = shutil.which("java")
    if not java:
        parser.error("Java 21 is required")
    record = dict(passed=False, deviceTestsPerformed=False, fullManagerCompilation=False)
    try:
        record["readinessSourceSha256"] = readiness(args, out, Path(java))
        if args.handler:
            record["handler"] = handler(out, Path(java))
        record["passed"] = True
    finally:
        (out / "verification.json").write_text(json.dumps(record, indent=2) + "\n", "utf-8")


if __name__ == "__main__":
    main()
