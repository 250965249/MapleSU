"""Run production startup/identity entry gates against explicit host-only SDK fixtures."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/specgen"))
from specgen.product import cached_jar


def declaration(source, signature):
    start = source.index(signature)
    opening = source.index("{", start)
    depth = 1
    for end in range(opening + 1, len(source)):
        if source[end] == "{": depth += 1
        if source[end] == "}": depth -= 1
        if depth == 0: return source[start:end + 1]
    raise ValueError(signature)


def expression(source, signature):
    return source[source.index(signature):].split("\n\n", 1)[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    ultra = ROOT / "manager/src/main/java/dev/maplesu/manager/runtime/ultra"
    application = ROOT / "manager/src/main/java/com/maplesu/core/KernelSUApplication.kt"
    bootstrap = ROOT / "manager/src/main/java/dev/maplesu/manager/workmode/boot/ModeBootstrap.kt"
    recovery = ultra / "UltraIdentityRecovery.kt"
    probe = ultra / "UltraEnvironmentProbe.kt"
    recovery_text = recovery.read_text(encoding="utf-8")
    probe_text = probe.read_text(encoding="utf-8")
    entry = declaration(recovery_text, "fun recover(context: Context): String {")
    entry = entry[:entry.index("// Rebuild only the current boot session.")]
    # Execute the unchanged production entry through the first SDK restore boundary.
    entry += 'Fixture.calls += "restore"; return Fixture.recoveryResult\n}'
    blocked = expression(recovery_text, "internal fun blocked(")
    cache_entry = declaration(probe_text, "private fun probe(context: Context, force: Boolean)").split("        try {", 1)[0]
    # Keep production cache admission and locks; count crossings into the SDK boundary.
    cache_entry += '''
 try {
  if (key != null) Fixture.calls += "environment-jni"
  snapshotKey = key; snapshotBootId = bootId
  snapshot = if (key == null) Snapshot(State.NoKey) else
   Fixture.sdkObservation.copy(observedAtElapsedMs = SystemClock.elapsedRealtime())
  return snapshot.state
 } finally { probeLock.unlock() }
}
'''
    fragments = {
        "Application.kt": '''package com.maplesu.core
import android.content.Context
import android.util.Log
import dev.maplesu.manager.workmode.*
import dev.maplesu.manager.workmode.gating.*
import kotlinx.coroutines.ensureActive
private const val TAG = "fixture"
class KernelSUApplication : Context() {
 suspend fun runRecovery() = recoverUltraEnvironment()
''' + declaration(application.read_text(encoding="utf-8"), "private suspend fun recoverUltraEnvironment()") + "\n}",
        "Recovery.kt": '''package dev.maplesu.manager.runtime.ultra
import android.content.Context
import android.os.SystemClock
import dev.maplesu.manager.modules.UltraRootKeyStore
import dev.maplesu.manager.workmode.*
import dev.maplesu.manager.workmode.superuser.LiteImplantQuiesceGate
import dev.maplesu.manager.workmode.ui.WorkModeSwitchSession
internal object UltraIdentityRecovery {
''' + blocked + "\n" + entry + '''
 interface RootPort { fun rootUid(key: String): Int? }
 fun candidateUid(key: String): Int? = object : RootPort {
''' + declaration(recovery_text, "override fun rootUid(key: String): Int?") + '''
 }.rootUid(key)
 interface AcceptedPort { fun accepted(key: String) }
 fun accept(context: Context, key: String) {
  val app = context.applicationContext
  object : AcceptedPort {
''' + declaration(recovery_text, "override fun accepted(key: String)") + '''
  }.accepted(key)
 }
 private fun uid(client: UltraRuntimeClient): Int? { Fixture.calls += "uid"; return Fixture.uid }
}
''',
        "Bootstrap.kt": '''package dev.maplesu.manager.workmode.boot
import android.content.Context
import dev.maplesu.manager.workmode.*
import java.util.concurrent.atomic.AtomicBoolean
class ModeBootstrapFixture {
 private val started = AtomicBoolean(true)
 private val firstFrameHandled = AtomicBoolean(false)
 private fun startDetectionThread(name: String, block: () -> Unit) = block()
 private fun executePhaseTwo(beforeDetection: () -> Unit) = beforeDetection()
 private fun startupTrace(message: String) {}
''' + declaration(bootstrap.read_text(encoding="utf-8"), "fun onManagerFirstFrame(context: Context)") + "\n}",
        "Probe.kt": '''package dev.maplesu.manager.runtime.ultra
import android.content.Context
import android.os.SystemClock
import java.util.concurrent.locks.ReentrantLock
object UltraEnvironmentProbe {
 private const val CACHE_TTL_MS = 3_000L
 private val probeLock = ReentrantLock()
 private var revision = 0L
 fun publishSnapshot(observation: Snapshot) { snapshot = observation }
 fun refresh(context: Context, force: Boolean = true) = probe(context, force)
''' +
            declaration(probe_text, "enum class State") + "\n" + declaration(probe_text, "data class Snapshot(") + '''
 private val lock = Any()
 var snapshot = Snapshot()
 var snapshotKey: String? = null
 var snapshotBootId: String? = null
''' + declaration(probe_text, "internal fun currentSnapshot(context: Context)") + "\n" +
            expression(probe_text, "internal fun scopeSnapshot(") + "\n" +
            expression(probe_text, "internal fun canReuse(") + "\n" +
            expression(probe_text, "fun invalidateAvailability()") + "\n" + cache_entry + "\n}",
    }
    for path in (ROOT / "scripts/fixtures/startup-fault-gates").glob("*.kt"):
        fragments[path.name] = path.read_text(encoding="utf-8")
    paired_policy = bootstrap.parent / "PairedStartupPolicy.kt"
    sources = [ultra / "UltraStartupWarmup.kt", paired_policy]
    for name, source in fragments.items():
        path = args.out / name
        path.write_text(source, encoding="utf-8")
        sources.append(path)
    deps = [cached_jar(*item) for item in [
        ("org.jetbrains.kotlin", "kotlin-stdlib", "2.4.20"),
        ("org.jetbrains", "annotations", "13.0"),
        ("org.jetbrains.kotlinx", "kotlinx-coroutines-core-jvm", "1.11.0"),
        ("junit", "junit", "4.13.2"), ("org.hamcrest", "hamcrest-core", "1.3")]]
    compiler = cached_jar("org.jetbrains.kotlin", "kotlin-compiler-embeddable", "2.4.20")
    classes = args.out / "classes"
    classes.mkdir(exist_ok=True)
    java = shutil.which("java")
    cp = os.pathsep.join(map(str, [classes, *deps]))
    commands = [[java, "-Xmx512m", "-cp", os.pathsep.join(map(str, [compiler, *deps])),
        "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler", "-no-stdlib", "-no-reflect", "-nowarn",
        "-jvm-target", "21", "-classpath", cp, "-d", classes, *sources],
        [java, "-cp", cp, "org.junit.runner.JUnitCore", "dev.maplesu.manager.runtime.ultra.StartupFaultGateTest"]]
    logs = []
    for command in commands:
        result = subprocess.run(list(map(str, command)), cwd=ROOT, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=55)
        logs.append(result.stdout + result.stderr)
        if result.returncode: break
    inputs = [application, recovery, probe, bootstrap, paired_policy, ultra / "UltraStartupWarmup.kt", Path(__file__).resolve(),
        *sorted((ROOT / "scripts/fixtures/startup-fault-gates").glob("*.kt"))]
    report = dict(passed=result.returncode == 0, exitCode=result.returncode, output="\n".join(logs),
        scope="Production recovery entry before SDK restore, blocked/candidate UID/accepted callbacks, application warmup, first-frame preparation, snapshot scope and cache admission before JNI; Android and SDK boundaries are fixtures",
        deviceVerification=False,
        sourceHashes={str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in inputs})
    (args.out / "result.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(report["output"])
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
