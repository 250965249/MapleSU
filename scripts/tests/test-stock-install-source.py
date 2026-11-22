"""Run actual StockInstallFlow/Attempt on JVM with explicit Android/service boundary doubles."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/specgen"))
from specgen.product import cached_jar

STUBS = {
    "Context.kt": '''package android.content
import java.io.File
import android.net.Uri
open class Context(val cacheDir:File, val filesDir:File, val contentResolver:ContentResolver)
class ContentResolver(val bytes:ByteArray) { fun openInputStream(uri:Uri) = bytes.inputStream() }
''',
    "Uri.kt": "package android.net\ndata class Uri(val value:String)\n",
    "Bundle.kt": '''package android.os
class Bundle {
    private val values = mutableMapOf<String,Any>()
    fun putString(key:String,value:String) { values[key]=value }
    fun getString(key:String) = values[key] as? String
    fun putLong(key:String,value:Long) { values[key]=value }
    fun getLong(key:String) = values[key] as? Long ?: 0L
}
class ParcelFileDescriptor(val file:java.io.File):java.io.Closeable {
    override fun close() = Unit
    class AutoCloseInputStream(descriptor:ParcelFileDescriptor):java.io.FileInputStream(descriptor.file)
    companion object { const val MODE_READ_ONLY=0;fun open(file:java.io.File,mode:Int)=ParcelFileDescriptor(file) }
}
''',
    "Log.kt": "package android.util\nobject Log { fun w(tag:String,message:String,error:Throwable)=0 }\n",
    "WorkMode.kt": "package dev.maplesu.manager.workmode\nenum class WorkMode { LITE,KSU }\n",
    "ImageRepository.kt": "package dev.maplesu.manager\nobject ImageRepository { const val MAX_IMAGE_BYTES=134217728L }\n",
    "UltraPending.kt": '''package dev.maplesu.manager.runtime.ultra
class UltraPendingInstallCredentialStore(context:android.content.Context) { fun observe(result:android.os.Bundle)=Unit }
''',
    "InstallerPorts.kt": '''package dev.maplesu.manager.installer
import android.content.Context
import android.os.Bundle
import android.os.ParcelFileDescriptor
import java.io.File
import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.Hashes
enum class InstallTargetMode(val workMode:WorkMode) { ULTRA(WorkMode.LITE),NORMAL(WorkMode.KSU) }
data class InstallCandidateImage(val image:File,val sha256:String,val size:Long,val partition:String,
    val compatibilityImages:Map<String,File> = emptyMap())
class LenovoSigningOptions(val enabled:Boolean=false) { fun mode(partition:String)=SigningMode.PLAIN }
enum class SigningMode { PLAIN }
class LenovoSigningSession(context:Context,options:LenovoSigningOptions,target:InstallTargetMode,task:String,
    selected:Boolean,log:(String)->Unit):java.io.Closeable {
    fun finish(candidate:InstallCandidateImage,source:File)=candidate
    fun commit(service:TestInstallerService,candidate:InstallCandidateImage)=service.commitNativeInstall("test",ParcelFileDescriptor(candidate.image),candidate.sha256)
    override fun close()=Unit
}
object VivoCompatibility {
    fun deviceSupported()=false
    fun prepare(context:Context,mode:WorkMode,candidate:InstallCandidateImage,sources:Map<String,File>,
        log:(String)->Unit,operationId:String)=candidate
}
object InstallerServiceClient {
    class AuthorizationFailure:RuntimeException("INSTALLER_ROOT_UNAVAILABLE")
    lateinit var service:TestInstallerService
    fun beginInstallation(context:Context,task:String,target:InstallTargetMode)=Unit
    fun <T> withService(context:Context,persistent:Boolean,rootTarget:InstallTargetMode,
        block:(TestInstallerService)->T):T=block(service)
}
class TestInstallerService(val root:File) {
    val events=mutableListOf<String>()
    var restore=false
    var manager=""
    var signed=false
    var prepareFailure:RuntimeException?=null
    val pre=File(root,"pre.img").apply { writeText("current partition PRE") }
    val stock=File(root,"stock.img").apply { writeText("explicit stock image") }
    fun prepareNativeInstall(task:String,target:String,partition:String,restore:Boolean,manager:String,accepted:Boolean):Bundle {
        events += "prepare";this.restore=restore;this.manager=manager
        prepareFailure?.let { throw it }
        return Bundle().apply { putString("taskId",task);putString("kind","NATIVE");putString("state","PREPARED") }
    }
    fun prepareNativeSignedInstall(task:String,target:String,partition:String,restore:Boolean,manager:String,
        accepted:Boolean,mode:String):Bundle {
        signed=true
        return prepareNativeInstall(task,target,partition,restore,manager,accepted)
    }
    fun openNativeInstallImage(task:String,partition:String,meta:Bundle):ParcelFileDescriptor {
        events += "open"
        val file=if(restore) stock else pre
        meta.putString("partition",partition);meta.putLong("size",file.length());meta.putString("sha256",Hashes.sha256(file))
        return ParcelFileDescriptor(file)
    }
    fun commitNativeInstall(task:String,descriptor:ParcelFileDescriptor,sha:String):Bundle {
        events += "commit"
        check(Hashes.sha256(descriptor.file)==sha)
        return Bundle().apply { putString("taskId",task);putString("kind","NATIVE");putString("state","REBOOT_REQUIRED") }
    }
    fun cancelNativeInstall(task:String):Bundle {
        events += "cancel"
        return Bundle().apply { putString("taskId",task);putString("state","CANCELLED") }
    }
}
''',
}


def identity(path):
    return {"path": str(path), "bytes": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--java", type=Path, required=True)
    parser.add_argument("--installer-core", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    std = cached_jar("org.jetbrains.kotlin", "kotlin-stdlib", "2.4.20")
    annotations = cached_jar("org.jetbrains", "annotations", "13.0")
    compiler = cached_jar("org.jetbrains.kotlin", "kotlin-compiler-embeddable", "2.4.20")
    coroutines = cached_jar("org.jetbrains.kotlinx", "kotlinx-coroutines-core-jvm", "1.11.0")
    junit = cached_jar("junit", "junit", "4.13.2")
    hamcrest = cached_jar("org.hamcrest", "hamcrest-core", "1.3")
    main_source = ROOT / "manager/src/main/java"
    sources = [main_source / "dev/maplesu/manager" / name for name in (
        "installer/StockInstallFlow.kt", "installer/StockInstallAttempt.kt",
        "installer/InstallerFailureDiagnostic.kt", "workmode/Hashes.kt")]
    sources += [ROOT / "scripts/fixtures/stock-install-source/StockInstallFlowSourceTest.kt",
                ROOT / "manager/src/test/java/dev/maplesu/manager/installer/DirectInstallSourceWiringTest.kt"]
    sources += [ROOT / "manager/src/test/java/com/maplesu/core/ui/screen/install" / name for name in (
        "InstallSourceFailureWiringTest.kt", "InstallScreenLoadingContractTest.kt")]
    inspected = [main_source / path for path in (
        "com/maplesu/core/ui/util/KsuCli.kt", "com/maplesu/core/ui/screen/flash/FlashUtils.kt",
        "com/maplesu/core/ui/screen/install/InstallScreen.kt", "dev/maplesu/manager/installer/StockInstallPreflight.kt")]
    for name, source in STUBS.items():
        path = output / name
        path.write_text(source, encoding="utf-8")
        sources.append(path)
    dependencies = [std, annotations, junit, hamcrest, args.installer_core.resolve()]
    inputs = sources + inspected + dependencies + [compiler, coroutines, args.java.resolve()]
    receipt = {"inputs": [identity(path) for path in inputs],
               "boundaryStubs": list(STUBS), "realClasses": ["StockInstallFlow", "StockInstallAttempt", "Hashes", "InstallerFailureDiagnostic"],
               "ksudExecuted": False, "deviceTestPerformed": False, "partitionWrites": False, "steps": []}
    jar = output / "source-tests.jar"
    classpath = os.pathsep.join(map(str, dependencies))
    commands = [
        ("compile", [args.java, "-Xmx512m", "-cp", os.pathsep.join(map(str, [compiler, std, annotations, coroutines])),
                     "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler", "-no-stdlib", "-no-reflect", "-jvm-target", "21",
                     "-classpath", classpath, "-d", jar, *sources]),
        ("tests", [args.java, "-Xmx256m", "-cp", str(jar) + os.pathsep + classpath, "org.junit.runner.JUnitCore",
                   "dev.maplesu.manager.installer.StockInstallFlowSourceTest",
                   "dev.maplesu.manager.installer.DirectInstallSourceWiringTest",
                   "com.maplesu.core.ui.screen.install.InstallSourceFailureWiringTest",
                   "com.maplesu.core.ui.screen.install.InstallScreenLoadingContractTest"]),
    ]
    try:
        for name, command in commands:
            result = subprocess.run(list(map(str, command)), cwd=ROOT / "manager", capture_output=True,
                                    text=True, encoding="utf-8", errors="replace")
            log = output / (name + ".log")
            log.write_text(result.stdout + result.stderr, encoding="utf-8")
            receipt["steps"].append({"name": name, "exitCode": result.returncode, "log": identity(log)})
            print(f"{name} code={result.returncode}", flush=True)
            if result.returncode:
                raise RuntimeError(log.read_text(encoding="utf-8"))
        receipt["inputsUnchanged"] = receipt["inputs"] == [identity(path) for path in inputs]
        assert receipt["inputsUnchanged"]
        receipt["passed"] = True
    finally:
        (output / "execution.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
