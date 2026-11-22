package dev.maplesu.manager.installer

import android.os.Bundle
import android.os.Process
import android.os.SystemClock
import androidx.test.core.app.ActivityScenario
import androidx.test.platform.app.InstrumentationRegistry
import com.maplesu.core.ui.MainActivity
import dev.maplesu.image.RamdiskInspector
import dev.maplesu.manager.ksu.KsuBootInfoSubcommand
import dev.maplesu.manager.ksu.KsuBootPatchOptions
import dev.maplesu.manager.ksu.KsuCandidateCommitPort
import dev.maplesu.manager.ksu.KsuCandidateWorkspaces
import dev.maplesu.manager.ksu.KsuCommands
import dev.maplesu.manager.ksu.KsuInstallProducer
import dev.maplesu.manager.ksu.KsuProduceResult
import dev.maplesu.manager.ksu.KsuRootCommandRunner
import dev.maplesu.manager.ksu.KsuShellResult
import dev.maplesu.manager.ksu.KsuTimeouts
import dev.maplesu.manager.runtime.RootBackend
import dev.maplesu.manager.runtime.RootExec
import dev.maplesu.manager.workmode.ModeRuntime
import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.control.ControlPaths
import dev.maplesu.manager.workmode.superuser.LiteImplantScripts
import dev.maplesu.manager.workmode.superuser.RootScriptRunner
import dev.maplesu.manager.workmode.superuser.RootScriptResult
import dev.maplesu.manager.workmode.switch.DeviceBootFacts
import dev.maplesu.manager.workmode.switch.ModeSwitchKmi
import java.io.File
import java.util.UUID
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test

/** Opt-in candidate-only proof: no switch/install task, partition commit or reboot. */
class NormalCandidatePreflightAndroidTest {
    @Test(timeout = 180_000)
    fun verifiedBaselineProducesAnAppReadableNormalCandidateWithoutWritingPartitions() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyNormalCandidate") == "true")
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        val previousTask = InstallerServiceClient.lastTaskId(context)
        val bootId = File("/proc/sys/kernel/random/boot_id").readText().trim()
        val log = File(context.cacheDir, "normal-candidate-preflight-${UUID.randomUUID()}.log")
        fun stage(name: String, completed: Boolean = false) {
            val state = if (completed) "PASSED" else "ENTERED"
            log.appendText("${SystemClock.elapsedRealtime()} boot=$bootId stage=$name state=$state\n")
            instrumentation.sendStatus(2, Bundle().apply {
                putString("stage", name)
                putString("stageState", state)
                putString("bootId", bootId)
                putString("testLog", log.absolutePath)
            })
        }
        ActivityScenario.launch(MainActivity::class.java).use {
            val deadline = SystemClock.elapsedRealtime() + 60_000
            while (ModeRuntime.active != WorkMode.LITE && SystemClock.elapsedRealtime() < deadline) {
                SystemClock.sleep(250)
            }
            assertEquals("Preflight requires the existing Ultra root environment", WorkMode.LITE, ModeRuntime.active)
            stage("root-identity")
            val identity = RootExec.execute(context, "/system/bin/id -u")
            assertTrue("Existing Root unavailable: code=${identity.code}", identity.ok)
            assertEquals(RootBackend.ULTRA_ENV, identity.backend)
            assertEquals("0", identity.output.trim())
            stage("root-identity", true)
            val runner = RootScriptRunner { script ->
                val result = RootExec.execute(context, script)
                RootScriptResult(result.code, result.output)
            }
            stage("capture-probe")
            val probe = requireNotNull(RootScriptBaselineCapture(runner, Process.myUid()).probe())
            stage("capture-probe", true)
            val device = DeviceBootFacts(probe.slot, probe.firmware, probe.kernelRelease)
            val bridge = RootScriptBaselineBridge(runner, deviceSlot = { probe.slot })
            stage("baseline-probe")
            val baseline = requireNotNull(reusableBaselineEntry(requireNotNull(bridge.probe()), device,
                BaselineIdentity.fromDevice(device), requireInitBoot = true)) {
                "An existing verified boot/init_boot baseline is required; this test never creates one"
            }
            stage("baseline-probe", true)
            val id = baseline.first.id
            check(Regex("[A-Za-z0-9._-]{1,128}").matches(id))
            val expected = baseline.second.partitions.single { part -> part.name == "init_boot" }
            val work = File(context.cacheDir, "normal-candidate-preflight-${UUID.randomUUID()}")
            assertTrue(work.mkdir())
            val candidateRoot = KsuCandidateWorkspaces.install(context.filesDir)
            val candidateNonce = System.currentTimeMillis()
            var completed = false
            try {
                stage("source-copy")
                val source = File(work, "baseline-init_boot.img").apply { writeBytes(ByteArray(0)) }
                val quote = LiteImplantScripts::quote
                val copy = runner.run(buildString {
                    appendLine("set -e")
                    appendLine("S=${quote("${ControlPaths.ROOT}/boot/baseline/$id/init_boot.img")}")
                    appendLine("T=${quote(source.absolutePath)}")
                    appendLine("[ -f \"\$S\" ] && [ ! -L \"\$S\" ] && [ ! -L \"\$T\" ]")
                    appendLine("/system/bin/cp \"\$S\" \"\$T\"")
                    appendLine("/system/bin/chown ${Process.myUid()}:${Process.myUid()} \"\$T\"")
                    appendLine("/system/bin/chmod 0600 \"\$T\"")
                    appendLine("/system/bin/restorecon \"\$T\"")
                })
                assertEquals("Verified baseline copy failed: ${copy.out}", 0, copy.code)
                assertEquals(expected.size, source.length())
                assertEquals(expected.sha256, KsuInstallProducer.sha256(source))
                stage("source-copy", true)
                val daemon = KsuCommands.daemonPath(File(context.applicationInfo.nativeLibraryDir))
                val commandRunner = KsuRootCommandRunner { command, _ ->
                    val result = RootExec.execute(context, command)
                    KsuShellResult(result.code, result.output.lines(), listOf(result.detail).filter(String::isNotBlank))
                }
                stage("catalog")
                val catalogResult = commandRunner.run(KsuInstallProducer.shellJoin(
                    KsuCommands.bootInfo(daemon, KsuBootInfoSubcommand.SUPPORTED_KMIS)), KsuTimeouts.COMMAND_MS)
                assertEquals("Native KMI catalog failed: ${catalogResult.outText} ${catalogResult.errText}", 0, catalogResult.code)
                val catalog = catalogResult.out.map(String::trim).filter(String::isNotEmpty).toSet()
                stage("catalog", true)
                val producer = KsuInstallProducer(daemon, commandRunner, candidateRoot,
                    KsuCandidateCommitPort { _, _ -> error("Candidate preflight must never commit") },
                    clock = { candidateNonce }, kmiCatalog = { catalog }, appUid = Process.myUid())
                stage("produce")
                val result = producer.produceCandidate(source, KsuBootPatchOptions(
                    kmi = requireNotNull(ModeSwitchKmi.parse(probe.kernelRelease)), partition = "init_boot"),
                    onStdout = { line -> log.appendText("stdout: $line\n") },
                    onStderr = { line -> log.appendText("stderr: $line\n") })
                assertTrue("Normal production candidate rejected: $result", result is KsuProduceResult.Produced)
                val candidate = (result as KsuProduceResult.Produced).candidate
                stage("produce", true)
                assertEquals(candidateRoot, candidate.candidate.parentFile!!.parentFile)
                assertFalse(candidate.candidate.toPath().startsWith(File(context.filesDir, "ksu/work").toPath()))
                assertTrue(candidate.candidate.canRead())
                assertEquals(probe.sizes.getValue("init_boot"), candidate.size)
                assertEquals(candidate.sha256, KsuInstallProducer.sha256(candidate.candidate))
                assertEquals(expected.sha256, candidate.sourceSha256)
                assertTrue(RamdiskInspector.inspect(candidate.candidate).requireKsuLkmForm().ok)
                assertTrue(KsuKernelPreservation.check("init_boot", source, candidate.candidate) is KsuKernelPreservation.Verdict.Ok)
                assertEquals(expected.sha256, KsuInstallProducer.sha256(source))
                assertEquals(previousTask, InstallerServiceClient.lastTaskId(context))
                assertEquals(bootId, File("/proc/sys/kernel/random/boot_id").readText().trim())
                stage("candidate-validated", true)
                instrumentation.sendStatus(2, Bundle().apply {
                    putString("state", "NORMAL_CANDIDATE_VERIFIED_NO_COMMIT")
                    putString("baselineId", id)
                    putString("sourceSha256", expected.sha256)
                    putString("candidateSha256", candidate.sha256)
                    putLong("candidateBytes", candidate.size)
                    putString("bootId", bootId)
                    putBoolean("taskUnchanged", true)
                    putString("workspace", candidateRoot.name)
                    putBoolean("legacyWorkspaceExists", File(context.filesDir, "ksu/work").exists())
                    putString("testLog", log.absolutePath)
                })
                completed = true
            } finally {
                if (completed) {
                    work.deleteRecursively()
                    File(candidateRoot, "cand-$candidateNonce").deleteRecursively()
                }
            }
        }
    }
}
