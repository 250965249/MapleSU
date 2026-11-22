package dev.maplesu.manager.installer

import android.os.Bundle
import android.os.SystemClock
import androidx.test.core.app.ActivityScenario
import androidx.test.platform.app.InstrumentationRegistry
import com.maplesu.core.ui.MainActivity
import dev.maplesu.manager.runtime.RootBackend
import dev.maplesu.manager.runtime.RootExec
import dev.maplesu.manager.runtime.RootExecResult
import dev.maplesu.manager.workmode.ModeRuntime
import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.service.ModeSwitchRuntime
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import java.io.File
import java.util.UUID
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test

/** Opt-in acceptance of an existing rebooted U→N task; never starts a switch or writes images. */
class NormalSwitchReadinessAndroidTest {
    @Test(timeout = 180_000)
    fun normalStartupVerifiesTheExactRebootedUltraToNormalSwitch() {
        val arguments = InstrumentationRegistry.getArguments()
        assumeTrue(arguments.getString("verifyNormalSwitch") == "true")
        val taskId = requireNotNull(arguments.getString("normalSwitchTaskId")) { "normalSwitchTaskId is required" }
        require(UUID.fromString(taskId).toString() == taskId) { "normalSwitchTaskId must be a canonical UUID" }
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        val previousTask = InstallerServiceClient.lastTaskId(context)
        val bootFile = File("/proc/sys/kernel/random/boot_id")
        val bootId = bootFile.readText().trim()
        assertEquals("System boot identity must be a UUID", bootId, UUID.fromString(bootId).toString())
        fun stage(name: String, state: String = "ENTERED", backend: RootBackend = RootBackend.NONE) {
            instrumentation.sendStatus(2, Bundle().apply {
                putString("taskId", taskId)
                putString("bootId", bootId)
                putString("stage", name)
                putString("state", state)
                putString("backend", backend.name)
            })
        }
        fun isNormalRoot(result: RootExecResult?) = result?.ok == true && result.backend == RootBackend.KSU &&
            result.output.trim().lines().map(String::trim) == listOf("0", bootId)

        val startupDeadline = SystemClock.elapsedRealtime() + 60_000
        ActivityScenario.launch(MainActivity::class.java).use {
            stage("normal-root")
            var root: RootExecResult? = null
            while (SystemClock.elapsedRealtime() < startupDeadline) {
                if (ModeRuntime.active == WorkMode.KSU) {
                    root = RootExec.execute(context,
                        "/system/bin/id -u\n/system/bin/cat /proc/sys/kernel/random/boot_id")
                    if (isNormalRoot(root)) break
                }
                SystemClock.sleep(250)
            }
            stage("normal-root", if (isNormalRoot(root)) "OBSERVED" else "NOT_READY", root?.backend ?: RootBackend.NONE)
            assertTrue("Normal root did not become ready within 60 seconds", SystemClock.elapsedRealtime() <= startupDeadline)
            assertEquals("Foreground startup did not activate Normal", WorkMode.KSU, ModeRuntime.active)
            assertTrue("Expected current-boot KSU uid0; backend=${root?.backend} code=${root?.code}", isNormalRoot(root))

            stage("exact-task")
            val facade = requireNotNull(ModeSwitchRuntime.facadeOrNull()) { "Startup did not initialize mode switching" }
            var exact = requireNotNull(runBlocking(Dispatchers.IO) { facade.statusFor(taskId) }) {
                "No exact switch record for $taskId"
            }
            assertEquals(taskId, exact.switchId)
            assertEquals("Task must originate in Ultra", WorkMode.LITE, WorkMode.fromWire(exact.fromMode))
            assertEquals("Task must target Normal", WorkMode.KSU, WorkMode.fromWire(exact.toMode))
            assertTrue("Switch did not observe a reboot", exact.bootObserved)
            assertTrue("Task is not ready for post-boot acceptance: ${exact.state}",
                exact.state in setOf("REBOOT_REQUIRED", "VERIFYING", "VERIFIED"))
            val projected = InstallerServiceClient.installationStatus(context, taskId)
            assertEquals("MODE_SWITCH", projected.getString("kind"))
            assertEquals(taskId, projected.getString("taskId"))
            assertTrue("Installation projection did not observe a reboot", projected.getBoolean("rebootObserved"))
            assertFalse("A switch operation is still active", projected.getBoolean("operationActive"))
            stage("exact-task", exact.state, RootBackend.KSU)

            if (exact.state != "VERIFIED") {
                stage("post-boot-acceptance")
                // Only the existing rebooted post-write task reaches this normal acceptance entry.
                val accepted = InstallerServiceClient.verifyInstallation(context, taskId)
                assertEquals("MODE_SWITCH", accepted.getString("kind"))
                assertEquals(taskId, accepted.getString("taskId"))
                assertEquals("BOOT_VERIFIED", accepted.getString("state"))
                assertTrue("Runtime acceptance failed", accepted.getBoolean("runtimeVerified"))
                assertTrue(accepted.getBoolean("rebootObserved"))
                stage("post-boot-acceptance", "BOOT_VERIFIED", RootBackend.KSU)
            }
            exact = requireNotNull(runBlocking(Dispatchers.IO) { facade.statusFor(taskId) })
            assertEquals(taskId, exact.switchId)
            assertEquals("Underlying switch is not verified", "VERIFIED", exact.state)
            assertTrue(exact.bootObserved)
            assertFalse(exact.rebootRequired)
            assertEquals("", exact.error)
            val acceptedStatus = InstallerServiceClient.installationStatus(context, taskId)
            assertEquals(taskId, acceptedStatus.getString("taskId"))
            assertTrue(acceptedStatus.getString("state") in setOf("VERIFIED", "BOOT_VERIFIED"))
            assertTrue(acceptedStatus.getBoolean("rebootObserved"))

            stage("partition-digests")
            assertEquals("Duplicate partition rows", exact.partitions.size, exact.partitions.map { row -> row.name }.toSet().size)
            val sha256 = Regex("[0-9a-fA-F]{64}")
            for (name in listOf("boot", "init_boot")) {
                val row = requireNotNull(exact.partitions.singleOrNull { partition -> partition.name == name }) {
                    "Verified switch has no exact $name row"
                }
                assertTrue("$name size must be positive", row.size > 0)
                assertTrue("$name target digest is invalid", sha256.matches(row.targetSha256))
                assertTrue("$name observed digest is invalid", sha256.matches(row.observedSha256))
                assertTrue("$name target/observed digest mismatch", row.targetSha256.equals(row.observedSha256, ignoreCase = true))
                instrumentation.sendStatus(2, Bundle().apply {
                    putString("taskId", taskId)
                    putString("bootId", bootId)
                    putString("stage", "partition-digests")
                    putString("partition", name)
                    putString("partitionState", row.state)
                    putLong("partitionBytes", row.size)
                    putString("targetSha256", row.targetSha256)
                    putString("observedSha256", row.observedSha256)
                })
            }
            val finalRoot = RootExec.execute(context,
                "/system/bin/id -u\n/system/bin/cat /proc/sys/kernel/random/boot_id")
            assertTrue("Normal root changed during acceptance", isNormalRoot(finalRoot))
            assertEquals(WorkMode.KSU, ModeRuntime.active)
            assertEquals("Boot changed during acceptance", bootId, bootFile.readText().trim())
            assertEquals("Acceptance replaced lastTaskId", previousTask, InstallerServiceClient.lastTaskId(context))
            stage("normal-switch-ready", "VERIFIED", finalRoot.backend)
        }
    }
}
