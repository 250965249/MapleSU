package dev.maplesu.manager.workmode.detect

import dev.maplesu.manager.jailbreak.JailbreakStatus
import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.detect.probes.JailbreakLeaseAdapter
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import java.io.File

class JailbreakBootBindingTest {
    private fun record() = JailbreakStatus("dirtyfrag", JailbreakStatus.STAGE_DAEMON_READY,
        "history", 1, 2, "boot-old", attemptId = "attempt", rootBackend = "hook")

    private fun snapshot(mode: WorkMode, boot: String = "boot-old") =
        EnvironmentSnapshot(mode, true, "hook:ready", boot, 2)

    @Test fun historyNeverOwnsTheNewBootOrAnUnknownBoot() {
        val previous = record()
        for (boot in listOf(null, "", "boot-new")) {
            assertFalse(previous.isCurrentBoot(boot))
            assertFalse(previous.claimsCurrentBoot(boot))
        }
        assertTrue(previous.claimsCurrentBoot("boot-old"))
        assertFalse(previous.copy(failure = "failed").claimsCurrentBoot("boot-old"))
        assertEquals(JailbreakStatus.STAGE_DAEMON_READY, previous.stage)
    }

    @Test fun historicalCardsAreHiddenUntilTheNewEnvironmentIsDetected() {
        for (mode in WorkMode.entries) {
            val previous = snapshot(mode)
            for (boot in listOf("boot-new", "")) {
                val projection = EnvironmentHomeProjection.decide(EnvironmentHomeProjection.Facts(previous, boot))
                assertNull("An expired temporary session must not render an installed card", projection.cachedMode)
                assertFalse("Expired is not proof of an uninstalled environment", projection.confirmedNotInstalled)
            }
            assertEquals(mode, EnvironmentHomeProjection.decide(
                EnvironmentHomeProjection.Facts(previous, "boot-old")).cachedMode)
        }
    }

    @Test fun liveRootAloneDoesNotValidateThePreviousBootsMode() {
        val projection = EnvironmentHomeProjection.decide(EnvironmentHomeProjection.Facts(
            snapshot(WorkMode.LITE), "boot-new", SuReadiness.USABLE))
        assertNull(projection.cachedMode)
        assertFalse(projection.confirmedNotInstalled)
    }

    @Test fun rebootFallsThroughTheOldLeaseAndReevaluatesBothInstalledBackends() = runBlocking {
        for (mode in WorkMode.entries) {
            val lease = JailbreakLeaseAdapter({ record() }, { error("old Hook must stay unopened") },
                { error("old lease must stay unopened") }, bootId = { "boot-new" })
            val detector = DefaultModeDetector(
                ksuProbe = { KsuFacts(responded = mode == WorkMode.KSU, isManager = mode == WorkMode.KSU,
                    version = 30000, uapi = 7) },
                ultraPort = { if (mode == WorkMode.LITE) UltraState.RUNNING else UltraState.NOT_INSTALLED },
                jailbreakLease = lease,
                bootIdSource = { "boot-new" },
            )
            val detection = detector.detect(DetectionRequest(DetectionOrigin.AFTER_ROOT_GRANTED,
                allowRootProbe = true, allowLiteExecutor = true, allowJailbreakProbe = true))
            assertEquals(mode, detection.state.activeMode)
            assertEquals("boot-new", detection.bootId)
            assertFalse(detection.rule == DetectionRules.Rule.R7_A_JAILBREAK)
        }
    }

    @Test fun rebootWithoutRootDoesNotReactivateTheOldJailbreak() = runBlocking {
        val lease = JailbreakLeaseAdapter({ record() }, { error("old Hook") }, { error("old lease") },
            bootId = { "boot-new" })
        val result = DefaultModeDetector(jailbreakLease = lease, bootIdSource = { "boot-new" })
            .detect(DetectionRequest(DetectionOrigin.AFTER_ROOT_GRANTED, true, true, true))
        assertNull(result.state.activeMode)
        assertEquals("boot-new", result.bootId)
    }

    @Test fun productionRecoveryAndHomeUseTheBootBoundPredicates() {
        val root = sequenceOf(File("."), File("..")).first { File(it, "manager").isDirectory }
        fun source(name: String) = File(root, "manager/src/main/java/$name").readText()
        val directory = source("dev/maplesu/manager/runtime/NativeSuDirectory.kt")
        assertEquals(2, Regex("claimsCurrentBoot\\(").findAll(directory).count())
        val daemon = source("dev/maplesu/manager/runtime/NativeSuDaemon.kt")
            .substringAfter("fun reproveHookOutcome(").substringBefore("private fun enableHookComponents(")
        assertTrue(daemon.indexOf("isCurrentBoot(") in 0 until daemon.indexOf("enableHookComponents(context)"))
        val home = source("com/maplesu/core/ui/viewmodel/HomeViewModel.kt")
        assertTrue(home.contains("else ModeRuntime.active ?: projection.cachedMode"))
        assertTrue(home.contains("!modeSettled && projection.cachedMode == WorkMode.LITE"))
    }
}
