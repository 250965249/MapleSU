package dev.maplesu.manager.jailbreak

import org.junit.Assert.*
import org.junit.Test
import java.io.File

class JailbreakManagerRestartTest {
    private fun outcome() = JailbreakController.Outcome(JailbreakStatus.STAGE_DAEMON_READY,
        "Normal ready", null, "attempt-a")
    private fun status() = JailbreakStatus(JailbreakMethod.MAPLESU_93260.wireName,
        JailbreakStatus.STAGE_DAEMON_READY, "Normal ready", 1, 2, "boot-a",
        attemptId = "attempt-a", rootBackend = JailbreakRequest.BACKEND_KSU,
        carrier = CarrierProof("ksu-lkm", "attempt-a", "boot-a", 2,
            probe = ProbeResult("id -u", 0, "0", 0)))

    @Test fun onlyCompleted93260NormalRequestsManagerRestart() {
        assertTrue(JailbreakManagerRestart.required(JailbreakMethod.MAPLESU_93260,
            JailbreakRequest.BACKEND_KSU, outcome()))
        for (method in JailbreakMethod.entries.filter { it != JailbreakMethod.MAPLESU_93260 })
            assertFalse(JailbreakManagerRestart.required(method, JailbreakRequest.BACKEND_KSU, outcome()))
        assertFalse(JailbreakManagerRestart.required(JailbreakMethod.MAPLESU_93260,
            JailbreakRequest.BACKEND_HOOK, outcome()))
        for (pending in listOf(outcome().copy(stage = JailbreakStatus.STAGE_PROVIDER_RUNNING),
            outcome().copy(stage = JailbreakStatus.STAGE_FAILED),
            outcome().copy(stage = JailbreakStatus.STAGE_CANCELLED),
            outcome().copy(failure = "failed"), outcome().copy(attemptId = null))) {
            assertFalse(JailbreakManagerRestart.required(JailbreakMethod.MAPLESU_93260,
                JailbreakRequest.BACKEND_KSU, pending))
        }
    }

    @Test fun restartRequiresPersistedCurrentBootCarrierProof() {
        assertTrue(JailbreakManagerRestart.confirmed(outcome(), status(), "boot-a"))
        for (record in listOf(null, status().copy(stage = JailbreakStatus.STAGE_ROOT_WORKER_OBSERVED),
            status().copy(method = JailbreakMethod.DIRTYFRAG.wireName),
            status().copy(rootBackend = JailbreakRequest.BACKEND_HOOK),
            status().copy(attemptId = "other"), status().copy(bootId = "boot-b"),
            status().copy(failure = "failed"), status().copy(carrier = null))) {
            assertFalse(JailbreakManagerRestart.confirmed(outcome(), record, "boot-a"))
        }
        for (boot in listOf(null, "", "boot-b"))
            assertFalse(JailbreakManagerRestart.confirmed(outcome(), status(), boot))
    }

    @Test fun staleOrNonRootCarrierNeverRestartsManager() {
        val carrier = status().carrier!!
        val probe = carrier.probe!!
        for (proof in listOf(carrier.copy(attemptId = "other"), carrier.copy(bootId = "other"),
            carrier.copy(kind = "l3-gate"), carrier.copy(probe = null),
            carrier.copy(probe = probe.copy(exitCode = 1)), carrier.copy(probe = probe.copy(uid = 2000)),
            carrier.copy(probe = probe.copy(stdout = "2000")))) {
            assertFalse(JailbreakManagerRestart.confirmed(outcome(), status().copy(carrier = proof), "boot-a"))
        }
    }

    @Test fun restartIsConsumedOnceAcrossUiOwners() {
        var saved: String? = null
        var calls = 0
        repeat(2) {
            JailbreakAutomaticReboot({ saved }, { saved = it; true })
                .onSuccess(true, JailbreakRequest.BACKEND_KSU, outcome()) { calls++; true }
        }
        assertEquals(1, calls)
    }

    @Test fun restartCommandDetachesThenStopsAndStartsTheExplicitManager() {
        val script = JailbreakManagerRestart.command("dev.maplesu.manager", "com.maplesu.core.ui.MainActivity",
            "attempt-a", File("/data/user/0/dev.maplesu.manager/files/manager-restart.ready"),
            File("/data/user/0/dev.maplesu.manager/files/manager-restart.log"))
        assertTrue(script.contains("/system/bin/nohup /system/bin/sh -c"))
        assertTrue(script.contains("</dev/null"))
        assertTrue(script.indexOf("force-stop --user 0") < script.indexOf("am start --user 0"))
        assertTrue(script.contains("dev.maplesu.manager/com.maplesu.core.ui.MainActivity"))
        assertFalse(script.contains("LauncherAlias"))
        assertFalse(script.contains("reboot"))
        assertFalse(script.contains("kill -"))
        assertTrue(script.contains("scheduled:attempt-a"))
        File("build/reports/normal-manager-restart/restart.sh").apply {
            parentFile!!.mkdirs()
            writeText(script)
        }
    }
}
