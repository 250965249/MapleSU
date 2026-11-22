package dev.maplesu.manager.runtime.ultra

import org.junit.Assert.assertEquals
import org.junit.Test

class UltraApplicationStartupTest {
    private val packageName = "dev.maplesu.manager"

    private fun start(processName: String): List<String> {
        val calls = mutableListOf<String>()
        UltraApplicationStartup.start(
            processName = processName,
            packageName = packageName,
            warmup = { calls += "warmup" },
        )
        return calls
    }

    @Test fun auxiliaryProcessesNeverStartUltraRecovery() {
        listOf(":root_directory", ":root:daemon", ":magica_boot", ":isolated").forEach { suffix ->
            assertEquals("Ultra startup tasks in $suffix", emptyList<String>(), start(packageName + suffix))
        }
    }

    @Test fun mainProcessStartsTheSingleRecoveryPath() {
        assertEquals(listOf("warmup"), start(packageName))
    }
}
