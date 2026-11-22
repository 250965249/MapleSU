package dev.maplesu.manager.jailbreak

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test
import java.io.File

/**
 * T5: transport liveness is derived, never a synthesised stage. The v1 identifiers
 * survive only so a legacy record can still be described; nothing produces them.
 */
class JailbreakExpiredPresentationTest {
    private fun source(relative: String): String {
        val root = sequenceOf(File("."), File("..")).first { File(it, "manager").isDirectory }
        return File(root, relative).readText()
    }

    @Test
    fun legacyTransportTokensAreStillReadable() {
        listOf("JAILBREAK_HOOK_WORKER_EXITED", "JAILBREAK_LEASE_EXITED").forEach { token ->
            assertEquals("Root 会话已断开，请查看导出日志", jailbreakFailureText(token))
        }
    }

    @Test
    fun theExpiredStageIsNoLongerProducedByTheController() {
        val controller = source(
            "manager/src/main/java/dev/maplesu/manager/jailbreak/JailbreakController.kt")
        assertFalse("the UI-side probe must not synthesise EXPIRED",
            controller.contains("STAGE_EXPIRED"))
        assertFalse("the expired-session token factory is gone",
            controller.contains("jailbreakExpiredSessionCode"))
    }
}
