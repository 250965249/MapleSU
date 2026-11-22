package dev.maplesu.manager.jailbreak

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test
import java.nio.file.Files

class JailbreakErrorCompatibilityTest {
    @Test fun legacyProviderTokensAreAcceptedAtTheInputBoundary() {
        for (suffix in listOf("IR_NOT_READY", "HANDOVER_NO_EXEC", "HOOK_RESTORE_UNVERIFIED", "KSU_NOT_READY")) {
            assertEquals("MAPLESU_$suffix", jailbreakErrorCode("MAPLESU_$suffix"))
            assertEquals("MAPLESU_$suffix", jailbreakErrorCode("MAPLESU_$suffix"))
        }
        assertEquals("HOOK_BACKEND_NOT_READY", jailbreakErrorCode("HOOK_BACKEND_NOT_READY"))
    }

    @Test fun oldStatusRemainsFailedAndKeepsTheStoredBytes() {
        val directory = Files.createTempDirectory("maplesu-error-status").toFile()
        try {
            val file = directory.resolve("status.json")
            val raw = JSONObject().put("method", "dirtyfrag").put("stage", "FAILED")
                .put("failure", "MAPLESU_IR_NOT_READY").put("bootId", "boot-a").toString()
            file.writeText(raw)
            val status = requireNotNull(JailbreakStatus.readFile(file, "boot-a"))
            assertEquals("FAILED", status.stage)
            assertEquals("MAPLESU_IR_NOT_READY", status.failure)
            assertFalse(status.claimsCurrentBoot("boot-a"))
            assertEquals(raw, file.readText())
            val updated = directory.resolve("updated.json")
            assertEquals(true, JailbreakStatus.writeFile(updated, status).isSuccess)
            assertEquals("MAPLESU_IR_NOT_READY", JSONObject(updated.readText()).getString("failure"))
        } finally {
            directory.deleteRecursively()
        }
    }

    @Test fun oldHookEvidenceKeepsItsFailureAndRestoreFields() {
        val raw = """{"schema":"maplesu.hook.v1","verdict":"FAILED","token":"MAPLESU_HANDOVER_NO_EXEC",
            "restore":{"origin":"KERNEL_SAVED","failures":1},"unload":{"state":"DONE"}}"""
        val parsed = requireNotNull(HookEvidence.parseMain(raw))
        assertEquals("MAPLESU_HANDOVER_NO_EXEC", parsed.token)
        val merged = requireNotNull(HookEvidence.merge(parsed, null))
        assertFalse(merged.ok)
        assertEquals(1, merged.failures)
        assertEquals("KERNEL_SAVED", merged.origin)
    }
}
