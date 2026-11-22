package dev.maplesu.manager.workmode.control

import dev.maplesu.manager.workmode.TestFixtures
import dev.maplesu.manager.workmode.detect.BootIdSource
import dev.maplesu.manager.workmode.detect.Clock
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/** 01 §8.1 `EvidenceRedactorTest`：不泄密 + 1 MiB 轮转。 */
class EvidenceRedactorTest {

    private fun line(
        error: String = "",
        evidence: List<String> = emptyList(),
        kind: String = "DETECT",
        packageHash: String? = null,
    ) = EvidenceLine(
        at = 1_000L,
        bootId = "boot-1",
        kind = kind,
        result = EvidenceLine.OK,
        error = error,
        evidence = evidence,
        packageHash = packageHash,
    )

    @Test
    fun dropsCredentialKey() {
        assertNull(EvidenceRedactor.scrub(line(error = "credential=abc")))
        assertNull(EvidenceRedactor.scrub(line(evidence = listOf("L1:credentialPresent=true"))))
    }

    @Test
    fun dropsRootKey() {
        assertNull(EvidenceRedactor.scrub(line(error = "rootKey=deadbeef")))
        assertNull(EvidenceRedactor.scrub(line(error = "root_key")))
    }

    @Test
    fun dropsStealthCode() {
        assertNull(EvidenceRedactor.scrub(line(error = "stealth_code=123456")))
        assertNull(EvidenceRedactor.scrub(line(evidence = listOf("S1:stealthcode"))))
    }

    @Test
    fun rejectsApkPath() {
        assertNull(EvidenceRedactor.scrub(line(error = "/data/app/dev.maplesu.manager/base.apk")))
        assertNull(EvidenceRedactor.scrub(line(error = "open /data/user/0/x failed")))
    }

    @Test
    fun safeLineSurvives() {
        val safe = line(evidence = listOf("S1:ok", "S2:ok", "L3:unknown"))
        assertEquals(safe, EvidenceRedactor.scrub(safe))
    }

    @Test
    fun hashesPackageName() {
        val hash = EvidenceRedactor.hashPackageName("com.example.app")
        assertEquals(16, hash.length)
        assertTrue(hash.matches(Regex("[0-9a-f]{16}")))
        assertEquals(hash, EvidenceRedactor.hashPackageName("com.example.app"))
        assertFalse(hash == EvidenceRedactor.hashPackageName("com.example.other"))
    }

    @Test
    fun evidenceLogDropsAndMarksRedaction() {
        val file = File(TestFixtures.tempDir("evidence").toFile(), "evidence.jsonl")
        val log = EvidenceLog(file, Clock { 1_000L }, BootIdSource { "boot-1" })
        assertFalse(log.append(line(error = "credential=secret")))
        val lines = log.readAll()
        assertEquals(1, lines.size)
        assertEquals(EvidenceLine.EVIDENCE_REDACTED, lines.last().error)
        assertTrue(log.append(line(evidence = listOf("S1:ok"))))
        assertEquals(2, log.readAll().size)
    }

    @Test
    fun rotatesAtLimit() {
        val directory = TestFixtures.tempDir("evidence-rotate").toFile()
        val file = File(directory, "evidence.jsonl")
        val log = EvidenceLog(file, Clock { 1_000L }, BootIdSource { "boot-1" }, maxBytes = 400)
        repeat(6) { index ->
            assertTrue(
                log.append(
                    line(evidence = listOf("S1:ok", "S2:ok"), kind = "DETECT"),
                ),
            )
            assertEquals(EvidenceLine.OK, log.readAll().lastOrNull()?.result ?: EvidenceLine.OK)
        }
        assertTrue("expected rotation file", log.rotatedFile().isFile)
        assertTrue(file.isFile)
        assertTrue("current file must be bounded", file.length() <= 400)
    }
}
