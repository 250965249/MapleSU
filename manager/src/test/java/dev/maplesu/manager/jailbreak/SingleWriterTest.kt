package dev.maplesu.manager.jailbreak

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * T3 host tests (§5 C1/C3, §7 T3): the UI process never writes `status.json`; only
 * the provider owns the record. The write itself is covered by `JailbreakStatusV2Test`;
 * here the contract is "who may call it" plus C3's "no FAILED once a carrier exists".
 */
class SingleWriterTest {
    private fun root(): File =
        sequenceOf(File("."), File("..")).first { File(it, "manager").isDirectory }

    private fun source(relative: String): String = File(root(), relative).readText()

    private fun record(
        stage: String = JailbreakStatus.STAGE_ROOT_WORKER_OBSERVED,
        carrier: CarrierProof? = null,
    ): JailbreakStatus = JailbreakStatus(
        method = "dirtyfrag",
        stage = stage,
        message = "test",
        startedAtMillis = 1L,
        updatedAtMillis = 2L,
        bootId = "boot-a",
        attemptId = "attempt-1",
        carrier = carrier,
    )

    private fun proof(): CarrierProof = CarrierProof(
        kind = "l3-gate", attemptId = "attempt-1", bootId = "boot-a",
        provenAtMillis = 3L, probe = ProbeResult("sh -c id -u", 0, "0", 0))

    @Test
    fun controllerNeverWritesTheRecord() {
        val source = source("manager/src/main/java/dev/maplesu/manager/jailbreak/JailbreakController.kt")
        assertFalse("the UI process must not write status.json",
            source.contains(".write(context)"))
        assertFalse("the UI process must not construct a writer",
            source.contains("JailbreakStatus.write"))
    }

    @Test
    fun prepareHookOnlyReturnsAndNeverWrites() {
        val source = source("manager/src/main/java/dev/maplesu/manager/runtime/NativeSuDaemon.kt")
        assertFalse("prepareHook runs in the UI process and must not persist",
            source.contains(".write(context)"))
    }

    @Test
    fun failedIsRejectedWhenACarrierProofExists() {
        val current = record(carrier = proof())

        val result = JailbreakStatus.apply(current,
            current.copy(stage = JailbreakStatus.STAGE_FAILED, failure = "boom"), Writer.PROVIDER)

        assertTrue("C3: a carrier proof forbids FAILED", result is ApplyResult.Rejected)
        assertTrue((result as ApplyResult.Rejected).reason.contains("CARRIER"))
    }

    @Test
    fun failedIsAllowedBeforeAnyCarrierProof() {
        val current = record(carrier = null)

        val result = JailbreakStatus.apply(current,
            current.copy(stage = JailbreakStatus.STAGE_FAILED, failure = "boom"), Writer.PROVIDER)

        assertTrue("without a carrier, FAILED is the honest outcome", result is ApplyResult.Applied)
    }
}
