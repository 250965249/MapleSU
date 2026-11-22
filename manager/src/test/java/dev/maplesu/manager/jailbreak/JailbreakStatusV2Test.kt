package dev.maplesu.manager.jailbreak

import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File
import java.nio.file.Files
import java.security.MessageDigest

/**
 * T1 host tests (§7 T1 / §8.1). Pure JVM: no Context, no Android runtime, no disk
 * outside a temp directory. The record is written and read through the file-level
 * API, so every assertion is about `JailbreakStatus` itself rather than a device.
 */
class JailbreakStatusV2Test {
    private lateinit var directory: File

    @Before
    fun setUp() {
        directory = Files.createTempDirectory("maplesu-jailbreak-status").toFile()
    }

    @After
    fun tearDown() {
        directory.deleteRecursively()
    }

    // --- helpers -----------------------------------------------------------

    private fun statusFile(): File = File(directory, "status.json")

    private fun record(
        stage: String = JailbreakStatus.STAGE_DAEMON_READY,
        bootId: String = "boot-a",
        ownerPid: Int? = 4242,
        attemptId: String = "attempt-1",
        failure: String? = null,
        carrier: CarrierProof? = null,
    ): JailbreakStatus = JailbreakStatus(
        method = "dirtyfrag",
        stage = stage,
        message = "test",
        startedAtMillis = 1L,
        updatedAtMillis = 2L,
        bootId = bootId,
        attemptId = attemptId,
        ownerPid = ownerPid,
        failure = failure,
        carrier = carrier,
    )

    private fun proof(): CarrierProof = CarrierProof(
        kind = "l3-gate",
        attemptId = "attempt-1",
        bootId = "boot-a",
        provenAtMillis = 3L,
        provenByPid = 4242,
        facts = mapOf("gate" to "ARMED", "recordOwnerUid" to "0"),
        probe = ProbeResult("/system/bin/sh -c id -u", 0, "0", 0),
    )

    private fun persist(status: JailbreakStatus) {
        val result = JailbreakStatus.writeFile(statusFile(), status)
        assertTrue("write failed: $result", result.isSuccess)
    }

    private fun read(
        bootId: String? = "boot-a",
        ownerAlive: (Int) -> Boolean = { true },
        carrierLive: (JailbreakStatus) -> Boolean? = { null },
    ): JailbreakStatus? = JailbreakStatus.readFile(statusFile(), bootId, ownerAlive, carrierLive)

    private fun sha256(file: File): String =
        MessageDigest.getInstance("SHA-256").digest(file.readBytes())
            .joinToString("") { "%02x".format(it) }

    // --- §5 C2: read is pure ----------------------------------------------

    @Test
    fun readPreservesStageOnBootChange() {
        persist(record(stage = JailbreakStatus.STAGE_DAEMON_READY, bootId = "boot-a"))

        val observed = read(bootId = "boot-b")

        assertNotNull(observed)
        assertEquals("read() must not rewrite the stage", JailbreakStatus.STAGE_DAEMON_READY,
            observed!!.stage)
        assertNull("read() must not synthesise a failure", observed.failure)
        assertTrue(observed.derived?.bootChanged == true)
    }

    @Test
    fun readPreservesStageOnOwnerExit() {
        persist(record(stage = JailbreakStatus.STAGE_DAEMON_READY, ownerPid = 4242))

        val observed = read(ownerAlive = { false })

        assertEquals(JailbreakStatus.STAGE_DAEMON_READY, observed!!.stage)
        assertNull(observed.failure)
        assertTrue(observed.derived?.ownerAlive == false)
    }

    @Test
    fun readDerivedDoesNotMutateStage() {
        persist(record(stage = JailbreakStatus.STAGE_ROOT_WORKER_OBSERVED))

        val observed = read(carrierLive = { false })

        assertEquals(JailbreakStatus.STAGE_ROOT_WORKER_OBSERVED, observed!!.stage)
        assertTrue(observed.derived?.carrierLive == false)
    }

    @Test
    fun readDoesNotTouchDisk() {
        persist(record())
        val before = sha256(statusFile())
        val modified = statusFile().lastModified()

        repeat(3) { read(bootId = "boot-b", ownerAlive = { false }) }

        assertEquals("read() wrote to status.json", before, sha256(statusFile()))
        assertEquals(modified, statusFile().lastModified())
        assertFalse(File(directory, "status.json.new").exists())
    }

    // --- §5 C1: single writer + revision ----------------------------------

    @Test
    fun applyRejectsUiWriter() {
        val current = record()
        persist(current)
        val before = statusFile().readBytes()

        val result = JailbreakStatus.apply(current, current.copy(stage = JailbreakStatus.STAGE_SUPERSEDED),
            Writer.UI)

        assertTrue("a UI process must never be an accepted writer", result is ApplyResult.Rejected)
        assertArrayEquals("apply() must not write", before, statusFile().readBytes())
    }

    @Test
    fun applyRejectsStaleRevision() {
        val current = record().copy(revision = 7L)

        val result = JailbreakStatus.apply(current, current.copy(stage = JailbreakStatus.STAGE_SUPERSEDED),
            Writer.PROVIDER, expectedRevision = 6L)

        assertTrue(result is ApplyResult.Rejected)
        assertTrue((result as ApplyResult.Rejected).reason.contains("STALE_REVISION"))
    }

    @Test
    fun applyIncrementsRevision() {
        val current = record(stage = JailbreakStatus.STAGE_ROOT_WORKER_OBSERVED).copy(revision = 4L)

        val applied = JailbreakStatus.apply(current,
            current.copy(stage = JailbreakStatus.STAGE_CARRIER_PROVEN, carrier = proof()),
            Writer.PROVIDER, expectedRevision = 4L)

        assertTrue(applied is ApplyResult.Applied)
        assertEquals(5L, (applied as ApplyResult.Applied).status.revision)
    }

    // --- §5 C4: monotonicity ----------------------------------------------

    @Test
    fun applyRejectsReadyToFailed() {
        val current = record(stage = JailbreakStatus.STAGE_DAEMON_READY)

        val result = JailbreakStatus.apply(current,
            current.copy(stage = JailbreakStatus.STAGE_FAILED, failure = "boom"), Writer.PROVIDER)

        assertTrue("READY -> FAILED must be rejected", result is ApplyResult.Rejected)
    }

    @Test
    fun applyAllowsCarrierProvenToReady() {
        val current = record(stage = JailbreakStatus.STAGE_ROOT_WORKER_OBSERVED)

        val proven = JailbreakStatus.apply(current,
            current.copy(stage = JailbreakStatus.STAGE_CARRIER_PROVEN, carrier = proof()),
            Writer.PROVIDER)
        assertTrue(proven is ApplyResult.Applied)
        assertEquals(JailbreakStatus.STAGE_CARRIER_PROVEN,
            (proven as ApplyResult.Applied).status.stage)

        val ready = JailbreakStatus.apply(proven.status,
            proven.status.copy(stage = JailbreakStatus.STAGE_DAEMON_READY), Writer.PROVIDER)
        assertTrue(ready is ApplyResult.Applied)
        assertEquals(JailbreakStatus.STAGE_DAEMON_READY, (ready as ApplyResult.Applied).status.stage)
    }

    @Test
    fun applyRejectsCarrierProvenToFailed() {
        val current = record(stage = JailbreakStatus.STAGE_CARRIER_PROVEN, carrier = proof())

        val result = JailbreakStatus.apply(current,
            current.copy(stage = JailbreakStatus.STAGE_FAILED, failure = "boom"), Writer.PROVIDER)

        assertTrue("carrier proven -> FAILED must be rejected", result is ApplyResult.Rejected)
    }

    // --- T1.3 write contract ----------------------------------------------

    @Test
    fun writeIsAtomicFsyncedAndReturnsResult() {
        val ok = JailbreakStatus.writeFile(statusFile(), record())
        assertTrue(ok.isSuccess)
        assertTrue(statusFile().exists())
        assertFalse("staging file leaked", File(directory, "status.json.new").exists())

        val blocker = File(directory, "blocker")
        blocker.writeText("not a directory")
        val failure = JailbreakStatus.writeFile(File(blocker, "status.json"), record())
        assertTrue("an unwritable target must be a Result failure", failure.isFailure)
    }

    // --- §9 compatibility --------------------------------------------------

    @Test
    fun legacyJsonParsesAsSchemaV1() {
        statusFile().writeText(
            """{"method":"dirtyfrag","stage":"DAEMON_READY","message":"old",
               "startedAtMillis":1,"updatedAtMillis":2,"bootId":"boot-a",
               "attemptId":"attempt-1","ownerPid":4242}""")

        val observed = read()

        assertNotNull(observed)
        assertEquals(1, observed!!.schema)
        assertEquals(0L, observed.revision)
        assertEquals(JailbreakStatus.STAGE_DAEMON_READY, observed.stage)
        assertEquals("attempt-1", observed.attemptId)
    }

    @Test
    fun carrierProofRoundTrips() {
        persist(record(stage = JailbreakStatus.STAGE_CARRIER_PROVEN, carrier = proof()))

        val observed = read()

        val carrier = observed!!.carrier
        assertNotNull(carrier)
        assertEquals("l3-gate", carrier!!.kind)
        assertEquals("ARMED", carrier.facts["gate"])
        assertEquals("0", carrier.facts["recordOwnerUid"])
        assertEquals(0, carrier.probe?.exitCode ?: -1)
        assertEquals(0, carrier.probe?.uid ?: -1)
        assertEquals("0", carrier.probe?.stdout)
    }

    @Test
    fun supersededIsTerminalNotFailed() {
        val current = record(stage = JailbreakStatus.STAGE_DAEMON_READY)

        val result = JailbreakStatus.apply(current,
            current.copy(stage = JailbreakStatus.STAGE_SUPERSEDED, message = "another boot"),
            Writer.PROVIDER)

        assertTrue(result is ApplyResult.Applied)
        val superseded = (result as ApplyResult.Applied).status
        assertTrue(superseded.isTerminal())
        assertNull("SUPERSEDED is not a failure", superseded.failure)
        assertEquals(JailbreakStatus.STAGE_SUPERSEDED, superseded.stage)
    }
}
