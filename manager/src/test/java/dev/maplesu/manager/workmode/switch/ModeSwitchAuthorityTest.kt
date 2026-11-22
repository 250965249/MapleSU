package dev.maplesu.manager.workmode.switch

import dev.maplesu.manager.workmode.TestFixtures
import dev.maplesu.manager.workmode.control.ControlJsonCodec
import dev.maplesu.manager.workmode.control.AtomicControlFile
import dev.maplesu.manager.workmode.control.schema.SwitchHeadViewCodec
import dev.maplesu.manager.workmode.detect.Clock
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.File
import java.util.UUID

/** `switch.json` 权威态（02 §3.2）：原子写 + sha + 与 01 只读投影兼容。 */
class ModeSwitchAuthorityTest {

    private val clock = Clock { 1_000L }
    private val temp = TestFixtures.tempDir("authority").toFile()

    private fun record(switchId: String = UUID.randomUUID().toString()) = SwitchRecord(
        switchId = switchId,
        planSha256 = "a".repeat(64),
        state = SwitchStateNames.REBOOT_REQUIRED,
        stage = "S4",
        step = SwitchSteps.COMMIT_PENDING,
        fromMode = "LITE",
        toMode = "KSU",
        fromBuild = "lite-1",
        toBuild = "ksu-1",
        baselineId = "bl-1",
        startBootId = "boot-1",
        currentBootId = "boot-1",
        createdAtUptimeMs = 10,
        updatedAtUptimeMs = 20,
        device = SwitchRecordDevice("_a", "fw-1", "5.10.198-android13-8", "android13-5.10", "Enforcing"),
        partitions = listOf(
            SwitchRecordPartition("boot", "RESTORE_BASELINE", 4096, "b".repeat(64), "c".repeat(64),
                "d".repeat(64), "DONE", "c".repeat(64)),
        ),
        attempts = SwitchRecordAttempts(bootVerifyFailures = 0, rebootRequests = 1),
    )

    @Test
    fun writeThenReadRoundTripsEveryFixedField() {
        val authority = FileSwitchAuthority(File(temp, "control"), clock)
        val expected = record()
        authority.write(expected)
        val read = authority.read()
        assertTrue(read is AuthorityRead.Ok)
        assertEquals(expected, (read as AuthorityRead.Ok).record)
        assertTrue(File(temp, "control/switch.json").isFile)
        assertTrue(File(temp, "control/switch.json.sha256").isFile)
        assertEquals(dev.maplesu.manager.workmode.control.ShaCheck.OK,
            AtomicControlFile.verifySha(File(temp, "control/switch.json")))
    }

    @Test
    fun legacyJsonWithoutCarrierFieldsKeepsLegacySemantics() {
        val raw = ControlJsonCodec.encode(record(), SwitchRecord.serializer())
            .replace(",\"targetPartition\":null", "")
            .replace(",\"sourcePartition\":null", "")
        val decoded = requireNotNull(ControlJsonCodec.decodeOrNull(raw, SwitchRecord.serializer()))
        assertEquals(1, decoded.schema)
        assertNull(decoded.targetPartition)
        assertNull(decoded.sourcePartition)
    }

    @Test
    fun explicitCarrierAndUnknownSourceRemainDistinctAfterFileRoundTrip() {
        val authority = FileSwitchAuthority(File(temp, "carriers"), clock)
        val expected = record().copy(fromMode = "KSU", toMode = "LITE",
            targetPartition = "boot", sourcePartition = "")
        authority.write(expected)
        assertEquals(expected, authority.read(expected.switchId))
        assertEquals("", authority.read(expected.switchId)!!.sourcePartition)
    }

    @Test
    fun fileIsParseableByReadOnlySwitchHeadProjection() {
        val authority = FileSwitchAuthority(File(temp, "control"), clock)
        val expected = record()
        authority.write(expected)
        val raw = File(temp, "control/switch.json").readText()
        val head = requireNotNull(SwitchHeadViewCodec.parse(raw))
        assertEquals(expected.switchId, head.switchId)
        assertEquals(SwitchStateNames.REBOOT_REQUIRED, head.state)
        assertEquals("LITE", head.from)
        assertEquals("KSU", head.to)
        assertTrue(head.pending)
        assertEquals(1, head.attempts)
    }

    @Test
    fun shaMismatchIsCorruptNotSilentlyAccepted() {
        val dir = File(temp, "corrupt")
        val authority = FileSwitchAuthority(dir, clock)
        authority.write(record())
        File(dir, "switch.json.sha256").writeText("f".repeat(64))
        val read = authority.read()
        assertTrue(read is AuthorityRead.Corrupt)
        assertEquals("SWITCH_CORRUPT", (read as AuthorityRead.Corrupt).code)
        assertNull(authority.read("any"))
    }

    @Test
    fun unknownSchemaAndInvalidSwitchIdAreCorrupt() {
        val dir = File(temp, "schema")
        dir.mkdirs()
        File(dir, "switch.json").writeText(
            ControlJsonCodec.encode(record().copy(schema = 99), SwitchRecord.serializer()),
        )
        val read = FileSwitchAuthority(dir, clock).read()
        assertTrue(read is AuthorityRead.Corrupt)
        assertEquals("CONTROL_SCHEMA_TOO_NEW", (read as AuthorityRead.Corrupt).code)

        val invalid = File(temp, "invalid")
        invalid.mkdirs()
        File(invalid, "switch.json").writeText(
            ControlJsonCodec.encode(record(switchId = "not-a-uuid"), SwitchRecord.serializer()),
        )
        assertTrue(FileSwitchAuthority(invalid, clock).read() is AuthorityRead.Corrupt)
    }

    @Test
    fun readWithSwitchIdOnlyReturnsMatchingRecord() {
        val authority = FileSwitchAuthority(File(temp, "filter"), clock)
        val expected = record()
        authority.write(expected)
        assertEquals(expected, authority.read(expected.switchId))
        assertNull(authority.read(UUID.randomUUID().toString()))
    }

    @Test
    fun writingInvalidRecordIsRejected() {
        val authority = FileSwitchAuthority(File(temp, "reject"), clock)
        try {
            authority.write(record(switchId = "bad"))
            fail("expected IllegalArgumentException")
        } catch (_: IllegalArgumentException) {
            assertTrue(authority.read() is AuthorityRead.Missing)
        }
    }

    @Test
    fun inMemoryAuthorityMatchesFileSemanticsForTests() {
        val expected = record()
        val authority = InMemorySwitchAuthority()
        assertTrue(authority.read() is AuthorityRead.Missing)
        authority.write(expected)
        val readBack = authority.read()
        assertTrue(readBack is AuthorityRead.Ok)
        assertEquals(expected, (readBack as AuthorityRead.Ok).record)
        assertEquals(expected, authority.read(expected.switchId))
        assertFalse(File("memory/switch.json").exists())
    }
}
