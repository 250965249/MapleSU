package dev.maplesu.manager.workmode.control

import dev.maplesu.manager.workmode.TestFixtures
import dev.maplesu.manager.workmode.control.schema.ModesFile
import dev.maplesu.manager.workmode.detect.BootIdSource
import dev.maplesu.manager.workmode.detect.Clock
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/** 01 §8.1 `ControlCorruptionTest`：§4.7 损坏恢复矩阵（每行一个用例）。 */
class ControlCorruptionTest {
    private val clock = Clock { 1_000L }
    private val boot = BootIdSource { "boot-1" }

    private fun root(): File = TestFixtures.tempDir("control").toFile().also {
        ControlPermissions.ensureTree(it)
    }

    private fun plane(root: File, diagnostics: MutableList<String> = mutableListOf()) =
        FileControlPlane(root = root, clock = clock, bootIdSource = boot, onDiagnostic = { diagnostics += it })

    private fun controlFile(root: File, name: String) = File(root, "control/$name")

    private inline fun <reified T> writeControl(root: File, name: String, value: T) {
        TestFixtures.writeControlJson(controlFile(root, name), value)
    }

    @Test
    fun modesCorruptBlocksSwitch() {
        val root = root()
        writeControl(root, "modes.json", TestFixtures.modesFile(revision = 1))
        controlFile(root, "modes.json").writeText("{ this is not json")
        val plane = plane(root)
        val read = plane.readModes()
        assertTrue(read is ControlRead.Corrupt)
        assertTrue((read as ControlRead.Corrupt).code == ControlErrors.CONTROL_MODES_CORRUPT)
        val write = plane.writeModes { it.copy(revision = 2) }
        assertTrue(write is ControlWrite.Rejected)
        assertTrue((write as ControlWrite.Rejected).code == ControlErrors.CONTROL_MODES_CORRUPT)
        // 保留现场：原文件不被静默重建。
        val quarantined = File(root, "control").listFiles()!!.any {
            it.name.startsWith("modes.json.corrupt-")
        }
        assertTrue("modes.json corruption must be quarantined", quarantined)
    }

    @Test
    fun modesShaMismatchIsCorrupt() {
        val root = root()
        writeControl(root, "modes.json", TestFixtures.modesFile())
        controlFile(root, "modes.json").writeText(
            ControlJsonCodec.encode(TestFixtures.modesFile(revision = 99), ModesFile.serializer()),
        )
        val read = plane(root).readModes()
        assertTrue(read is ControlRead.Corrupt)
    }

    @Test
    fun schemaTooNewIsReadOnly() {
        val root = root()
        writeControl(root, "modes.json", TestFixtures.modesFile(schema = 2))
        val plane = plane(root)
        val read = plane.readModes()
        assertTrue(read is ControlRead.Unreadable)
        assertEquals(ControlErrors.CONTROL_SCHEMA_TOO_NEW, (read as ControlRead.Unreadable).code)
        val write = plane.writeModes { it.copy(revision = 2) }
        assertTrue(write is ControlWrite.Rejected)
        assertEquals(ControlErrors.CONTROL_SCHEMA_TOO_NEW, (write as ControlWrite.Rejected).code)
    }

    @Test
    fun revisionRegressionRejected() {
        val root = root()
        writeControl(root, "modes.json", TestFixtures.modesFile(revision = 5))
        val plane = plane(root)
        val result = plane.writeModes { it.copy(revision = 4) }
        assertTrue(result is ControlWrite.Rejected)
        assertEquals(ControlErrors.CONTROL_REVISION_REGRESSION, (result as ControlWrite.Rejected).code)
        val read = plane.readModes()
        assertEquals(5L, (read as ControlRead.Ok).value.revision)
    }

    @Test
    fun writeModesIncrementsRevisionAndVerifies() {
        val root = root()
        writeControl(root, "modes.json", TestFixtures.modesFile(revision = 5))
        val plane = plane(root)
        val result = plane.writeModes { it.copy(revision = 6, updatedAt = 2_000L) }
        assertTrue(result is ControlWrite.Ok)
        assertEquals(6L, (result as ControlWrite.Ok).revision)
        assertEquals(ShaCheck.OK, AtomicControlFile.verifySha(controlFile(root, "modes.json")))
        val read = plane.readModes()
        assertEquals(6L, (read as ControlRead.Ok).value.revision)
    }

    @Test
    fun sharedCorruptFallsBackToPrev() {
        val root = root()
        val plane = plane(root)
        assertTrue(plane.writeSharedSuperuser { it.copy(revision = 2, entries = listOf(TestFixtures.grantIntent(uid = 1))) } is ControlWrite.Ok)
        assertTrue(plane.writeSharedSuperuser { it.copy(revision = 3, entries = listOf(TestFixtures.grantIntent(uid = 2))) } is ControlWrite.Ok)
        val main = File(root, "shared/superuser.json")
        assertTrue(File(root, "shared/superuser.json.prev").isFile)
        main.writeText("{ corrupt")
        val diagnostics = mutableListOf<String>()
        val read = plane(root, diagnostics).readSharedSuperuser()
        assertTrue(read is ControlRead.Ok)
        assertEquals(2L, (read as ControlRead.Ok).value.revision)
        assertTrue(diagnostics.contains(ControlErrors.SHARED_ROLLED_BACK))
    }

    @Test
    fun sharedBothCorruptNeverRebuildsEmpty() {
        val root = root()
        val plane = plane(root)
        plane.writeSharedSuperuser { it.copy(revision = 2) }
        plane.writeSharedSuperuser { it.copy(revision = 3) }
        File(root, "shared/superuser.json").writeText("{ corrupt")
        File(root, "shared/superuser.json.prev").writeText("{ also corrupt")
        val read = plane(root).readSharedSuperuser()
        assertTrue(read is ControlRead.Corrupt)
        assertEquals(ControlErrors.SHARED_CORRUPT, (read as ControlRead.Corrupt).code)
        assertTrue(File(root, "shared/superuser.json").isFile)
    }

    @Test
    fun installedCorruptTreatedAsMissing() {
        val root = root()
        writeControl(root, "installed.json", TestFixtures.installedFile())
        controlFile(root, "installed.json").writeText("not json")
        val read = plane(root).readInstalled()
        assertTrue(read is ControlRead.Missing)
    }

    @Test
    fun selinuxPolicyWrittenIsTampered() {
        val root = root()
        writeControl(root, "selinux.json", TestFixtures.selinuxFile(policyWritten = true))
        val read = plane(root).readSelinux()
        assertTrue(read is ControlRead.Corrupt)
        assertEquals(ControlErrors.CONTROL_TAMPERED, (read as ControlRead.Corrupt).code)
    }

    @Test
    fun switchCorruptGoesRecoveryRequired() {
        val root = root()
        controlFile(root, "switch.json").writeText("{ broken")
        val read = plane(root).readSwitchHead()
        assertTrue(read is ControlRead.Corrupt)
        assertEquals(ControlErrors.SWITCH_CORRUPT, (read as ControlRead.Corrupt).code)
    }

    @Test
    fun publishCorruptTreatedAsMissing() {
        val root = root()
        writeControl(root, "publish.json", TestFixtures.publishFile())
        controlFile(root, "publish.json").writeText("oops")
        assertTrue(plane(root).readPublish() is ControlRead.Missing)
    }

    @Test
    fun missingFilesAreMissingNotDefaults() {
        val plane = plane(root())
        assertTrue(plane.readModes() is ControlRead.Missing)
        assertTrue(plane.readInstalled() is ControlRead.Missing)
        assertTrue(plane.readSwitchHead() is ControlRead.Missing)
        assertTrue(plane.readSharedSuperuser() is ControlRead.Missing)
        assertFalse(plane.readModes() is ControlRead.Ok)
    }

    @Test
    fun appendEvidenceAndStepWork() {
        val root = root()
        val plane = plane(root)
        plane.appendEvidence(
            EvidenceLine(at = 1, bootId = "boot-1", kind = "DETECT", result = EvidenceLine.OK),
        )
        val lines = File(root, "control/evidence.jsonl").readLines().filter { it.isNotBlank() }
        assertEquals(1, lines.size)
        val first = plane.appendStep("sw-1", "{\"seq\":1,\"op\":\"PREPARED\"}")
        val second = plane.appendStep("sw-1", "{\"seq\":2,\"op\":\"MOVE_INTENT\"}")
        assertEquals(1L, first)
        assertEquals(2L, second)
        assertTrue(File(root, "boot/work/sw-1/journal.jsonl").isFile)
    }
}
