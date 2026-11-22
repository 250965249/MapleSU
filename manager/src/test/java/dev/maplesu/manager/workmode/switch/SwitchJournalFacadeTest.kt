package dev.maplesu.manager.workmode.switch

import dev.maplesu.manager.workmode.TestFixtures
import dev.maplesu.manager.workmode.control.ControlErrors
import dev.maplesu.manager.workmode.control.ControlPlane
import dev.maplesu.manager.workmode.control.ControlRead
import dev.maplesu.manager.workmode.control.ControlWrite
import dev.maplesu.manager.workmode.control.ControlPermissions
import dev.maplesu.manager.workmode.control.EvidenceLine
import dev.maplesu.manager.workmode.control.FileControlPlane
import dev.maplesu.manager.workmode.control.schema.InstalledFile
import dev.maplesu.manager.workmode.control.schema.ModesFile
import dev.maplesu.manager.workmode.control.schema.PublishFile
import dev.maplesu.manager.workmode.control.schema.SelinuxFile
import dev.maplesu.manager.workmode.control.schema.SharedSuperuserFile
import dev.maplesu.manager.workmode.control.schema.SwitchHeadView
import dev.maplesu.manager.workmode.detect.BootIdSource
import dev.maplesu.manager.workmode.detect.Clock
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/** 01 §8.1 `SwitchJournalFacadeTest`：只测 App 侧只读门面。 */
class SwitchJournalFacadeTest {
    private val clock = Clock { 1_000L }
    private val boot = BootIdSource { "boot-1" }

    private fun root(): File = TestFixtures.tempDir("facade").toFile().also { ControlPermissions.ensureTree(it) }

    private fun facade(root: File) = FileSwitchJournalFacade(FileControlPlane(root, clock, boot), root)

    private fun writeSwitch(root: File, state: String, switchId: String = "sw-1") {
        val raw = """
            {"schema":1,"switchId":"$switchId","planSha256":"${"a".repeat(64)}","state":"$state",
             "stage":"S4","step":"4d","fromMode":"LITE","toMode":"KSU","startBootId":"boot-1",
             "attempts":{"bootVerifyFailures":0,"rebootRequests":1},
             "error":{"code":"","stage":""},"updatedAtUptimeMs":10}
        """.trimIndent()
        val target = File(root, "control/switch.json")
        target.parentFile?.mkdirs()
        target.writeText(raw)
    }

    private fun appendJournal(root: File, switchId: String, op: SwitchOp) {
        FileSwitchJournal(File(root, "boot/work/$switchId/journal.jsonl"), clock, boot).append(
            switchId = switchId, planSha256 = "a".repeat(64), stage = "S4", step = "4a", op = op,
        )
    }

    @Test
    fun currentParsesAllStates() {
        for (state in SwitchStateNames.ALL) {
            val root = root()
            writeSwitch(root, state)
            val head = facade(root).current()
            assertTrue("state=$state", head is ControlRead.Ok)
            assertEquals(state, (head as ControlRead.Ok).value.state)
            assertEquals(state in SwitchStateNames.PENDING, head.value.pending)
        }
    }

    @Test
    fun unknownStateIsPending() {
        val root = root()
        writeSwitch(root, "FUTURE_STATE")
        val head = (facade(root).current() as ControlRead.Ok).value
        assertTrue(head.pending)
    }

    @Test
    fun corruptJsonIsCorruptNotDefault() {
        val root = root()
        File(root, "control/switch.json").writeText("{ broken")
        val head = facade(root).current()
        assertTrue(head is ControlRead.Corrupt)
        assertEquals(ControlErrors.SWITCH_CORRUPT, (head as ControlRead.Corrupt).code)
        // 现场存在但读不出 → 保守按 pending 处理。
        assertTrue(facade(root).hasPending())
        File(root, "control/switch.json").writeText("{ broken")
    }

    @Test
    fun hasPendingTrueForAllPendingStates() {
        for (state in SwitchStateNames.PENDING) {
            val root = root()
            writeSwitch(root, state)
            assertTrue("state=$state", facade(root).hasPending())
        }
    }

    @Test
    fun hasPendingFalseForTerminal() {
        for (state in SwitchStateNames.TERMINAL) {
            val root = root()
            writeSwitch(root, state)
            assertFalse("state=$state", facade(root).hasPending())
        }
    }

    @Test
    fun scanIncompleteIgnoresTerminal() {
        val root = root()
        writeSwitch(root, SwitchStateNames.VERIFIED)
        assertTrue(facade(root).scanIncomplete().isEmpty())
    }

    @Test
    fun scanIncompleteFindsJournalWithoutSwitchJson() {
        val root = root()
        appendJournal(root, "sw-journal", SwitchOp.PREPARED)
        val facade = facade(root)
        assertTrue(facade.current() is ControlRead.Missing)
        assertTrue(facade.hasPending())
        val incomplete = facade.scanIncomplete()
        assertEquals(1, incomplete.size)
        assertEquals("sw-journal", incomplete.first().switchId)
        assertEquals(SwitchStateNames.BEGIN, incomplete.first().state)
    }

    @Test
    fun unavailableWithoutRoot() {
        val facade = FileSwitchJournalFacade(unreadablePlane(), root())
        val outcome = runBlocking { facade.requestReconcile() }
        assertTrue(outcome is ReconcileOutcome.Unavailable)
        assertEquals("NO_ROOT", (outcome as ReconcileOutcome.Unavailable).code)
    }

    @Test
    fun diagnosticsAreRedactedAndComplete() {
        val root = root()
        writeSwitch(root, SwitchStateNames.COMMIT)
        appendJournal(root, "sw-1", SwitchOp.MOVE_INTENT)
        val diagnostics = facade(root).exportDiagnostics("sw-1")
        assertTrue(diagnostics != null)
        diagnostics!!
        assertTrue(diagnostics.contains("state=COMMIT"))
        assertTrue(diagnostics.contains("journal.state=COMMIT"))
        assertFalse(diagnostics.contains("rootKey"))
        assertFalse(diagnostics.contains("credential"))
        assertFalse(diagnostics.contains("stealth_code"))
    }

    @Test
    fun diagnosticsMissingReturnsNull() {
        assertNull(facade(root()).exportDiagnostics("nope"))
    }

    private fun unreadablePlane(): ControlPlane = object : ControlPlane {
        override fun readModes(): ControlRead<ModesFile> = ControlRead.Unreadable("/m", "NO_ROOT")
        override fun readInstalled(): ControlRead<InstalledFile> = ControlRead.Unreadable("/i", "NO_ROOT")
        override fun readSwitchHead(): ControlRead<SwitchHeadView> = ControlRead.Unreadable("/s", "NO_ROOT")
        override fun readSharedSuperuser(): ControlRead<SharedSuperuserFile> = ControlRead.Unreadable("/u", "NO_ROOT")
        override fun readSelinux(): ControlRead<SelinuxFile> = ControlRead.Unreadable("/x", "NO_ROOT")
        override fun readPublish(): ControlRead<PublishFile> = ControlRead.Unreadable("/p", "NO_ROOT")
        override fun writeModes(transform: (ModesFile) -> ModesFile): ControlWrite<ModesFile> =
            ControlWrite.Rejected("NO_ROOT", "")
        override fun writeSharedSuperuser(
            transform: (SharedSuperuserFile) -> SharedSuperuserFile,
        ): ControlWrite<SharedSuperuserFile> = ControlWrite.Rejected("NO_ROOT", "")
        override fun appendEvidence(line: EvidenceLine) = Unit
        override fun appendStep(switchId: String, line: String): Long = 0L
    }
}
