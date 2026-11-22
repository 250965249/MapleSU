package dev.maplesu.manager.workmode.superuser

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files

/** W19：root 侧备份脚本 + 证据解析 + 备份工作流（主机 fake root）。 */
class LiteImplantBackupTest {
    private val sha = "a".repeat(64)

    private class FakeRoot(private val handler: (String) -> RootScriptResult) : RootScriptRunner {
        val scripts = mutableListOf<String>()
        override fun run(script: String): RootScriptResult {
            scripts += script
            return handler(script)
        }
    }

    private fun tempRoot(): File = Files.createTempDirectory("maplesu-implant-backup-").toFile()

    private fun backupPathOf(script: String): String? {
        val match = Regex("cp -f '([^']*)' '([^']*)'").find(script) ?: return null
        return match.groupValues[2]
    }

    @Test
    fun backupScriptQuotesPathsAndWritesEvidence() {
        val script = LiteImplantScripts.backup("/data/app/x y/lib/su", "/adb/originals/x/deliver-su.bin")
        assertTrue(script.startsWith("set -eu"))
        assertTrue(script.contains("'/data/app/x y/lib/su'"))
        assertTrue(script.contains("chmod 0600"))
        assertTrue(script.contains("chown 0:0"))
        assertTrue(script.contains("sha256sum"))
        assertTrue(script.contains("ORIGINAL:SAVED"))
        assertTrue(script.contains("ORIGINAL:ABSENT"))
        // 隐私：脚本不得出现凭据/our client magic/rootKey。
        for (forbidden in listOf("credential", "MPLSUKEY", "rootKey", "stealth_code")) {
            assertFalse(forbidden, script.contains(forbidden))
        }
    }

    @Test
    fun parseSavedEvidence() {
        val evidence = LiteImplantScripts.parseBackup("noise\n$sha\nORIGINAL:SAVED:$sha:10123:10123:700\n")
        assertTrue(evidence != null)
        assertFalse(evidence!!.originalAbsent)
        assertEquals(sha, evidence.sha256)
        assertEquals(10123, evidence.uid)
        assertEquals(10123, evidence.gid)
        assertEquals(0x1C0, evidence.mode)
    }

    @Test
    fun parseAbsentEvidence() {
        val evidence = LiteImplantScripts.parseBackup("ORIGINAL:ABSENT\n")
        assertTrue(evidence!!.originalAbsent)
        assertNull(evidence.sha256)
    }

    @Test
    fun parseMalformedEvidenceReturnsNull() {
        assertNull(LiteImplantScripts.parseBackup(""))
        assertNull(LiteImplantScripts.parseBackup("ORIGINAL:SAVED:not-a-sha:1:1:700"))
        assertNull(LiteImplantScripts.parseBackup("garbage"))
    }

    @Test
    fun restoreScriptRestoresMetadataAndVerifiesSha() {
        val script = LiteImplantScripts.restoreOriginal(
            backupPath = "/adb/originals/x/wiring-libfoo.so.bin",
            targetPath = "/data/app/x/lib/arm64/libfoo.so",
            sha256 = sha,
            uid = 10123,
            gid = 10123,
            mode = 0x1C0,
        )
        assertTrue(script.contains("cp -f '/adb/originals/x/wiring-libfoo.so.bin' '/data/app/x/lib/arm64/libfoo.so'"))
        assertTrue(script.contains("chown 10123:10123"))
        assertTrue(script.contains("chmod 700"))
        assertTrue(script.contains("sha256sum"))
        assertTrue(script.contains("exit 4"))
    }

    @Test
    fun removeTargetScriptIsIdempotent() {
        val script = LiteImplantScripts.removeTarget("/data/app/x/lib/arm64/su")
        assertTrue(script.contains("rm -f '/data/app/x/lib/arm64/su'"))
        assertTrue(script.contains("exit 3"))
    }

    @Test
    fun cleanupCreatedDirsIsReversedAndNonFatal() {
        val script = LiteImplantScripts.cleanupCreatedDirs(
            listOf("/data/app/x/lib/arm64", "/data/app/x/lib"),
        )
        val first = script.indexOf("rmdir '/data/app/x/lib/arm64'")
        val second = script.indexOf("rmdir '/data/app/x/lib'")
        assertTrue(first in 0 until second)
        assertTrue(script.contains("|| true"))
    }

    @Test
    fun removeSideLibrariesOnlyRemovesRootOwned() {
        val script = LiteImplantScripts.removeSideLibraries("/data/app/x/lib/arm64")
        assertTrue(script.contains("-name 'lib*'"))
        assertTrue(script.contains("-user 0"))
        assertTrue(script.contains("rm -f"))
        assertTrue(script.contains("if [ -d '/data/app/x/lib/arm64' ]"))
    }

    @Test
    fun workflowPrepareDeliveryAbsentIsInactiveIntent() {
        val root = tempRoot()
        try {
            val runner = FakeRoot { RootScriptResult(0, "ORIGINAL:ABSENT\n") }
            val workflow = LiteImplantBackupWorkflow(runner, root)
            val preparation = workflow.prepareDelivery(
                packageName = "com.example.app",
                uid = 10_200,
                deliverPath = "/data/app/com.example.app/lib/arm64/su",
                deliverSha256 = sha,
                createdDirs = listOf("/data/app/com.example.app/lib/arm64"),
            )
            assertTrue(preparation.ok)
            val intent = preparation.intent!!
            assertEquals(ImplantKinds.DELIVERY, intent.kind)
            assertTrue(intent.originalAbsent)
            assertFalse(intent.active)
            assertNull(intent.originalBackupPath)
            assertEquals(listOf("/data/app/com.example.app/lib/arm64"), intent.createdDirs)
            assertEquals(1, runner.scripts.size)
        } finally {
            root.deleteRecursively()
        }
    }

    @Test
    fun workflowPrepareWiringSavedRequiresRealBackupFile() {
        val root = tempRoot()
        try {
            val runner = FakeRoot { script ->
                val backup = backupPathOf(script) ?: return@FakeRoot RootScriptResult(1, "no cp")
                File(backup).parentFile?.mkdirs()
                File(backup).writeText("original-library")
                RootScriptResult(0, "ORIGINAL:SAVED:$sha:10123:10123:644\n")
            }
            val workflow = LiteImplantBackupWorkflow(runner, root)
            val preparation = workflow.prepareWiring(
                packageName = "com.example.app",
                uid = 10_200,
                targetLibraryPath = "/data/app/com.example.app/lib/arm64/libfoo.so",
                deliverPath = "/data/app/com.example.app/lib/arm64/su",
                deliverSha256 = sha,
            )
            assertTrue(preparation.ok)
            val intent = preparation.intent!!
            assertEquals(ImplantKinds.WIRING, intent.kind)
            assertFalse(intent.originalAbsent)
            assertEquals("/data/app/com.example.app/lib/arm64/libfoo.so", intent.wiringTargetLib)
            assertTrue(File(intent.originalBackupPath!!).isFile)
            assertEquals(0x1A4, intent.originalMode)
            assertTrue(FileOriginalBackupStore(root).hasOriginal(intent))
        } finally {
            root.deleteRecursively()
        }
    }

    @Test
    fun workflowRunnerFailureFailsClosed() {
        val root = tempRoot()
        try {
            val workflow = LiteImplantBackupWorkflow(FakeRoot { RootScriptResult(1, "denied") }, root)
            val preparation = workflow.prepareDelivery("com.example.app", 1, "/x/su", sha)
            assertFalse(preparation.ok)
            assertEquals(LiteImplantCodes.BACKUP_FAILED, preparation.code)
            assertNull(preparation.intent)
        } finally {
            root.deleteRecursively()
        }
    }

    @Test
    fun workflowClaimsSavedButBackupMissingFailsClosed() {
        val root = tempRoot()
        try {
            // root 报告 SAVED 但备份文件不可见（协议不一致）→ 必须失败，不能放行写入。
            val workflow = LiteImplantBackupWorkflow(
                FakeRoot { RootScriptResult(0, "ORIGINAL:SAVED:$sha:0:0:644\n") },
                root,
            )
            val preparation = workflow.prepareDelivery("com.example.app", 1, "/x/su", sha)
            assertFalse(preparation.ok)
            assertEquals(LiteImplantCodes.BACKUP_FAILED, preparation.code)
        } finally {
            root.deleteRecursively()
        }
    }
}
