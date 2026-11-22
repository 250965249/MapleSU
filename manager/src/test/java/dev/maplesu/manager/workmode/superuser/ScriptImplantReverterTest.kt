package dev.maplesu.manager.workmode.superuser

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** W19 撤回脚本：有原件恢复原件 / 无原件删 shim / 软链式植入清 side library / 幂等。 */
class ScriptImplantReverterTest {
    private val sha = "a".repeat(64)

    private class RecordingRoot(var code: Int = 0) : RootScriptRunner {
        val scripts = mutableListOf<String>()
        override fun run(script: String): RootScriptResult {
            scripts += script
            return RootScriptResult(code, if (code == 0) "REVERTED" else "failed")
        }
    }

    private fun intent(
        kind: String = ImplantKinds.WIRING,
        originalAbsent: Boolean = false,
        originalBackupPath: String? = "/adb/originals/com.example.app/wiring-libfoo.so.bin",
    ) = ImplantIntent(
        packageName = "com.example.app",
        uid = 10_200,
        deliverPath = "/data/app/com.example.app/lib/arm64/su",
        deliverSha256 = sha,
        wiringTargetLib = "/data/app/com.example.app/lib/arm64/libfoo.so",
        wiringOriginalSha256 = sha,
        createdDirs = listOf("/data/app/com.example.app/lib/arm64"),
        pathInjection = kind == ImplantKinds.PATH_INJECTION,
        recordedAt = 1_000L,
        kind = kind,
        originalAbsent = originalAbsent,
        originalBackupPath = if (originalAbsent) null else originalBackupPath,
        originalSha256 = if (originalAbsent) null else sha,
        originalMode = 0x1A4,
        originalUid = 10123,
        originalGid = 10123,
    )

    @Test
    fun deliveryWithAbsentOriginalDeletesShim() {
        val root = RecordingRoot()
        val reverter = ScriptImplantReverter(root)
        assertTrue(reverter.revert(intent(kind = ImplantKinds.DELIVERY, originalAbsent = true)))
        val script = root.scripts.single()
        assertTrue(script.contains("rm -f '/data/app/com.example.app/lib/arm64/su'"))
        assertFalse(script.contains("cp -f"))
    }

    @Test
    fun deliveryWithBackupRestoresOriginalAndMetadata() {
        val root = RecordingRoot()
        val reverter = ScriptImplantReverter(root)
        val target = intent(kind = ImplantKinds.DELIVERY)
        assertTrue(reverter.revert(target))
        val script = root.scripts.single()
        assertTrue(script.contains("cp -f '/adb/originals/com.example.app/wiring-libfoo.so.bin'"))
        assertTrue(script.contains("chown 10123:10123"))
        assertTrue(script.contains("chmod 644"))
        assertTrue(script.contains("sha256sum"))
        assertFalse(script.contains("rm -f '/data/app/com.example.app/lib/arm64/su'"))
    }

    @Test
    fun wiringRestoresLibraryAndRemovesSideLibraries() {
        val root = RecordingRoot()
        assertTrue(ScriptImplantReverter(root).revert(intent()))
        val script = root.scripts.single()
        assertTrue(script.contains("'/data/app/com.example.app/lib/arm64/libfoo.so'"))
        assertTrue(script.contains("-user 0"))
        assertTrue(script.contains("-name 'lib*'"))
        // 清理我们新建的目录（rmdir 非致命）。
        assertTrue(script.contains("rmdir '/data/app/com.example.app/lib/arm64'"))
    }

    @Test
    fun pathInjectionIsTransientNoopButSucceeds() {
        val root = RecordingRoot()
        assertTrue(ScriptImplantReverter(root).revert(intent(kind = ImplantKinds.PATH_INJECTION)))
        val script = root.scripts.single()
        assertFalse(script.contains("cp -f"))
        assertFalse(script.contains("rm -f"))
        assertTrue(script.contains("REVERTED"))
    }

    @Test
    fun runnerFailureReturnsFalse() {
        val root = RecordingRoot(code = 1)
        assertFalse(ScriptImplantReverter(root).revert(intent(kind = ImplantKinds.DELIVERY, originalAbsent = true)))
    }

    @Test
    fun missingBackupPathFailsWithoutRunningRoot() {
        val root = RecordingRoot()
        val broken = intent(kind = ImplantKinds.DELIVERY, originalBackupPath = null)
        assertFalse(ScriptImplantReverter(root).revert(broken))
        assertTrue(root.scripts.isEmpty())
    }

    @Test
    fun scriptsNeverContainCredentialOrRootKey() {
        val root = RecordingRoot()
        val reverter = ScriptImplantReverter(root)
        reverter.revert(intent(kind = ImplantKinds.DELIVERY, originalAbsent = true))
        reverter.revert(intent(kind = ImplantKinds.DELIVERY))
        reverter.revert(intent(kind = ImplantKinds.WIRING))
        reverter.revert(intent(kind = ImplantKinds.PATH_INJECTION))
        for (script in root.scripts) {
            for (forbidden in listOf("credential", "MPLSUKEY", "rootKey", "stealth_code", "token")) {
                assertFalse(forbidden, script.contains(forbidden))
            }
        }
        assertEquals(4, root.scripts.size)
    }
}
