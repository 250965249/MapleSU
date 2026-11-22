package dev.maplesu.manager.workmode.superuser

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files

/** W19 recorder：先登记未激活、成功后激活；PATH 注入无需备份；provider 安装/复位。 */
class LiteImplantRecorderTest {
    private val sha = "a".repeat(64)

    private class FakeRoot(private val handler: (String) -> RootScriptResult) : RootScriptRunner {
        override fun run(script: String): RootScriptResult = handler(script)
    }

    private fun tempRoot(): File = Files.createTempDirectory("maplesu-implant-recorder-").toFile()

    private fun backupPathOf(script: String): String? =
        Regex("cp -f '([^']*)' '([^']*)'").find(script)?.groupValues?.get(2)

    @Test
    fun beforeDeliveryRecordsInactiveThenAfterActivates() {
        val root = tempRoot()
        try {
            val runner = FakeRoot { RootScriptResult(0, "ORIGINAL:ABSENT\n") }
            val (recorder, registry) = createLiteImplantRecorder(root, runner)
            val preparation = recorder.beforeDelivery(
                packageName = "com.example.app",
                uid = 10_200,
                deliverPath = "/data/app/com.example.app/lib/arm64/su",
                deliverSha256 = sha,
                createdDirs = listOf("/data/app/com.example.app/lib/arm64"),
                now = 1_000L,
            )
            assertTrue(preparation.ok)
            val pending = registry.pending().single()
            assertFalse("recorded before write must be inactive", pending.active)
            assertEquals(ImplantKinds.DELIVERY, pending.kind)

            recorder.afterDelivery(preparation)
            assertTrue(registry.pending().single().active)
            assertTrue(registry.hasOriginals())
        } finally {
            root.deleteRecursively()
        }
    }

    @Test
    fun beforeWiringRecordsBackupEvidenceAndActivates() {
        val root = tempRoot()
        try {
            val runner = FakeRoot { script ->
                val backup = backupPathOf(script) ?: return@FakeRoot RootScriptResult(1, "no cp")
                File(backup).parentFile?.mkdirs()
                File(backup).writeText("original")
                RootScriptResult(0, "ORIGINAL:SAVED:$sha:10123:10123:644\n")
            }
            val (recorder, registry) = createLiteImplantRecorder(root, runner)
            val preparation = recorder.beforeWiring(
                packageName = "com.example.app",
                uid = 10_200,
                targetLibraryPath = "/data/app/com.example.app/lib/arm64/libfoo.so",
                deliverPath = "/data/app/com.example.app/lib/arm64/su",
                deliverSha256 = sha,
                createdDirs = listOf("/data/app/com.example.app/lib/arm64"),
                now = 1_000L,
            )
            assertTrue(preparation.ok)
            val intent = registry.pending().single()
            assertEquals(ImplantKinds.WIRING, intent.kind)
            assertTrue(intent.originalBackupPath!!.isNotBlank())
            assertTrue(registry.hasOriginals())
            recorder.afterWiring(preparation)
            assertTrue(registry.pending().single().active)
        } finally {
            root.deleteRecursively()
        }
    }

    @Test
    fun recordPathInjectionNeedsNoBackup() {
        val root = tempRoot()
        try {
            val runner = FakeRoot { RootScriptResult(0, "ORIGINAL:ABSENT\n") }
            val (recorder, registry) = createLiteImplantRecorder(root, runner)
            val preparation = recorder.recordPathInjection(
                packageName = "com.example.app",
                uid = 10_200,
                deliverPath = "/data/app/com.example.app/lib/arm64/su",
                deliverSha256 = "",
                now = 1_000L,
            )
            assertTrue(preparation.ok)
            val intent = registry.pending().single()
            assertEquals(ImplantKinds.PATH_INJECTION, intent.kind)
            assertTrue(intent.originalAbsent)
            assertTrue(intent.active)
            assertTrue(registry.hasOriginals())
        } finally {
            root.deleteRecursively()
        }
    }

    @Test
    fun registryWriteFailureFailsClosed() {
        val root = tempRoot()
        try {
            val throwing = object : LiteImplantRegistry {
                override fun record(intent: ImplantIntent) = error("disk full")
                override fun pending(): List<ImplantIntent> = emptyList()
                override fun revert(packageName: String): RevertReport = RevertReport(true)
                override fun hasOriginals(): Boolean = false
            }
            val workflow = LiteImplantBackupWorkflow(
                FakeRoot { RootScriptResult(0, "ORIGINAL:ABSENT\n") },
                root,
            )
            val preparation = RegistryLiteImplantRecorder(throwing, workflow).beforeDelivery(
                "com.example.app", 1, "/x/su", sha, emptyList(), 1L,
            )
            assertFalse(preparation.ok)
            assertEquals(LiteImplantCodes.REGISTRY_WRITE_FAILED, preparation.code)
        } finally {
            root.deleteRecursively()
        }
    }

    @Test
    fun providerInstallAndReset() {
        try {
            assertNull(LiteImplantRecorderProvider.current())
            val fake = object : LiteImplantRecorder {
                override fun beforeDelivery(
                    packageName: String, uid: Int, deliverPath: String,
                    deliverSha256: String, createdDirs: List<String>, now: Long,
                ) = ImplantPreparation(ok = true)

                override fun afterDelivery(preparation: ImplantPreparation) = Unit
                override fun beforeWiring(
                    packageName: String, uid: Int, targetLibraryPath: String, deliverPath: String,
                    deliverSha256: String, createdDirs: List<String>, now: Long,
                ) = ImplantPreparation(ok = true)

                override fun afterWiring(preparation: ImplantPreparation) = Unit
                override fun recordPathInjection(
                    packageName: String, uid: Int, deliverPath: String, deliverSha256: String, now: Long,
                ) = ImplantPreparation(ok = true)
            }
            LiteImplantRecorderProvider.install(fake)
            assertSame(fake, LiteImplantRecorderProvider.current())
        } finally {
            LiteImplantRecorderProvider.resetForTest()
        }
        assertNull(LiteImplantRecorderProvider.current())
    }
}
