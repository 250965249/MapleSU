package dev.maplesu.manager.workmode.superuser

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files

class LiteImplantRegistryTest {
    private class FakeOriginals(var present: Boolean = true) : OriginalBackupStore {
        override fun hasOriginal(intent: ImplantIntent): Boolean = present
    }

    private class FakeReverter(var succeed: Boolean = true) : ImplantReverter {
        val reverted = mutableListOf<String>()
        override fun revert(intent: ImplantIntent): Boolean {
            reverted.add(intent.packageName)
            return succeed
        }
    }

    private fun fixture(
        originals: FakeOriginals = FakeOriginals(),
        reverter: FakeReverter = FakeReverter(),
    ): Triple<File, FileLiteImplantRegistry, Pair<FakeOriginals, FakeReverter>> {
        val root = Files.createTempDirectory("maplesu-implants-test-").toFile()
        return Triple(
            root,
            FileLiteImplantRegistry(root, originals, reverter),
            originals to reverter,
        )
    }

    private fun intent(
        packageName: String = Fixtures.APP,
        wiring: Boolean = true,
        pathInjection: Boolean = false,
    ) = ImplantIntent(
        packageName = packageName,
        uid = Fixtures.UID,
        deliverPath = "/data/app/$packageName/lib/arm64/su",
        deliverSha256 = Fixtures.hash('d'),
        wiringTargetLib = if (wiring) "/data/app/$packageName/lib/arm64/libfoo.so" else null,
        wiringOriginalSha256 = if (wiring) Fixtures.hash('e') else null,
        sideLibraryPath = if (wiring) "/data/app/$packageName/lib/arm64/libmaplesu_su.so" else null,
        createdDirs = listOf("/data/app/$packageName/lib/arm64"),
        pathInjection = pathInjection,
        recordedAt = 1_000L,
    )

    @Test
    fun recordAndPending() {
        val (root, registry, _) = fixture()
        try {
            registry.record(intent())
            assertEquals(1, registry.pending().size)
            assertEquals(Fixtures.APP, registry.pending().single().packageName)
        } finally {
            root.deleteRecursively()
        }
    }

    @Test
    fun recordReplacesSamePackage() {
        val (root, registry, _) = fixture()
        try {
            registry.record(intent())
            registry.record(intent().copy(deliverSha256 = Fixtures.hash('f')))
            assertEquals(1, registry.pending().size)
        } finally {
            root.deleteRecursively()
        }
    }

    @Test
    fun emptyRegistryHasOriginals() {
        val (root, registry, _) = fixture()
        try {
            assertTrue(registry.hasOriginals())
        } finally {
            root.deleteRecursively()
        }
    }

    @Test
    fun missingOriginalBlocksFullyIsolatedSwitch() {
        val originals = FakeOriginals(present = false)
        val (root, registry, _) = fixture(originals)
        try {
            registry.record(intent())
            assertFalse(registry.hasOriginals())
            val report = registry.revert(Fixtures.APP)
            assertEquals("LITE_IMPLANT_ORIGINAL_MISSING", report.code)
            assertEquals(1, registry.pending().size)
        } finally {
            root.deleteRecursively()
        }
    }

    @Test
    fun revertSuccessRemovesRecord() {
        val reverter = FakeReverter(succeed = true)
        val (root, registry, _) = fixture(reverter = reverter)
        try {
            registry.record(intent())
            val report = registry.revert(Fixtures.APP)
            assertTrue(report.ok)
            assertEquals(listOf(Fixtures.APP), reverter.reverted)
            assertTrue(registry.pending().isEmpty())
        } finally {
            root.deleteRecursively()
        }
    }

    @Test
    fun revertFailureKeepsRecordAndReportsCode() {
        val reverter = FakeReverter(succeed = false)
        val (root, registry, _) = fixture(reverter = reverter)
        try {
            registry.record(intent())
            val report = registry.revert(Fixtures.APP)
            assertFalse(report.ok)
            assertEquals("LITE_IMPLANT_REVERT_FAILED", report.code)
            assertEquals(1, registry.pending().size)
        } finally {
            root.deleteRecursively()
        }
    }

    @Test
    fun unknownPackageRevertIsNoOp() {
        val (root, registry, _) = fixture()
        try {
            registry.record(intent())
            val report = registry.revert("com.example.unknown")
            assertTrue(report.ok)
            assertEquals(1, registry.pending().size)
        } finally {
            root.deleteRecursively()
        }
    }

    @Test
    fun survivesNewInstance() {
        val (root, registry, _) = fixture()
        try {
            registry.record(intent())
            val reopened = FileLiteImplantRegistry(root, FakeOriginals(), FakeReverter(), TestClock())
            assertEquals(1, reopened.pending().size)
        } finally {
            root.deleteRecursively()
        }
    }

    @Test
    fun corruptFileFailsClosed() {
        val (root, registry, _) = fixture()
        try {
            File(root, "lite-implants.json").writeText("{broken")
            assertFalse(registry.hasOriginals())
            assertEquals("LITE_IMPLANT_REGISTRY_CORRUPT", registry.revert(Fixtures.APP).code)
        } finally {
            root.deleteRecursively()
        }
    }

    @Test
    fun multiplePackagesRevertOnlyOne() {
        val reverter = FakeReverter(succeed = true)
        val (root, registry, _) = fixture(reverter = reverter)
        try {
            registry.record(intent(Fixtures.APP))
            registry.record(intent(Fixtures.OTHER))
            assertTrue(registry.revert(Fixtures.APP).ok)
            assertEquals(listOf(Fixtures.OTHER), registry.pending().map { it.packageName })
        } finally {
            root.deleteRecursively()
        }
    }

    @Test
    fun fileOriginalStoreRequiresBackupOnlyWhenRestoring() {
        val root = Files.createTempDirectory("maplesu-implants-originals-").toFile()
        try {
            val store = FileOriginalBackupStore(root)
            val restoring = intent(wiring = true)
            assertFalse(store.hasOriginal(restoring))
            val original = File(root, "originals/${restoring.packageName}/${restoring.wiringOriginalSha256}")
            original.parentFile.mkdirs()
            original.writeText("original")
            assertTrue(store.hasOriginal(restoring))
            // 无原件修改（仅授权，不植入）不阻断。
            assertTrue(store.hasOriginal(intent(wiring = false)))
        } finally {
            root.deleteRecursively()
        }
    }
}
