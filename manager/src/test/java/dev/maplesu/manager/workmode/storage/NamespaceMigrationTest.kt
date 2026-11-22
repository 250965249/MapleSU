package dev.maplesu.manager.workmode.storage

import dev.maplesu.manager.workmode.TestFixtures
import dev.maplesu.manager.workmode.WorkMode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File
import java.io.IOException

/** 01 §8.1 `NamespaceMigrationTest`：一次性迁移 + 幂等 + legacy 保留 + 失败不翻转。 */
class NamespaceMigrationTest {
    private lateinit var prefsDir: File
    private lateinit var filesDir: File

    @Before
    fun setUp() {
        val root = TestFixtures.tempDir("namespace").toFile()
        prefsDir = File(root, "shared_prefs").apply { mkdirs() }
        filesDir = File(root, "files").apply { mkdirs() }
    }

    private fun migration(copier: ((File, File) -> Unit)? = null) =
        FileNamespaceMigration(prefsDir, filesDir, copier)

    private fun write(name: String, content: String = "<map/>") {
        File(prefsDir, "$name.xml").writeText(content)
    }

    @Test
    fun copiesLegacyToActiveNamespace() {
        write("settings", "<map>lite</map>")
        val report = migration().run(WorkMode.KSU)
        assertTrue(report.ok)
        assertTrue(report.copied.contains("settings_B.xml"))
        assertEquals("<map>lite</map>", File(prefsDir, "settings_B.xml").readText())
        // A 的源文件必须保持原位（A 仍用原名）。
        assertEquals("<map>lite</map>", File(prefsDir, "settings.xml").readText())
    }

    @Test
    fun keepsLegacyCopy() {
        write("settings", "<map>x</map>")
        val report = migration().run(WorkMode.KSU)
        assertTrue(File(prefsDir, "settings.legacy").isFile)
        assertEquals("<map>x</map>", File(prefsDir, "settings.legacy").readText())
        assertTrue(report.legacyKept.contains("settings.legacy"))
    }

    @Test
    fun idempotent_whenTargetExists() {
        write("settings")
        val first = migration().run(WorkMode.KSU)
        assertTrue(first.ok)
        val second = migration().run(WorkMode.KSU)
        assertTrue(second.ok)
        assertTrue(second.skipped.contains("settings_B.xml"))
        assertTrue(second.copied.isEmpty())
    }

    @Test
    fun failedCopyLeavesOriginal() {
        write("settings", "<map>keep</map>")
        val failing = migration(copier = { _, target ->
            if (target.name == "settings_B.xml") throw IOException("MIGRATION_INJECTED")
            target.writeText("<map/>")
        })
        val report = failing.run(WorkMode.KSU)
        assertFalse(report.ok)
        assertTrue(report.failed.contains("settings_B.xml"))
        assertTrue(File(prefsDir, "settings.xml").isFile)
        assertFalse(File(prefsDir, "settings_B.xml").exists())
    }

    @Test
    fun doesNotTouchOtherModeNamespace() {
        write("settings", "<map>a</map>")
        File(prefsDir, "installer.xml").writeText("<map/>")
        val report = migration().run(WorkMode.LITE)
        assertTrue(report.ok)
        assertFalse(File(prefsDir, "settings_B.xml").exists())
        assertFalse(File(prefsDir, "installer_B.xml").exists())
        assertEquals("<map>a</map>", File(prefsDir, "settings.xml").readText())
        // A 模式也应保留 legacy 回退副本。
        assertTrue(File(prefsDir, "settings.legacy").isFile)
    }

    @Test
    fun installerMigratesToInstallerB_onlyWhenKsu() {
        write("settings")
        write("installer", "<map task=\"7\"/>")
        migration().run(WorkMode.LITE)
        assertFalse(File(prefsDir, "installer_B.xml").exists())

        val root = TestFixtures.tempDir("namespace-b").toFile()
        val prefsB = File(root, "shared_prefs").apply { mkdirs() }
        val filesB = File(root, "files").apply { mkdirs() }
        File(prefsB, "settings.xml").writeText("<map/>")
        File(prefsB, "installer.xml").writeText("<map task=\"7\"/>")
        val report = FileNamespaceMigration(prefsB, filesB).run(WorkMode.KSU)
        assertTrue(report.ok)
        assertEquals("<map task=\"7\"/>", File(prefsB, "installer_B.xml").readText())
    }

    @Test
    fun aOnlyPrefsAreNotMigratedOrRenamed() {
        write("settings")
        write("maplesu-ultra", "<map rootKey=\"secret\"/>")
        val report = migration().run(WorkMode.KSU)
        assertTrue(report.ok)
        assertTrue(File(prefsDir, "maplesu-ultra.xml").isFile)
        assertFalse(File(prefsDir, "maplesu-ultra_B.xml").exists())
        assertFalse(File(prefsDir, "maplesu-ultra_A.xml").exists())
    }

    @Test
    fun filesDirKsuCreatedOnlyForKsu() {
        write("settings")
        migration().run(WorkMode.KSU)
        assertTrue(File(filesDir, "ksu").isDirectory)

        val root = TestFixtures.tempDir("namespace-lite").toFile()
        val prefs = File(root, "shared_prefs").apply { mkdirs() }
        val files = File(root, "files").apply { mkdirs() }
        File(prefs, "settings.xml").writeText("<map/>")
        FileNamespaceMigration(prefs, files).run(WorkMode.LITE)
        assertFalse(File(files, "ksu").exists())
    }

    @Test
    fun needsMigrationSemantics() {
        assertFalse(migration().needsMigration())
        write("settings")
        assertTrue(migration().needsMigration())
        migration().run(WorkMode.LITE)
        assertFalse(migration().needsMigration())
    }
}
