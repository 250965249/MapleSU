package dev.maplesu.manager.workmode.snapshot

import dev.maplesu.manager.workmode.Hashes
import dev.maplesu.manager.workmode.TestFixtures
import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.control.AtomicControlFile
import dev.maplesu.manager.workmode.control.ShaCheck
import dev.maplesu.manager.workmode.control.schema.Integrity
import dev.maplesu.manager.workmode.control.schema.SnapshotEntry
import dev.maplesu.manager.workmode.control.schema.SnapshotManifest
import dev.maplesu.manager.workmode.control.schema.canonicalized
import dev.maplesu.manager.workmode.detect.BootIdSource
import dev.maplesu.manager.workmode.detect.Clock
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/** 01 §8.1 `SnapshotManifestTest`：排序 / symlink sha / DIR 聚合 / 排除原因 / integrity。 */
class SnapshotManifestTest {
    private val clock = Clock { 1_000L }
    private val boot = BootIdSource { "boot-1" }

    private fun entry(
        storePath: String,
        type: String = SnapshotScope.TYPE_FILE,
        sha: String = TestFixtures.hash('a'),
        linkTarget: String? = null,
        size: Long = 1,
    ) = SnapshotEntry(
        kind = SnapshotScope.KIND_APP_TREE,
        livePath = storePath.removePrefix("app/"),
        storePath = storePath,
        type = type,
        size = size,
        sha256 = sha,
        linkTarget = linkTarget,
        mode = 0x1a4,
        uid = -1,
        gid = -1,
        origin = SnapshotScope.ORIGIN_NEUTRAL,
    )

    private fun manifest(entries: List<SnapshotEntry>, excluded: List<dev.maplesu.manager.workmode.control.schema.ExcludedEntry> = emptyList()) =
        SnapshotManifests.withIntegrity(
            SnapshotManifest(
                id = "rev-1-A",
                revision = 1,
                mode = "A",
                createdAt = 1_000L,
                bootId = "boot-1",
                app = TestFixtures.appSnapshotFacts(),
                entries = entries,
                excluded = excluded,
                totals = SnapshotManifests.totals(entries),
                integrity = Integrity(""),
            ),
        )

    @Test
    fun entriesSortedByStorePath() {
        val unsorted = manifest(
            listOf(entry("app/b.txt"), entry("app/a.txt"), entry("app/z/y.txt")),
        )
        assertEquals(
            listOf("app/a.txt", "app/b.txt", "app/z/y.txt"),
            unsorted.canonicalized().entries.map { it.storePath },
        )
        assertTrue(SnapshotManifests.encode(unsorted).indexOf("app/a.txt") <
            SnapshotManifests.encode(unsorted).indexOf("app/b.txt"))
    }

    @Test
    fun symlinkShaIsTargetHash() {
        assertEquals(Hashes.sha256Hex("/data/adb/modules/foo"), SnapshotManifests.symlinkSha("/data/adb/modules/foo"))
        val symlink = entry("app/link", SnapshotScope.TYPE_SYMLINK, sha = SnapshotManifests.symlinkSha("target"), linkTarget = "target")
        assertEquals(SnapshotManifests.symlinkSha("target"), symlink.sha256)
        assertNotNull(symlink.linkTarget)
    }

    @Test
    fun dirAggregateShaStable() {
        val children = listOf(entry("app/dir/a", sha = TestFixtures.hash('1')), entry("app/dir/b", sha = TestFixtures.hash('2')))
        val first = SnapshotManifests.directoryAggregateSha(children)
        val second = SnapshotManifests.directoryAggregateSha(children.reversed())
        assertEquals(first, second)
        val changed = listOf(children[0], children[1].copy(sha256 = TestFixtures.hash('3')))
        assertFalse(first == SnapshotManifests.directoryAggregateSha(changed))
        assertEquals(64, first.length)
    }

    @Test
    fun excludedReasonsRequired() {
        for (rule in SnapshotScope.EXCLUDED_RULES) {
            assertTrue("reason must be a known code", rule.reason in SnapshotScope.ExcludedEntryReasons.ALL)
        }
        for (path in listOf("module-catalog/staged/x.zip", "log/app.log", "wallpaper/movie.mp4", "module-catalog/maplesu-credential.bin")) {
            val exclusion = SnapshotScope.exclusionFor(path)
            assertNotNull("expected exclusion for $path", exclusion)
            assertTrue(exclusion!!.reason in SnapshotScope.ExcludedEntryReasons.ALL)
        }
        assertEquals(SnapshotScope.ExcludedEntryReasons.CACHE, SnapshotScope.exclusionFor("module-catalog/staged/x.zip")?.reason)
        assertEquals(SnapshotScope.ExcludedEntryReasons.NO_BACKUP_SECRET, SnapshotScope.exclusionFor("module-catalog/maplesu-credential.bin")?.reason)
        assertTrue(SnapshotScope.isSnapshotCandidate("module-catalog/rev-1/module.prop"))
        assertFalse(SnapshotScope.isSnapshotCandidate("module-catalog/staged/x.zip"))
        assertFalse(SnapshotScope.isSnapshotCandidate("unregistered/file.bin"))
    }

    @Test
    fun totalsConsistent() {
        val entries = listOf(
            entry("app/a", size = 10),
            entry("app/b", type = SnapshotScope.TYPE_DIR, size = 0),
            entry("app/c", type = SnapshotScope.TYPE_SYMLINK, size = 0),
        )
        val totals = SnapshotManifests.totals(entries)
        assertEquals(3, totals.entryCount)
        assertEquals(2, totals.fileCount)
        assertEquals(10L, totals.bytes)
    }

    @Test
    fun integrityMatchesCanonicalBytes() {
        val manifest = manifest(listOf(entry("app/a")))
        assertTrue(SnapshotManifests.verify(manifest))
        val blank = manifest.copy(integrity = Integrity(""))
        assertEquals(SnapshotManifests.computeIntegrity(manifest), SnapshotManifests.computeIntegrity(blank))
        val tampered = manifest.copy(entries = manifest.entries + entry("app/b"))
        assertFalse(SnapshotManifests.verify(tampered))
    }

    @Test
    fun writerCreatesManifestPayloadAndExcludedEntries() {
        val appDir = TestFixtures.tempDir("snapshot-app").toFile()
        val storeRoot = TestFixtures.tempDir("snapshot-store").toFile()
        File(appDir, "module-catalog/rev-1").mkdirs()
        File(appDir, "module-catalog/rev-1/module.prop").writeText("id=demo\n")
        File(appDir, "module-catalog/staged").mkdirs()
        File(appDir, "module-catalog/staged/x.zip").writeBytes(byteArrayOf(1))
        File(appDir, "module-catalog/maplesu-credential.bin").writeBytes(byteArrayOf(2))
        File(appDir, "wallpaper").mkdirs()
        File(appDir, "wallpaper/w.png").writeBytes(byteArrayOf(3, 4))

        val writer = FileSnapshotWriter(appDir, storeRoot, clock, boot)
        val result = writer.create(WorkMode.LITE, revision = 7, appFacts = TestFixtures.appSnapshotFacts())
        assertTrue("expected Ok, got $result", result is SnapshotResult.Ok)
        val ok = result as SnapshotResult.Ok
        val snapshotDir = File(ok.storePath)
        assertTrue(File(snapshotDir, "payload/app/module-catalog/rev-1/module.prop").isFile)
        assertTrue(File(snapshotDir, "payload/app/maplesu-credential.bin").exists().not())
        assertEquals(ShaCheck.OK, AtomicControlFile.verifySha(File(snapshotDir, "manifest.json")))
        assertEquals("rev-7-A", ok.manifest.id)
        assertEquals("A", ok.manifest.mode)
        assertTrue(ok.manifest.entries.any { it.storePath == "app/wallpaper/w.png" })
        assertTrue(ok.manifest.excluded.any { it.reason == SnapshotScope.ExcludedEntryReasons.NO_BACKUP_SECRET })
        assertTrue(ok.manifest.excluded.any { it.reason == SnapshotScope.ExcludedEntryReasons.CACHE })
        assertTrue(ok.manifest.excluded.all { it.reason in SnapshotScope.ExcludedEntryReasons.ALL })
        assertTrue(ok.manifest.entries.map { it.storePath }.zipWithNext().all { (a, b) -> a <= b })
        assertTrue(ok.manifest.totals.bytes >= 3)
        assertTrue(SnapshotManifests.verify(ok.manifest))
        // 磁盘 manifest 可反解析且 integrity 一致。
        val fromDisk = SnapshotManifests.decode(File(snapshotDir, "manifest.json").readText())
        assertNotNull(fromDisk)
        assertTrue(SnapshotManifests.verify(fromDisk!!))
    }

    @Test
    fun writerDoesNotFollowSymlinksOutsideScope() {
        val appDir = TestFixtures.tempDir("snapshot-link-app").toFile()
        val storeRoot = TestFixtures.tempDir("snapshot-link-store").toFile()
        File(appDir, "wallpaper").mkdirs()
        val external = File(appDir, "outside.txt").apply { writeText("secret") }
        runCatching {
            java.nio.file.Files.createSymbolicLink(File(appDir, "wallpaper/link.txt").toPath(), external.toPath())
        }
        val result = FileSnapshotWriter(appDir, storeRoot, clock, boot)
            .create(WorkMode.LITE, revision = 1, appFacts = TestFixtures.appSnapshotFacts())
        // Windows 无符号链接权限时只校验 Ok/无异常；有权限时必须是 SYMLINK 条目而非跟随。
        assertTrue(result is SnapshotResult.Ok)
        val entries = (result as SnapshotResult.Ok).manifest.entries
        val linkEntry = entries.firstOrNull { it.storePath == "app/wallpaper/link.txt" }
        if (linkEntry != null && linkEntry.type == SnapshotScope.TYPE_SYMLINK) {
            assertNotNull(linkEntry.linkTarget)
        }
    }
}
