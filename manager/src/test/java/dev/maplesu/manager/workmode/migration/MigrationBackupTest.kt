package dev.maplesu.manager.workmode.migration

import dev.maplesu.manager.workmode.control.AtomicControlFile
import dev.maplesu.manager.workmode.control.ControlJsonCodec
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/** 05 §2：备份目录 / manifest schema / 读回校验 / 保留策略（T-15、T-23）。 */
class MigrationBackupTest {
    @get:Rule val tmp = TemporaryFolder()

    private fun backup(): MigrationBackup =
        MigrationBackup(tmp.root, clock = { FIXED_NOW }, bootIdSource = { "boot-test" })

    private fun register(backup: MigrationBackup): BackupManifest {
        backup.ensureLayout(Fixtures.MIGRATION_ID)
        val source = Fixtures.write(tmp.root, "source/allowlist.txt", "records")
        val objectRef = backup.captureFile(
            Fixtures.MIGRATION_ID, source, "auth/ksu/allowlist",
            kind = "AUTH_ALLOWLIST", label = "allowlist",
        )
        val manifest = BackupManifest(
            migrationId = Fixtures.MIGRATION_ID,
            createdAtEpochMs = FIXED_NOW,
            createdBootId = "boot-test",
            objects = listOf(objectRef),
        )
        return backup.writeManifest(manifest)
    }

    @Test
    fun layoutCreatesDocumentedDirectories() {
        val backup = backup()
        val root = backup.ensureLayout(Fixtures.MIGRATION_ID)
        MigrationPaths.BACKUP_SUBDIRS.forEach { sub ->
            assertTrue("missing $sub", File(root, sub).isDirectory)
        }
        assertTrue(backup.secretsDir(Fixtures.MIGRATION_ID).isDirectory)
    }

    @Test
    fun captureFileWritesReadBackVerifiedObject() {
        val backup = backup()
        backup.ensureLayout(Fixtures.MIGRATION_ID)
        val source = Fixtures.write(tmp.root, "source/tree.tar", "payload")
        val objectRef = backup.captureFile(
            Fixtures.MIGRATION_ID, source, "external-data/tree.tar",
            kind = "EXTERNAL_DATA_TAR", label = "tree",
        )
        assertTrue(objectRef.readBack)
        assertEquals(MigrationHashes.sha256(source), objectRef.sha256)
        val target = backup.objectFile(Fixtures.MIGRATION_ID, "external-data/tree.tar")
        assertTrue(target.isFile)
    }

    @Test
    fun manifestRoundTripsAndVerifies() {
        val backup = backup()
        val manifest = register(backup)
        assertFalse(manifest.verified)
        val read = backup.readManifest(Fixtures.MIGRATION_ID)
        assertNotNull(read)
        assertEquals(Fixtures.MIGRATION_ID, read!!.migrationId)
        assertEquals(1, read.objects.size)
        assertTrue(backup.verify(Fixtures.MIGRATION_ID, read).ok)
        val verified = backup.markVerified(Fixtures.MIGRATION_ID, read)
        assertTrue(verified.verified)
        assertEquals(FIXED_NOW, verified.verifiedAtEpochMs)
        backup.requireVerified(verified)
    }

    @Test
    fun tamperedObjectFailsVerification() {
        val backup = backup()
        val manifest = register(backup)
        val target = backup.objectFile(Fixtures.MIGRATION_ID, "auth/ksu/allowlist")
        target.writeText("tampered")
        val verification = backup.verify(Fixtures.MIGRATION_ID, manifest)
        assertFalse(verification.ok)
        assertEquals(listOf("AUTH_ALLOWLIST.allowlist"), verification.mismatched)
        assertThrows(MigrationFailure::class.java) {
            backup.markVerified(Fixtures.MIGRATION_ID, manifest)
        }
    }

    @Test
    fun missingObjectFailsVerification() {
        val backup = backup()
        val manifest = register(backup)
        backup.objectFile(Fixtures.MIGRATION_ID, "auth/ksu/allowlist").delete()
        val verification = backup.verify(Fixtures.MIGRATION_ID, manifest)
        assertFalse(verification.ok)
        assertEquals(listOf("AUTH_ALLOWLIST.allowlist"), verification.missing)
    }

    @Test
    fun unverifiedManifestIsRejectedByGate() {
        val backup = backup()
        val manifest = register(backup)
        val failure = assertThrows(MigrationFailure::class.java) { backup.requireVerified(manifest) }
        assertEquals(MigrationCodes.BACKUP_NOT_VERIFIED, failure.code)
    }

    @Test
    fun schemaMismatchIsRejected() {
        val backup = backup()
        backup.ensureLayout(Fixtures.MIGRATION_ID)
        val file = MigrationPaths.manifest(tmp.root, Fixtures.MIGRATION_ID)
        AtomicControlFile.writeJson(
            file,
            """{"schema":2,"migrationId":"${Fixtures.MIGRATION_ID}","objects":[]}""",
        )
        val failure = assertThrows(MigrationFailure::class.java) {
            backup.readManifest(Fixtures.MIGRATION_ID)
        }
        assertEquals(MigrationCodes.MANIFEST_INVALID, failure.code)
    }

    @Test
    fun objectPathTraversalIsRejected() {
        val backup = backup()
        backup.ensureLayout(Fixtures.MIGRATION_ID)
        val failure = assertThrows(MigrationFailure::class.java) {
            backup.objectFile(Fixtures.MIGRATION_ID, "../escape")
        }
        assertEquals(MigrationCodes.MODULE_PATH_INVALID, failure.code)
    }

    @Test
    fun missingSourceFileIsRejected() {
        val backup = backup()
        backup.ensureLayout(Fixtures.MIGRATION_ID)
        val failure = assertThrows(MigrationFailure::class.java) {
            backup.captureFile(
                Fixtures.MIGRATION_ID, File(tmp.root, "nope"), "images/pre-boot.img",
                kind = "PARTITION_IMAGE", label = "pre",
            )
        }
        assertEquals(MigrationCodes.BACKUP_SOURCE_MISSING, failure.code)
    }

    @Test
    fun retentionRequiresM9UserConfirmationAndKeepWindow() {
        val backup = backup()
        backup.ensureLayout(Fixtures.MIGRATION_ID)
        assertFalse(backup.canPurge(Fixtures.MIGRATION_ID, FIXED_NOW + 10_000_000, userConfirmed = false))
        backup.writeRetention(Fixtures.MIGRATION_ID, keepUntilEpochMs = FIXED_NOW + 7 * DAY, readyToPurge = false)
        assertFalse(backup.canPurge(Fixtures.MIGRATION_ID, FIXED_NOW + 8 * DAY, userConfirmed = true))
        backup.markReadyToPurge(Fixtures.MIGRATION_ID, keepDays = 7)
        assertFalse(backup.canPurge(Fixtures.MIGRATION_ID, FIXED_NOW + DAY, userConfirmed = true))
        assertTrue(backup.canPurge(Fixtures.MIGRATION_ID, FIXED_NOW + 8 * DAY, userConfirmed = true))
    }

    @Test
    fun manifestIsCanonicalAndObjectListSorted() {
        val backup = backup()
        backup.ensureLayout(Fixtures.MIGRATION_ID)
        val first = backup.captureBytes(
            Fixtures.MIGRATION_ID, "a".toByteArray(), "our/a.bin", "CANDIDATE", "a",
        )
        val second = backup.captureBytes(
            Fixtures.MIGRATION_ID, "b".toByteArray(), "our/b.bin", "CANDIDATE", "b",
        )
        val written = backup.writeManifest(
            BackupManifest(
                migrationId = Fixtures.MIGRATION_ID,
                objects = listOf(second, first),
                restoreSet = listOf("init_boot", "boot"),
            ),
        )
        assertEquals(listOf(first.id, second.id), written.objects.map { it.id })
        assertEquals(listOf("boot", "init_boot"), written.restoreSet)
        val raw = AtomicControlFile.readUtf8(MigrationPaths.manifest(tmp.root, Fixtures.MIGRATION_ID))!!
        val decoded = ControlJsonCodec.decodeOrNull<BackupManifest>(raw)
        assertEquals(written, decoded)
    }

    @Test
    fun spaceEstimatorBlocksWhenFreeSpaceTooSmall() {
        val estimate = SpaceEstimator.estimate(
            partitionSizes = mapOf("boot" to 64L * 1024 * 1024, "init_boot" to 8L * 1024 * 1024),
            restoreSet = setOf("init_boot"),
            targetSet = setOf("boot"),
            externalDataBytes = 0,
            apkBytes = 0,
            freeBytesOnData = 1L,
        )
        assertFalse(estimate.adequate)
        assertTrue(estimate.requiredBytes > 0)
        // 边界语义（05 §2.7）：required = backupEstimate + 2×分区；free >= required 才允许。
        val reference = SpaceEstimator.estimate(
            mapOf("boot" to 1024L, "init_boot" to 1024L), emptySet(), setOf("boot"), 0, 0, Long.MAX_VALUE,
        )
        assertTrue(reference.adequate)
        val atBoundary = SpaceEstimator.estimate(
            mapOf("boot" to 1024L, "init_boot" to 1024L), emptySet(), setOf("boot"), 0, 0,
            reference.requiredBytes,
        )
        assertTrue(atBoundary.adequate)
        val belowBoundary = SpaceEstimator.estimate(
            mapOf("boot" to 1024L, "init_boot" to 1024L), emptySet(), setOf("boot"), 0, 0,
            reference.requiredBytes - 1,
        )
        assertFalse(belowBoundary.adequate)
    }

    private companion object {
        const val FIXED_NOW = 1_793_260_800_000L
        const val DAY = 24L * 60L * 60L * 1000L
    }
}
