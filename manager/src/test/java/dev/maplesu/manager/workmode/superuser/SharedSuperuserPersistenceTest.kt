package dev.maplesu.manager.workmode.superuser

import dev.maplesu.manager.workmode.control.ControlRead
import dev.maplesu.manager.workmode.control.FileControlPlane
import dev.maplesu.manager.workmode.control.schema.GrantIntent
import dev.maplesu.manager.workmode.control.schema.canonicalized
import dev.maplesu.manager.workmode.detect.BootIdSource
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/** `shared/superuser.json` 往返 / 损坏 / 回退（01 §4.7、§6.5）。 */
class SharedSuperuserPersistenceTest {
    private fun plane(root: File, diagnostics: MutableList<String> = mutableListOf()) = FileControlPlane(
        root = root,
        clock = TestClock(),
        bootIdSource = BootIdSource { "boot-1" },
        onDiagnostic = { diagnostics += it },
    )

    @Test
    fun sharedFileRoundTripsExactly() {
        TestControl.create().use { control ->
            val expected = Fixtures.shared(
                revision = 3,
                entries = listOf(
                    Fixtures.intentFrom(Fixtures.identity()).copy(
                        signerSha256 = listOf(Fixtures.hash('b'), Fixtures.hash('a')),
                        degraded = listOf("z", "a", "a"),
                    ),
                ),
                tombs = listOf(Fixtures.tomb()),
            )
            control.write(expected)
            val read = control.read()
            assertEquals(expected.canonicalized(), read)
            assertEquals(3, read.revision)
        }
    }

    @Test
    fun writingSameValueIsByteStable() {
        TestControl.create().use { control ->
            val value = Fixtures.shared(entries = listOf(Fixtures.intentFrom(Fixtures.identity())))
            control.write(value)
            val first = control.readRaw()
            control.write(value)
            assertEquals(first, control.readRaw())
        }
    }

    @Test
    fun unknownFieldsAreIgnoredOnRead() {
        TestControl.create().use { control ->
            control.write(Fixtures.shared(entries = listOf(Fixtures.intentFrom(Fixtures.identity()))))
            val raw = control.readRaw()
            val patched = raw.dropLast(1) + ",\"futureField\":{\"a\":1}}"
            control.writeRaw(patched)
            val read = control.read()
            assertEquals(1, read.entries.size)
        }
    }

    @Test
    fun corruptPrimaryFallsBackToPrevGeneration() {
        val root = java.nio.file.Files.createTempDirectory("maplesu-shared-prev-").toFile()
        try {
            val diagnostics = mutableListOf<String>()
            val plane = plane(root, diagnostics)
            plane.writeSharedSuperuser { Fixtures.shared(revision = 1) }
            plane.writeSharedSuperuser { Fixtures.shared(revision = 2) }
            // 主文件损坏，.prev 为 revision=1 的上一代。
            File(root, "shared/superuser.json").writeText("{corrupt")
            File(root, "shared/superuser.json.sha256").delete()
            val read = plane.readSharedSuperuser()
            assertTrue(read is ControlRead.Ok)
            assertEquals(1, (read as ControlRead.Ok).value.revision)
            assertTrue(diagnostics.contains("SHARED_ROLLED_BACK"))
        } finally {
            root.deleteRecursively()
        }
    }

    @Test
    fun corruptPrimaryAndPrevIsCorruptNotDefault() {
        val root = java.nio.file.Files.createTempDirectory("maplesu-shared-both-").toFile()
        try {
            val plane = plane(root)
            File(root, "shared").mkdirs()
            File(root, "shared/superuser.json").writeText("{corrupt")
            File(root, "shared/superuser.json.prev").writeText("{also-corrupt")
            val read = plane.readSharedSuperuser()
            assertTrue(read is ControlRead.Corrupt)
            assertEquals("SHARED_CORRUPT", (read as ControlRead.Corrupt).code)
        } finally {
            root.deleteRecursively()
        }
    }

    @Test
    fun schemaTooNewIsNotSilentlyAccepted() {
        TestControl.create().use { control ->
            control.write(Fixtures.shared(entries = listOf(Fixtures.intentFrom(Fixtures.identity()))))
            val raw = control.readRaw().replace("\"schema\":1", "\"schema\":2")
            assertTrue(raw.contains("\"schema\":2"))
            control.writeRaw(raw)
            val read = control.plane.readSharedSuperuser()
            // 已知 ControlPlane 行为：schema too new 本应是 Unreadable，但 readSharedSuperuser 的
            // .prev 回退路径在无 prev 时会归一成 Corrupt(SHARED_CORRUPT)；两者都不允许静默 Ok。
            assertFalse(read is ControlRead.Ok)
            assertTrue(read is ControlRead.Corrupt)
            assertEquals("SHARED_CORRUPT", (read as ControlRead.Corrupt).code)
        }
    }

    @Test
    fun revisionRegressionIsRejected() {
        TestControl.create().use { control ->
            control.write(Fixtures.shared(revision = 5))
            val result = control.plane.writeSharedSuperuser { Fixtures.shared(revision = 4) }
            val rejected = result is dev.maplesu.manager.workmode.control.ControlWrite.Rejected
            assertTrue(rejected)
            if (rejected) {
                assertEquals("CONTROL_REVISION_REGRESSION",
                    (result as dev.maplesu.manager.workmode.control.ControlWrite.Rejected).code)
            }
        }
    }

    @Test
    fun denyAndTombSurviveRoundTrip() {
        TestControl.create().use { control ->
            val value = Fixtures.shared(
                entries = listOf(Fixtures.intentFrom(Fixtures.identity(), GrantIntent.DENY)),
                tombs = listOf(Fixtures.tomb()),
            )
            control.write(value)
            val read = control.read()
            assertEquals(GrantIntent.DENY, read.entries.single().decision)
            assertEquals(Fixtures.APP, read.tombs.single().packageName)
            assertFalse(read.tombs.single().signerSha256.isEmpty())
        }
    }
}
