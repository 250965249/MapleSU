package dev.maplesu.manager.jailbreak

import org.junit.Assert.*
import org.junit.Test
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Files

class JailbreakSelinuxBaselineTest {
    private val observed = ByteBuffer.allocate(20).order(ByteOrder.LITTLE_ENDIAN)
        .apply { listOf(1, 2, 1, 0, 1).forEach { putInt(it) } }.array()
    private val window = """{"schema":"maplesu.selinux.window.v1","provider":"ghostlock",
        "bootId":"boot-1","attempt":"attempt-1","before":[1,2,1,0,1],
        "after":[1,4,1,2,1],"restoreFrom":0,"restoreTo":1}"""

    private fun withFiles(test: (File, File) -> Unit) {
        val directory = Files.createTempDirectory("selinux-baseline-").toFile()
        try { test(File(directory, "baseline"), File(directory, "window.json")) }
        finally { directory.deleteRecursively() }
    }

    @Test fun missingAppSnapshotSelectsExplicitDefaultOnTheFirstAttempt() = withFiles { raw, _ ->
        val selected = JailbreakSelinuxBaseline.select(raw, "boot-1", "attempt-1", emptyList()) { true }
        assertNull(selected.file)
        assertEquals("normalized-default", selected.source)
        assertFalse(raw.exists())
    }

    @Test fun rootWindowSurvivesAppEaccesAndIsPersistedBeforeUse() = withFiles { raw, root ->
        root.writeText(window)
        val selected = JailbreakSelinuxBaseline.select(raw, "boot-1", "attempt-1", listOf(root)) { true }
        assertEquals("root-window", selected.source)
        assertEquals(48L, selected.file!!.length())
        assertEquals("boot-1", File(selected.file.path + ".boot").readText().trim())
        val bytes = ByteBuffer.wrap(selected.file.readBytes()).order(ByteOrder.LITTLE_ENDIAN)
        assertEquals(listOf(1, 2, 1, 0, 1, 1, 4, 1, 2, 1, 0, 1), List(12) { bytes.int })
        assertFalse(raw.exists())
    }

    @Test fun rawCaptureIsKeptWhenTheOptionalWindowIsDamaged() = withFiles { raw, root ->
        raw.writeBytes(observed)
        File(raw.path + ".boot").writeText("boot-1\n")
        root.writeText(window.replace("boot-1", "old-boot"))
        val selected = JailbreakSelinuxBaseline.select(raw, "boot-1", "attempt-1", listOf(root)) { true }
        assertEquals("pre-entry", selected.source)
        assertArrayEquals(observed, raw.readBytes())
    }

    @Test fun staleMalformedAndUntrustedWindowsUseTheDefault() = withFiles { raw, root ->
        for (text in listOf(window.replace("boot-1", "old-boot"),
            window.replace("attempt-1", "old-attempt"), window.replace("1,2,1,0,1", "1,3,1,0,1"),
            window.replace("1,4,1,2,1", "1,0,1,2,1"), window.replace("restoreTo\":1", "restoreTo\":0"),
            window.replace("1,2,1,0,1", "1,2,1,-1,1"), "{")) {
            root.writeText(text)
            assertEquals("normalized-default", JailbreakSelinuxBaseline.select(raw, "boot-1",
                "attempt-1", listOf(root)) { true }.source)
        }
        root.writeText(window)
        assertEquals("normalized-default", JailbreakSelinuxBaseline.select(raw, "boot-1",
            "attempt-1", listOf(root)) { false }.source)
    }

    @Test fun staleOrPartialRawSnapshotDoesNotBlockRootInitialization() = withFiles { raw, _ ->
        raw.writeBytes(observed)
        File(raw.path + ".boot").writeText("old-boot")
        assertNull(JailbreakSelinuxBaseline.select(raw, "boot-1", "attempt-1", emptyList()) { true }.file)
        File(raw.path + ".boot").writeText("boot-1")
        raw.writeBytes(observed.copyOf(8))
        assertNull(JailbreakSelinuxBaseline.select(raw, "boot-1", "attempt-1", emptyList()) { true }.file)
    }

    @Test fun atomicSavePublishesTheWholeSnapshot() = withFiles { raw, _ ->
        JailbreakSelinuxBaseline.atomicWrite(raw, observed)
        assertArrayEquals(observed, raw.readBytes())
        assertFalse(File(raw.path + ".tmp").exists())
    }

    @Test fun savedWindowRemainsUsableAfterSourceLogCleanup() = withFiles { raw, root ->
        root.writeText(window)
        val captured = JailbreakSelinuxBaseline.select(raw, "boot-1", "attempt-1", listOf(root)) { true }
        root.delete()
        assertEquals(captured.file, JailbreakSelinuxBaseline.select(raw, "boot-1", "attempt-1",
            emptyList()) { false }.file)
        assertNull(JailbreakSelinuxBaseline.select(raw, "next-boot", "attempt-1", emptyList()) { true }.file)
    }
}
