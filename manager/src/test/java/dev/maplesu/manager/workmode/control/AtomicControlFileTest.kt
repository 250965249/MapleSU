package dev.maplesu.manager.workmode.control

import dev.maplesu.manager.workmode.TestFixtures
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.File
import java.io.IOException

/** 原子写（01 §4.2）：tmp+fsync+rename、sha 校验、append-only。 */
class AtomicControlFileTest {
    private fun dir(): File = TestFixtures.tempDir("atomic").toFile()

    @Test
    fun writeJsonCreatesShaAndVerifies() {
        val directory = dir()
        val target = File(directory, "modes.json")
        AtomicControlFile.writeJson(target, "{\"a\":1}")
        assertTrue(target.isFile)
        assertEquals("{\"a\":1}", target.readText())
        assertEquals(ShaCheck.OK, AtomicControlFile.verifySha(target))
        assertTrue(AtomicControlFile.shaFile(target).isFile)
    }

    @Test
    fun verifyShaMissingAndMismatch() {
        val directory = dir()
        val target = File(directory, "file.json")
        AtomicControlFile.writeUtf8(target, "{}".toByteArray())
        assertEquals(ShaCheck.MISSING, AtomicControlFile.verifySha(target))

        AtomicControlFile.writeJson(target, "{\"a\":1}")
        assertEquals(ShaCheck.OK, AtomicControlFile.verifySha(target))
        target.writeText("{\"a\":2}")
        assertEquals(ShaCheck.MISMATCH, AtomicControlFile.verifySha(target))
    }

    @Test
    fun atomicReplaceLeavesNoTemporaryFiles() {
        val directory = dir()
        val target = File(directory, "switch.json")
        AtomicControlFile.writeJson(target, "{\"v\":1}")
        AtomicControlFile.writeJson(target, "{\"v\":2}")
        assertEquals("{\"v\":2}", target.readText())
        val leftovers = directory.listFiles()!!.filter { it.name.contains(".tmp-") }
        assertTrue("temporary files left: $leftovers", leftovers.isEmpty())
        assertEquals(ShaCheck.OK, AtomicControlFile.verifySha(target))
    }

    @Test
    fun appendLineAppendsNewlineAndKeepsContent() {
        val directory = dir()
        val target = File(directory, "journal.jsonl")
        AtomicControlFile.appendLine(target, "line-1")
        AtomicControlFile.appendLine(target, "line-2")
        assertEquals(listOf("line-1", "line-2"), target.readLines())
        assertTrue(target.readText().endsWith("\n"))
    }

    @Test
    fun readUtf8HonoursMaxBytes() {
        val directory = dir()
        val target = File(directory, "big.txt")
        target.writeText("x".repeat(64))
        assertEquals(null, AtomicControlFile.readUtf8(target, maxBytes = 8))
        assertEquals(64, AtomicControlFile.readUtf8(target, maxBytes = 1024)?.length)
        assertNull(AtomicControlFile.readUtf8(File(directory, "missing.txt")))
    }

    @Test
    fun writeFailsWhenParentDirectoryMissing() {
        val target = File(File(TestFixtures.tempDir("atomic-missing").toFile(), "nope"), "file.json")
        try {
            AtomicControlFile.writeUtf8(target, "{}".toByteArray())
            fail("expected IOException for missing parent dir")
        } catch (_: IOException) {
        }
        assertFalse(target.exists())
    }
}
