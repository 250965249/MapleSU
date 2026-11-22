package dev.maplesu.manager.jailbreak

import java.io.IOException
import java.io.Reader
import java.io.StringReader
import org.junit.Assert.*
import org.junit.Test

class ProviderOutputReaderTest {
    @Test fun persistsPartialOutputBeforeTheNextReadAndParsesOnlyCompleteLines() {
        val persisted = StringBuilder()
        val lines = mutableListOf<String>()
        val chunks = listOf("[*] preparing", " stage\n\u001eGLK_STATUS w1 in_", "progress\n[+] finished")
        var index = 0
        val input = object : Reader() {
            override fun read(buffer: CharArray, offset: Int, count: Int): Int {
                if (index == 1) {
                    assertEquals("[*] preparing", persisted.toString())
                    assertTrue(lines.isEmpty())
                }
                if (index == chunks.size) return -1
                val chunk = chunks[index++]
                chunk.toCharArray().copyInto(buffer, offset)
                return chunk.length
            }
            override fun close() = Unit
        }
        ProviderOutputReader.read(input, { persisted.append(it) }, { lines.add(it) })
        assertEquals(chunks.joinToString(""), persisted.toString())
        assertEquals(listOf("[*] preparing stage", "\u001eGLK_STATUS w1 in_progress", "[+] finished"), lines)
    }

    @Test fun fullOutputSurvivesVeryLongLinesAndUtf8TextWithoutDuplicatedOrDroppedChunks() {
        val text = "详细过程 " + "x".repeat(30_000) + "\n[+] cleanup verified\n"
        val persisted = StringBuilder()
        val lines = mutableListOf<String>()
        ProviderOutputReader.read(StringReader(text), { persisted.append(it) }, { lines.add(it) })
        assertEquals(text, persisted.toString())
        assertEquals(8192, lines.first().length)
        assertEquals("[+] cleanup verified", lines.last())
    }

    @Test fun streamFailureRetainsTheLastUnterminatedOutputForTheLiveReader() {
        val persisted = StringBuilder()
        var emitted = false
        val input = object : Reader() {
            override fun read(buffer: CharArray, offset: Int, count: Int): Int {
                if (emitted) throw IOException("stream closed")
                emitted = true
                "partial detail".toCharArray().copyInto(buffer, offset)
                return "partial detail".length
            }
            override fun close() = Unit
        }
        assertThrows(IOException::class.java) {
            ProviderOutputReader.read(input, { persisted.append(it) }, { fail("No complete line arrived") })
        }
        assertEquals("partial detail", persisted.toString())
    }
}
