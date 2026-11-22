package dev.maplesu.manager.workmode.service

import dev.maplesu.manager.workmode.switch.ModeSwitchCodes
import dev.maplesu.manager.workmode.switch.ModeSwitchHashes
import java.io.File
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class ModeSwitchCandidateImageTest {
    @get:Rule val temporary = TemporaryFolder()

    @Test fun compactProducerOutputIsZeroFilledWithoutChangingItsSource() {
        val source = temporary.newFile("compact.img").apply { writeBytes(byteArrayOf(1, 2, 3)) }
        val output = fullSizeSwitchCandidate(source, File(temporary.root, "candidate.img"), 4096)
        assertArrayEquals(byteArrayOf(1, 2, 3), source.readBytes())
        assertArrayEquals(byteArrayOf(1, 2, 3).copyOf(4096), output.readBytes())
        assertEquals(4096L, output.length())
        assertNotEquals(ModeSwitchHashes.sha256(source), ModeSwitchHashes.sha256(output))
    }

    @Test fun alreadyFullOutputKeepsItsExactBytesAndDigest() {
        val source = temporary.newFile("full.img").apply { writeBytes(ByteArray(4096) { it.toByte() }) }
        val output = fullSizeSwitchCandidate(source, File(temporary.root, "candidate.img"), 4096)
        assertEquals(ModeSwitchHashes.sha256(source), ModeSwitchHashes.sha256(output))
    }

    @Test fun oversizedAndEmptyOutputsAreNotTruncatedOrPublished() {
        for (bytes in listOf(ByteArray(0), ByteArray(4097))) {
            val source = temporary.newFile().apply { writeBytes(bytes) }
            val output = File(temporary.root, "candidate.img")
            val failure = assertThrows(IllegalStateException::class.java) {
                fullSizeSwitchCandidate(source, output, 4096)
            }
            assertEquals(ModeSwitchCodes.PRODUCE_OUTPUT_SIZE_INVALID, failure.message)
            assertFalse(output.exists())
        }
    }
}
