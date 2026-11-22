package com.maplesu.core.ui.util

import dev.maplesu.manager.installer.InstallCandidateImage
import dev.maplesu.manager.ultrakernel.UltraKernelSpec
import java.io.File
import java.nio.file.Files
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class UltraKernelBootExportTest {
    @get:Rule val temporary = TemporaryFolder()

    private fun candidate(name: String = "boot.img", partition: String = "boot"): InstallCandidateImage {
        val image = temporary.newFile(name).apply { writeBytes(ByteArray(64) { it.toByte() }) }
        return InstallCandidateImage(image, UltraKernelSpec.sha256(image), image.length(), partition)
    }

    @Test fun absentOrDeletedCandidateIsNotOffered() {
        assertFalse(UltraKernelBootExport.hasVerifiedCandidate(null))
        val candidate = candidate()
        assertTrue(candidate.image.delete())
        assertFalse(UltraKernelBootExport.hasVerifiedCandidate(candidate))
    }

    @Test fun normalAndUltraCandidatesAreBothVerified() {
        for (partition in listOf("boot", "init_boot")) {
            assertTrue(UltraKernelBootExport.hasVerifiedCandidate(candidate("$partition.img", partition)))
        }
    }

    @Test fun changedBytesAreRejectedEvenWhenSizeMatches() {
        val candidate = candidate()
        candidate.image.writeBytes(ByteArray(candidate.size.toInt()) { 0x33 })
        assertFalse(UltraKernelBootExport.hasVerifiedCandidate(candidate))
    }

    @Test fun incorrectOrEmptySizeIsRejected() {
        val candidate = candidate()
        assertFalse(UltraKernelBootExport.hasVerifiedCandidate(candidate.copy(size = candidate.size + 1)))
        assertFalse(UltraKernelBootExport.hasVerifiedCandidate(candidate.copy(size = 0)))
        candidate.image.appendBytes(byteArrayOf(1))
        assertFalse(UltraKernelBootExport.hasVerifiedCandidate(candidate))
    }

    @Test fun anUnrelatedValidImageDoesNotReplaceTheSelectedCandidate() {
        assertTrue(UltraKernelBootExport.hasVerifiedCandidate(candidate("older-ultra.img")))
        val current = candidate("current-normal.img", "init_boot")
        current.image.writeText("corrupted")
        assertFalse(UltraKernelBootExport.hasVerifiedCandidate(current))
    }

    @Test fun symbolicLinksAreNotTreatedAsTheSubmittedImage() {
        val candidate = candidate()
        val link = File(temporary.root, "linked.img").toPath()
        val created = runCatching { Files.createSymbolicLink(link, candidate.image.toPath()) }.isSuccess
        assumeTrue("Host must permit symbolic links", created)
        assertFalse(UltraKernelBootExport.hasVerifiedCandidate(candidate.copy(image = link.toFile())))
    }
}
