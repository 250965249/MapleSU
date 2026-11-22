package dev.maplesu.manager.workmode.service

import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.switch.ModeSwitchHashes
import dev.maplesu.manager.workmode.switch.ModeSwitchRequest
import java.io.File
import java.util.UUID
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/** Ordinary BASE files only; never opens an Android partition provider. */
class LocalInstallerGatewayExportTest {
    @get:Rule val temporary = TemporaryFolder()

    @Test fun baseExportCopiesCompleteBytesAndKeepsItsSource() {
        val root = temporary.newFolder()
        val source = File(root, "baseline-fixture/boot.img").apply {
            parentFile!!.mkdirs()
            writeBytes(ByteArray(4096) { it.toByte() })
        }
        val bytes = source.readBytes()
        val destination = File(root, "work/base.img")
        val gateway = LocalInstallerGateway(root) { throw AssertionError("export must not open a journal") }
        val request = ModeSwitchRequest(UUID.randomUUID().toString(), WorkMode.LITE, WorkMode.KSU,
            "baseline-fixture", targetPartition = "boot")
        val exported = gateway.exportImage(request, "BASE", "boot", destination)
        assertArrayEquals(bytes, source.readBytes())
        assertArrayEquals(bytes, destination.readBytes())
        assertEquals(destination, exported.file)
        assertEquals(bytes.size.toLong(), exported.size)
        assertEquals(ModeSwitchHashes.sha256(source), exported.sha256)
    }

    @Test fun baseExportToItsOwnSourceDoesNotTruncateIt() {
        val root = temporary.newFolder()
        val source = File(root, "baseline-fixture/boot.img").apply {
            parentFile!!.mkdirs()
            writeBytes(byteArrayOf(1, 2, 3, 4))
        }
        val bytes = source.readBytes()
        val gateway = LocalInstallerGateway(root) { throw AssertionError("export must not open a journal") }
        val request = ModeSwitchRequest(UUID.randomUUID().toString(), WorkMode.LITE, WorkMode.KSU,
            "baseline-fixture", targetPartition = "boot")
        val exported = gateway.exportImage(request, "BASE", "boot", source)
        assertArrayEquals(bytes, source.readBytes())
        assertEquals(bytes.size.toLong(), exported.size)
        assertEquals(ModeSwitchHashes.sha256(source), exported.sha256)
    }
}
