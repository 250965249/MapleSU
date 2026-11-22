package dev.maplesu.manager.modules

import dev.maplesu.manager.ModuleArchiveInspector
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry
import org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.tukaani.xz.LZMA2Options
import org.tukaani.xz.XZOutputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class ZygiskModuleStorageTest {
    @get:Rule val temporary = TemporaryFolder()

    private fun report(library: String): ModuleArchiveInspector.Report {
        val archive = temporary.newFile()
        ZipOutputStream(archive.outputStream()).use { output ->
            output.putNextEntry(ZipEntry("module.prop"))
            output.write("id=zygisk_fixture\nname=Fixture\nversionCode=1\n".toByteArray())
            output.closeEntry()
            output.putNextEntry(ZipEntry(library))
            output.write(byteArrayOf(0x7f, 69, 76, 70, 2, 1, 1) + ByteArray(13))
            output.closeEntry()
        }
        return ModuleArchiveInspector.inspect(archive)
    }

    @Test fun directZygiskArchiveUsesEarlyStorageBeforeExtraction() {
        assertTrue(LiteScriptModuleBackend.hasZygiskPayload(report("zygisk/arm64-v8a.so"), emptyList()))
    }

    @Test fun selfExtractingFrameworkIsRecognizedFromItsInstalledTree() {
        val report = report("lib/arm64-v8a/libzygisk.so")
        val old = temporary.newFolder()
        val early = temporary.newFolder()
        assertFalse(LiteScriptModuleBackend.hasZygiskPayload(report, listOf(old, early)))
        File(old, "zygisk").mkdir()
        File(old, "zygisk/arm64-v8a.so").writeText("installed by customize.sh")
        assertTrue(LiteScriptModuleBackend.hasZygiskPayload(report, listOf(old, early)))
        old.copyRecursively(early, overwrite = true)
        old.deleteRecursively()
        assertTrue(LiteScriptModuleBackend.hasZygiskPayload(report, listOf(old, early)))
    }

    @Test fun ordinaryNativeModuleAndEmptyZygiskFolderKeepTheirStorage() {
        val report = report("lib/arm64-v8a/libfixture.so")
        val tree = temporary.newFolder()
        File(tree, "zygisk").mkdir()
        File(tree, "zygisk/README.md").writeText("fixture")
        assertFalse(LiteScriptModuleBackend.hasZygiskPayload(report, listOf(tree)))
    }

    @Test fun selfExtractingInstallerReceivesOnlyItsBootstrapFiles() {
        val archive = extractionArchive("SKIPUNZIP=1\ntrue\n")
        val tree = temporary.newFolder()
        assertEquals(setOf("customize.sh"), LiteScriptModuleBackend.extract(archive, tree).keys)
        assertEquals(setOf("module.prop", "customize.sh"), tree.listFiles()!!.map { it.name }.toSet())
    }

    @Test fun ordinaryAndLegacyInstallersKeepPayloadButExcludeRecoveryMetadata() {
        for (legacy in listOf(false, true)) {
            val archive = extractionArchive(if (legacy) "SKIPUNZIP=1\n" else "true\n", legacy)
            val tree = temporary.newFolder()
            LiteScriptModuleBackend.extract(archive, tree)
            assertTrue(File(tree, "lib/payload.so").isFile)
            assertFalse(File(tree, "META-INF").exists())
        }
    }

    @Test fun unusedScriptPayloadIsNotRequiredToParseAsTheInstallerShell() {
        val archive = temporary.newFile()
        ZipOutputStream(archive.outputStream()).use { output ->
            mapOf("module.prop" to "id=fixture\n", "customize.sh" to "true\n", "unused.sh" to "if then\n").forEach { (name, text) ->
                output.putNextEntry(ZipEntry(name)); output.write(text.toByteArray()); output.closeEntry()
            }
        }
        val tree = temporary.newFolder()
        LiteScriptModuleBackend.extract(archive, tree)
        assertEquals("if then\n", File(tree, "unused.sh").readText())
        assertEquals("true\n", File(tree, "customize.sh").readText())
    }

    @Test fun xzCompressedSelfExtractingUpdateReceivesOnlyBootstrapFiles() {
        val archive = extractionArchive("SKIPUNZIP=1\ntrue\n", xz = true)
        val tree = temporary.newFolder()
        ModuleArchiveInspector.inspect(archive)
        assertEquals(setOf("customize.sh"), LiteScriptModuleBackend.extract(archive, tree).keys)
        assertEquals(setOf("module.prop", "customize.sh"), tree.listFiles()!!.map { it.name }.toSet())
        assertEquals("SKIPUNZIP=1\ntrue\n", File(tree, "customize.sh").readText())
    }

    @Test fun xzCompressedOrdinaryAndLegacyUpdatesKeepTheirPayload() {
        for (legacy in listOf(false, true)) {
            val archive = extractionArchive(if (legacy) "SKIPUNZIP=1\n" else "true\n", legacy, xz = true)
            val tree = temporary.newFolder()
            LiteScriptModuleBackend.extract(archive, tree)
            assertEquals("payload", File(tree, "lib/payload.so").readText())
            assertFalse(File(tree, "META-INF").exists())
        }
    }

    private fun extractionArchive(customize: String, legacy: Boolean = false, xz: Boolean = false): File {
        val archive = temporary.newFile()
        val files = linkedMapOf("module.prop" to "id=fixture\n", "customize.sh" to customize,
            "lib/payload.so" to "payload", "META-INF/com/google/android/update-binary" to "recovery")
        if (legacy) files["install.sh"] = "true\n"
        if (xz) {
            ZipArchiveOutputStream(archive).use { output ->
                files.forEach { (name, data) ->
                    val bytes = data.toByteArray()
                    val compressed = ByteArrayOutputStream().also { buffer ->
                        XZOutputStream(buffer, LZMA2Options()).use { it.write(bytes) }
                    }.toByteArray()
                    val entry = ZipArchiveEntry(name).apply {
                        method = 95
                        size = bytes.size.toLong()
                        compressedSize = compressed.size.toLong()
                        crc = CRC32().apply { update(bytes) }.value
                    }
                    output.addRawArchiveEntry(entry, compressed.inputStream())
                }
            }
            return archive
        }
        ZipOutputStream(archive.outputStream()).use { output ->
            files.forEach { (name, data) ->
                output.putNextEntry(ZipEntry(name))
                output.write(data.toByteArray())
                output.closeEntry()
            }
        }
        return archive
    }
}
