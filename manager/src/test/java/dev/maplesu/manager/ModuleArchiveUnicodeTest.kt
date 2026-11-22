package dev.maplesu.manager

import dev.maplesu.manager.modules.LiteScriptModuleBackend
import org.apache.commons.compress.archivers.zip.UnicodePathExtraField
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry
import org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.nio.charset.Charset
import java.util.zip.CRC32
import java.util.zip.ZipEntry

class ModuleArchiveUnicodeTest {
    @get:Rule val tmp = TemporaryFolder()

    private fun archive(vararg names: Pair<String, String>, invalidCrc: Boolean = false,
                        invalidUtf8: Boolean = false, utf8: Boolean = false,
                        customizeText: String = "exit 0\n"): File {
        val file = tmp.newFile()
        val encoding = if (utf8) Charsets.UTF_8 else Charset.forName("GBK")
        ZipArchiveOutputStream(file).use { zip ->
            zip.setEncoding(encoding.name())
            zip.setUseLanguageEncodingFlag(utf8)
            zip.setCreateUnicodeExtraFields(ZipArchiveOutputStream.UnicodeExtraFieldPolicy.NEVER)
            for ((rawName, unicodeName) in listOf("module.prop" to "module.prop") + names) {
                val content = when {
                    rawName == "module.prop" -> "id=unicode_demo\n"
                    unicodeName == "customize.sh" -> customizeText
                    else -> "exit 0\n"
                }
                val bytes = content.toByteArray()
                val entry = ZipArchiveEntry(rawName).apply {
                    method = ZipEntry.STORED
                    size = bytes.size.toLong()
                    crc = CRC32().apply { update(bytes) }.value
                    if (rawName != "module.prop") addExtraField(UnicodePathExtraField(unicodeName,
                        rawName.toByteArray(encoding)).apply {
                        if (invalidCrc) nameCRC32 = nameCRC32 xor 1
                        if (invalidUtf8) this.unicodeName = byteArrayOf(0xc3.toByte(), 0x28)
                    })
                }
                zip.putArchiveEntry(entry)
                zip.write(bytes)
                zip.closeArchiveEntry()
            }
        }
        return file
    }

    private fun reject(file: File, code: String) {
        val failure = assertThrows(ModuleArchiveInspector.Failure::class.java) {
            ModuleArchiveInspector.inspect(file)
        }
        assertEquals(code, failure.code)
    }

    @Test fun legacyChineseNamesUseTheirVerifiedUnicodePathsInBothParsers() {
        val name = "Whitelist520/独断万古.sh"
        val file = archive(name to name)
        val before = file.readBytes()
        assertEquals("unicode_demo", ModuleArchiveInspector.inspect(file).id)
        assertEquals("unicode_demo", ModuleArchiveInspector.inspectKernelSu(file).id)
        assertArrayEquals(before, file.readBytes())
    }

    @Test fun extractionUsesTheSameVerifiedNameWithoutExecutingTheScript() {
        val name = "Whitelist520/独断万古.sh"
        val file = archive(name to name)
        ModuleArchiveInspector.inspect(file)
        val destination = tmp.newFolder()
        val scripts = LiteScriptModuleBackend.extract(file, destination)
        assertEquals("exit 0\n", File(destination, name).readText())
        assertEquals(setOf(name), scripts.keys)
        assertEquals(2, destination.walkTopDown().count { it.isFile })
    }

    @Test fun unicodeCustomizeNameControlsSkipUnzipExactlyAsItsExtractedName() {
        val file = archive("中文脚本.sh" to "customize.sh", "中文数据.txt" to "payload.txt",
            customizeText = "SKIPUNZIP=1\n")
        ModuleArchiveInspector.inspect(file)
        val destination = tmp.newFolder()
        val scripts = LiteScriptModuleBackend.extract(file, destination)
        assertEquals(setOf("customize.sh"), scripts.keys)
        assertEquals("SKIPUNZIP=1\n", File(destination, "customize.sh").readText())
        assertFalse(File(destination, "payload.txt").exists())
        assertFalse(File(destination, "中文脚本.sh").exists())
    }

    @Test fun invalidUnicodeCrcDoesNotEnableLegacyRawNameDecoding() {
        reject(archive("中文.sh" to "中文.sh", invalidCrc = true), "INVALID_ARCHIVE_PATH")
    }

    @Test fun malformedUnicodeUtf8IsRejected() {
        reject(archive("中文.sh" to "中文.sh", invalidUtf8 = true), "INVALID_ARCHIVE_PATH")
    }

    @Test fun unicodePathsKeepTraversalAbsoluteControlAndDriveChecks() {
        for (name in listOf("../outside", "/absolute", "a/../../outside", "a/./entry", "a//entry",
            "C:/entry", "a\\entry", "a\u0000entry", "a\u007fentry")) {
            reject(archive("中文.sh" to name), "INVALID_ARCHIVE_PATH")
        }
    }

    @Test fun differentRawNamesDoNotHideDuplicateUnicodePaths() {
        reject(archive("中文一.sh" to "same.sh", "中文二.sh" to "same.sh"), "DUPLICATE_ARCHIVE_PATH")
    }

    @Test fun unicodePathsDoNotHideLocalAndCentralRawNameDisagreement() {
        val file = archive("中文.sh" to "中文.sh")
        val bytes = file.readBytes()
        bytes[30] = 'x'.code.toByte()
        file.writeBytes(bytes)
        reject(file, "ARCHIVE_HEADER_MISMATCH")
    }

    @Test fun utf8FlagKeepsTheRawUtf8NameAuthoritative() {
        val file = archive("中文.sh" to "../outside", utf8 = true)
        ModuleArchiveInspector.inspect(file)
        val destination = tmp.newFolder()
        val scripts = LiteScriptModuleBackend.extract(file, destination)
        assertEquals(setOf("中文.sh"), scripts.keys)
        assertFalse(File(destination.parentFile, "outside").exists())
    }
}
