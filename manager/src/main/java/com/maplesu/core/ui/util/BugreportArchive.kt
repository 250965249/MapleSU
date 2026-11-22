package com.maplesu.core.ui.util

import org.apache.commons.compress.archivers.tar.TarArchiveEntry
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream
import java.io.File
import java.io.IOException
import java.io.OutputStream
import java.util.zip.GZIPOutputStream
import java.nio.file.Files

/** Packing and publishing use the app UID, including when no privileged channel is available. */
internal object BugreportArchive {
    private val textExtensions = setOf("txt", "log", "json", "jsonl", "xml", "prop", "csv", "tsv", "md", "yaml", "yml")
    private val keyField = Regex("""(?i)(?<![A-Za-z0-9_])(["']?(?:root[-_ ]?key|ultra[-_ ]?key|key)["']?\s*[:=]\s*)(["']?)([A-Za-z0-9_-]{48})(?![A-Za-z0-9_-])""")
    private val tokenField = Regex("""(?i)(?<![A-Za-z0-9_])(["']?(?:su[-_]?token|token)["']?\s*[:=]\s*)(["']?)((?:0x)?[0-9a-f]{16,128})(?![A-Za-z0-9_-])""")
    private val keyLike = Regex("(?<![A-Za-z0-9])[A-Za-z0-9]{48}(?![A-Za-z0-9])")
    private val privateSdkDirectory = Regex("""/data/[A-Za-z0-9]{16,17}(?=/|\s|["']|$)""")

    fun <T> withStagingDirectory(cache: File, collect: (File) -> T): T {
        val directory = Files.createTempDirectory(cache.toPath(), "bugreport-").toFile()
        try { return collect(directory) } finally { directory.deleteRecursively() }
    }

    /** Root writes into existing app-owned inodes, so the app can read every collected file. */
    fun prepareCollectionFiles(files: Collection<File>) {
        files.forEach { file -> check(file.createNewFile()) { "BUGREPORT_STAGING_FILE_EXISTS" } }
    }

    fun redact(text: String, knownSecrets: Collection<String> = emptyList()): String = redactor(knownSecrets)(text)

    private fun redactor(knownSecrets: Collection<String>): (String) -> String {
        val known = knownSecrets.filter { it.length >= 16 }.distinct().map {
            Regex("(?<![A-Za-z0-9_-])${Regex.escape(it)}(?![A-Za-z0-9_-])")
        }
        return { text ->
            var safe = text
            for ((pattern, marker) in listOf(keyField to "<REDACTED-KEY>", tokenField to "<REDACTED-TOKEN>")) {
                safe = pattern.replace(safe) { match ->
                    val quote = match.groupValues[2]
                    match.groupValues[1] + if (quote.isEmpty()) "\"$marker\"" else quote + marker
                }
            }
            known.forEach { safe = safe.replace(it, "<REDACTED>") }
            safe = keyLike.replace(safe, "<REDACTED-KEY>")
            privateSdkDirectory.replace(safe, "/data/<private>")
        }
    }

    fun pack(directory: File, destination: File, knownSecrets: Collection<String> = emptyList()): File {
        require(directory.isDirectory) { "BUGREPORT_DIRECTORY_MISSING" }
        val files = directory.walkTopDown().filter { it.isFile }.sortedBy { it.path }.toList()
        val secrets = knownSecrets.toMutableSet()
        // Discover labelled values before packing, including values repeated in process argv.
        files.filter { it.extension.lowercase() in textExtensions }.forEach { file ->
            file.useLines { lines -> lines.forEach { line ->
                listOf(keyField, tokenField).forEach { pattern ->
                    pattern.findAll(line).forEach { secrets += it.groupValues[3] }
                }
            } }
        }
        val redact = redactor(secrets)
        val temporary = File.createTempFile(".bugreport-", ".tmp", destination.parentFile)
        try {
            GZIPOutputStream(temporary.outputStream().buffered()).use { gzip ->
                TarArchiveOutputStream(gzip, "UTF-8").use { tar ->
                    tar.setLongFileMode(TarArchiveOutputStream.LONGFILE_POSIX)
                    files.forEach { file ->
                        val copy = if (file.extension.lowercase() in textExtensions) {
                            File.createTempFile(".redacted-", ".tmp", destination.parentFile)
                        } else null
                        try {
                            if (copy != null) writeRedacted(file, copy, redact)
                            val source = copy ?: file
                            val entry = TarArchiveEntry(source, file.relativeTo(directory).invariantSeparatorsPath)
                            tar.putArchiveEntry(entry)
                            source.inputStream().use { it.copyTo(tar) }
                            tar.closeArchiveEntry()
                        } finally { copy?.delete() }
                    }
                    tar.finish()
                }
            }
            if (temporary.length() == 0L || !temporary.renameTo(destination)) {
                throw IOException("BUGREPORT_PUBLISH_FAILED")
            }
            return destination
        } finally {
            temporary.delete()
        }
    }

    private fun writeRedacted(source: File, destination: File, redact: (String) -> String) {
        source.bufferedReader().use { input -> destination.bufferedWriter().use { output ->
            val buffer = CharArray(8192)
            val line = StringBuilder()
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                for (index in 0 until count) {
                    line.append(buffer[index])
                    if (buffer[index] == '\n') {
                        output.write(redact(line.toString()))
                        line.setLength(0)
                    }
                }
            }
            if (line.isNotEmpty()) output.write(redact(line.toString()))
        } }
    }

    fun copy(archive: File, openOutput: () -> OutputStream?): Long {
        if (!archive.isFile || archive.length() == 0L) throw IOException("BUGREPORT_ARCHIVE_MISSING")
        val size = archive.length()
        val output = openOutput() ?: throw IOException("BUGREPORT_DESTINATION_UNAVAILABLE")
        val copied = output.use { target -> archive.inputStream().use { it.copyTo(target) } }
        if (copied != size) throw IOException("BUGREPORT_COPY_INCOMPLETE")
        return copied
    }
}
