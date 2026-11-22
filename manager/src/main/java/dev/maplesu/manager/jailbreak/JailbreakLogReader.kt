package dev.maplesu.manager.jailbreak

import com.maplesu.core.ui.util.BugreportArchive
import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import org.json.JSONObject

/** App-UID file reads only. Displaying progress never opens a privileged channel. */
internal class JailbreakLogReader(
    private val protectedDirectory: File,
    private val filesDirectory: File,
    private val method: String,
    private val backend: String,
    private val preferredAttempt: String? = null,
    private val notBefore: Long = 0,
    private val limit: Int = 2000,
) {
    enum class Tone { DETAIL, STEP, SUCCESS, ERROR }
    data class Line(val source: String, val text: String, val tone: Tone)
    data class Snapshot(val attemptId: String? = null, val lines: List<Line> = emptyList(),
                        val omitted: Int = 0, val stage: String? = null) {
        fun text(): String = lines.joinToString("\n") { "[${it.source}] ${it.text}" }
    }
    private class Cursor(var offset: Long = 0, var prefix: ByteArray = byteArrayOf(), var pending: String = "",
                         var initial: Boolean = true, var skipFragment: Boolean = false)

    private val cursors = linkedMapOf<String, Cursor>()
    private val documents = mutableMapOf<String, String>()
    private val lines = ArrayDeque<Line>()
    private var omitted = 0
    private var attempt: String? = null
    private val errorPattern = Regex("(?i)\\b(failed|fatal|error|timeout|unavailable|missing)\\b")
    private val ansi = Regex("\u001B\\[[0-9;]*[A-Za-z]")
    private val clock = SimpleDateFormat("HH:mm:ss.SSS", Locale.ROOT)

    fun poll(): Snapshot {
        val id = attempt ?: findAttempt()?.also { attempt = it } ?: return Snapshot()
        val directory = File(filesDirectory, "jailbreak/attempts/$id")
        val sources = linkedMapOf<String, File>()
        directory.walkTopDown().filter { file ->
            file.isFile && file.extension in setOf("log", "json", "jsonl") &&
                file.canonicalPath.startsWith(directory.canonicalPath + File.separator)
        }.forEach { sources[it.relativeTo(directory).invariantSeparatorsPath] = it }
        // Fixed helper paths belong to the live attempt only. Old runs use their saved copies.
        val live = document(File(filesDirectory, "jailbreak/status.json"))
        if (live != null && live.optString("attemptId") == id &&
            live.optString("stage") !in listOf(JailbreakStatus.STAGE_IDLE, JailbreakStatus.STAGE_TARGET_CHECKED)) {
            JailbreakDiagnostics.liveFiles.forEach { (path, name) ->
                File(protectedDirectory, path).takeIf {
                    it.isFile && it.lastModified() >= live.optLong("startedAtMillis")
                }?.let { sources[name] = it }
            }
        }
        // status-history contains every persisted transition; status.json is its latest copy.
        if ("status-history.jsonl" in sources) sources.remove("status.json")
        // Older/startup paths may have only this file. Drop it only when its duplicate has output.
        if ((sources["$method-native.log"]?.length() ?: 0) > 0) sources.remove("native-stage.log")
        sources.forEach { (name, file) ->
            runCatching {
                if (file.extension == "json") readDocument(name, file) else readAppend(name, file)
            }.onFailure { error ->
                val message = "[!] $name: ${error.javaClass.simpleName}"
                if (documents["error:$name"] != message) {
                    documents["error:$name"] = message
                    append(name, message)
                }
            }
        }
        val partial = cursors.filter { (name, cursor) -> name in sources && cursor.pending.isNotEmpty() }.map { (name, cursor) ->
            line(name, cursor.pending)
        }
        val visible = lines.toList() + partial
        val status = live?.takeIf { it.optString("attemptId") == id }
            ?: document(File(directory, "status.json")) ?: document(File(directory, "caller-outcome.json"))
        return Snapshot(id, visible.takeLast(limit), omitted + (visible.size - limit).coerceAtLeast(0),
            status?.optString("stage"))
    }

    private fun findAttempt(): String? {
        val root = File(filesDirectory, "jailbreak/attempts")
        preferredAttempt?.let {
            return it.takeIf { id -> Regex("[A-Za-z0-9_-]{1,128}").matches(id) && File(root, id).isDirectory }
        }
        return root.listFiles().orEmpty().filter { it.isDirectory }.mapNotNull { directory ->
            val status = document(File(directory, "status.json"))
                ?: document(File(directory, "request.json"))
                ?: document(File(directory, "caller-outcome.json")) ?: return@mapNotNull null
            val started = status.optLong("startedAtMillis").takeIf { it > 0 }
                ?: status.optLong("completedAtMillis")
            if (status.optString("method") != method || status.optString("rootBackend") != backend ||
                started < notBefore) return@mapNotNull null
            directory.name to started
        }.maxByOrNull { it.second }?.first
    }

    private fun document(file: File): JSONObject? = runCatching { JSONObject(file.readText()) }.getOrNull()

    private fun readDocument(name: String, file: File) {
        val text = file.readText()
        // A writer may be replacing a JSON document; retry the next poll if incomplete.
        if (runCatching { JSONObject(text) }.isFailure) return
        if (documents[name] == text) return
        documents[name] = text
        append(name, text)
    }

    private fun readAppend(name: String, file: File) {
        val cursor = cursors.getOrPut(name) { Cursor() }
        RandomAccessFile(file, "r").use { input ->
            val prefix = ByteArray(minOf(64L, input.length()).toInt()).also { input.readFully(it) }
            if (input.length() < cursor.offset ||
                !prefix.take(cursor.prefix.size).toByteArray().contentEquals(cursor.prefix)) {
                cursor.offset = 0
                cursor.pending = ""
                cursor.initial = true
                cursor.skipFragment = false
            }
            cursor.prefix = prefix
            if (cursor.initial) {
                cursor.initial = false
                // Reopening a large retained log starts at its newest output immediately.
                if (input.length() > 128 * 1024) {
                    cursor.offset = input.length() - 128 * 1024
                    cursor.skipFragment = true
                    omitted++
                }
            }
            input.seek(cursor.offset)
            val bytes = ByteArray(minOf(128 * 1024L, input.length() - cursor.offset).toInt())
            input.readFully(bytes)
            // Keep an incomplete UTF-8 character on disk until its remaining bytes arrive.
            val buffer = ByteBuffer.wrap(bytes)
            val chars = CharBuffer.allocate(bytes.size)
            Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPLACE)
                .onUnmappableCharacter(CodingErrorAction.REPLACE).decode(buffer, chars, false)
            cursor.offset += buffer.position()
            chars.flip()
            var combined = cursor.pending + chars.toString()
            if (cursor.skipFragment) {
                val newline = combined.indexOf('\n')
                if (newline < 0) { cursor.pending = ""; return }
                combined = combined.substring(newline + 1)
                cursor.skipFragment = false
            }
            val parts = combined.split('\n')
            parts.dropLast(1).forEach { append(name, it.trimEnd('\r')) }
            cursor.pending = parts.last()
            while (cursor.pending.length > 4096) {
                append(name, cursor.pending.take(4096))
                cursor.pending = cursor.pending.drop(4096)
            }
        }
    }

    private fun append(source: String, text: String) {
        lines.addLast(line(source, text))
        while (lines.size > limit) { lines.removeFirst(); omitted++ }
    }

    private fun line(source: String, text: String): Line {
        val status = if (source in listOf("status-history.jsonl", "status.json", "caller-outcome.json", "progress.jsonl"))
            runCatching { JSONObject(text) }.getOrNull() else null
        val stage = status?.optString("stage")?.takeIf { it.isNotEmpty() }
        val formatted = if (status != null) buildString {
            val time = status.optLong("updatedAtMillis").takeIf { it > 0 }
                ?: status.optLong("completedAtMillis").takeIf { it > 0 }
            if (time != null) append(clock.format(Date(time))).append(' ')
            append('[').append(stage ?: status.optString("step")).append("] ").append(status.optString("message"))
            if (!status.isNull("failure")) append(" · ").append(status.optString("failure"))
        } else ansi.replace(text, "")
        val tone = when {
            stage == JailbreakStatus.STAGE_FAILED || formatted.contains("[!]") ||
                errorPattern.containsMatchIn(formatted) -> Tone.ERROR
            stage == JailbreakStatus.STAGE_DAEMON_READY || formatted.contains("[+]") -> Tone.SUCCESS
            status != null || formatted.contains("[*]") || formatted.contains("[T+") -> Tone.STEP
            else -> Tone.DETAIL
        }
        return Line(source, BugreportArchive.redact(formatted), tone)
    }
}
