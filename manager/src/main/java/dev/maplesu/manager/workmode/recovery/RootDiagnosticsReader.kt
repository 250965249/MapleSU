package dev.maplesu.manager.workmode.recovery

import dev.maplesu.manager.runtime.RootExec
import dev.maplesu.manager.runtime.RootExecResult
import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.util.Base64

/** Reads only diagnostic metadata through the active Root backend, then reuses the redactor. */
class RootDiagnosticsReader(
    private val root: File,
    private val cacheDir: File,
    private val runner: (String) -> RootExecResult = { RootExec.execute(it) },
) {
    fun read(switchId: String): DiagnosticsSnapshot {
        require(switchId.isBlank() || ID.matches(switchId)) { "DIAGNOSTICS_SWITCH_ID_INVALID" }
        val result = runner(command(switchId))
        if (!result.ok) {
            val sourceError = result.output.lineSequence().firstOrNull {
                it.matches(Regex("DIAGNOSTICS_[A-Z_]+"))
            }
            throw IOException(listOfNotNull(
                "DIAGNOSTICS_ROOT_FAILED:${result.backend}:exit=${result.code}",
                result.detail.takeIf(String::isNotBlank), sourceError,
            ).joinToString(":"))
        }
        val files = decode(result.output, switchId)
        check(cacheDir.isDirectory || cacheDir.mkdirs()) { "DIAGNOSTICS_CACHE_UNAVAILABLE" }
        val temporary = Files.createTempDirectory(cacheDir.toPath(), "diagnosis-read-").toFile()
        try {
            files.forEach { (path, bytes) ->
                val file = File(temporary, path)
                check(file.parentFile!!.isDirectory || file.parentFile!!.mkdirs()) {
                    "DIAGNOSTICS_CACHE_UNAVAILABLE"
                }
                file.writeBytes(bytes)
            }
            val snapshot = DiagnosticsExporter(temporary, File(temporary, "unused")).collect(switchId)
            return snapshot.copy(notes = snapshot.notes + "ROOT_BACKEND:${result.backend}" +
                if (result.output.lineSequence().any { it == "ROOT_MISSING" }) listOf("CONTROL_ROOT_MISSING")
                else emptyList())
        } finally {
            // This is only the new private cache child created above, never the Root source tree.
            temporary.deleteRecursively()
        }
    }

    private fun decode(output: String, switchId: String): Map<String, ByteArray> {
        check(output.length <= MAX_TOTAL_BYTES * 2) { "DIAGNOSTICS_REPLY_TOO_LARGE" }
        val lines = output.lineSequence().filter(String::isNotEmpty).toList()
        check(lines.size >= 3 && lines[0] == HEADER && lines[1] == "UID\t0" && lines.last() == "END") {
            "DIAGNOSTICS_REPLY_INVALID"
        }
        val files = linkedMapOf<String, ByteArray>()
        var total = 0
        for (line in lines.drop(2).dropLast(1)) {
            if (line == "ROOT_MISSING") {
                check(lines.size == 4) { "DIAGNOSTICS_REPLY_INVALID" }
                continue
            }
            val fields = line.split('\t', limit = 3)
            check(fields.size == 3 && fields[0] == "FILE") { "DIAGNOSTICS_REPLY_INVALID" }
            val path = fields[1]
            check(path in CONTROL_FILES || BASELINE_FILE.matches(path) ||
                (switchId.isNotBlank() && path == "boot/work/$switchId/journal.jsonl")) {
                "DIAGNOSTICS_PATH_INVALID"
            }
            check(path !in files && files.size < MAX_FILES) { "DIAGNOSTICS_REPLY_INVALID" }
            val bytes = try { Base64.getDecoder().decode(fields[2]) } catch (_: IllegalArgumentException) {
                throw IOException("DIAGNOSTICS_ENCODING_INVALID")
            }
            total += bytes.size
            check(bytes.size <= MAX_FILE_BYTES && total <= MAX_TOTAL_BYTES) { "DIAGNOSTICS_REPLY_TOO_LARGE" }
            files[path] = bytes
        }
        return files
    }

    private fun command(switchId: String): String {
        val journal = if (switchId.isBlank()) "" else "read_one 'boot/work/$switchId/journal.jsonl'"
        return """
            fail() { printf '%s\n' "${'$'}1"; exit 74; }
            uid=${'$'}(id -u) || fail DIAGNOSTICS_IDENTITY_FAILED
            [ "${'$'}uid" = 0 ] || fail DIAGNOSTICS_ROOT_IDENTITY_REQUIRED
            root=${quote(root.absolutePath.replace('\\', '/'))}
            parent=${'$'}{root%/*}
            [ -r "${'$'}parent" ] && [ -x "${'$'}parent" ] || fail DIAGNOSTICS_SOURCE_PARENT_UNREADABLE
            printf '$HEADER\nUID\t0\n'
            [ ! -L "${'$'}root" ] || fail DIAGNOSTICS_SOURCE_SYMLINK
            if [ ! -e "${'$'}root" ]; then printf 'ROOT_MISSING\nEND\n'; exit 0; fi
            check_dir() {
                [ ! -L "${'$'}1" ] || fail DIAGNOSTICS_SOURCE_SYMLINK
                if [ -e "${'$'}1" ]; then
                    [ -d "${'$'}1" ] && [ -r "${'$'}1" ] && [ -x "${'$'}1" ] || fail DIAGNOSTICS_SOURCE_UNREADABLE
                fi
            }
            check_dir "${'$'}root"
            for dir in control boot boot/work boot/baseline; do check_dir "${'$'}root/${'$'}dir"; done
            total=0
            count=0
            read_one() {
                rel=${'$'}1
                path="${'$'}root/${'$'}rel"
                [ ! -L "${'$'}path" ] || fail DIAGNOSTICS_SOURCE_SYMLINK
                if [ -e "${'$'}path" ]; then
                    [ -f "${'$'}path" ] && [ -r "${'$'}path" ] || fail DIAGNOSTICS_SOURCE_UNREADABLE
                    size=${'$'}(wc -c < "${'$'}path") || fail DIAGNOSTICS_SOURCE_UNREADABLE
                    total=${'$'}((total + size))
                    count=${'$'}((count + 1))
                    [ "${'$'}size" -le $MAX_FILE_BYTES ] && [ "${'$'}total" -le $MAX_TOTAL_BYTES ] &&
                        [ "${'$'}count" -le $MAX_FILES ] || fail DIAGNOSTICS_SOURCE_TOO_LARGE
                    encoded=${'$'}(base64 < "${'$'}path") || fail DIAGNOSTICS_SOURCE_UNREADABLE
                    printf 'FILE\t%s\t' "${'$'}rel"
                    printf '%s' "${'$'}encoded" | tr -d '\r\n'
                    printf '\n'
                fi
            }
            ${CONTROL_FILES.joinToString("\n") { "read_one '$it'" }}
            $journal
            for directory in "${'$'}root/boot/baseline/"*; do
                [ -e "${'$'}directory" ] || continue
                check_dir "${'$'}directory"
                name=${'$'}{directory##*/}
                case "${'$'}name" in ''|*[!A-Za-z0-9_-]*) fail DIAGNOSTICS_BASELINE_ID_INVALID;; esac
                [ "${'$'}{#name}" -le 128 ] || fail DIAGNOSTICS_BASELINE_ID_INVALID
                read_one "boot/baseline/${'$'}name/manifest.json"
            done
            printf 'END\n'
        """.trimIndent()
    }

    private fun quote(value: String) = "'" + value.replace("'", "'\\''") + "'"

    private companion object {
        const val HEADER = "MAPLESU_DIAGNOSTICS_V1"
        const val MAX_FILE_BYTES = 2 shl 20
        const val MAX_TOTAL_BYTES = 8 shl 20
        const val MAX_FILES = 128
        val ID = Regex("[A-Za-z0-9_-]{1,64}")
        val BASELINE_FILE = Regex("boot/baseline/[A-Za-z0-9_-]{1,128}/manifest\\.json")
        val CONTROL_FILES = listOf("control/switch.json", "control/evidence.jsonl", "control/device.slot",
            "control/device.firmware", "control/device.kernel", "control/boot_id")
    }
}
