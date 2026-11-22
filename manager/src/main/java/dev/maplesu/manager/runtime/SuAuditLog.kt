package dev.maplesu.manager.runtime

import android.content.Context
import java.io.File
import java.io.FileOutputStream
import java.security.MessageDigest
import java.util.Locale

/**
 * The one su audit log (design §5).
 *
 * <p>Why it exists. `LiteWebAdminService.sulog()` used to answer `available=false`
 * ("Ultra does not record su logs"), and `StageMark.LINE_SINK` was declared but never
 * assigned anywhere in the repository, so every `su:start:denied:*` line was a no-op.
 * The result was that a refusal on the Ultra route left no evidence at all.
 *
 * <p>Format: JSONL, one object per line, bounded at 256 KiB with one rotation. The field
 * list is fixed by the design; **no token, no full argv, no file content, no signing
 * material** ever goes in. `argvSha256` is the first 16 hex digits of
 * `sha256(argv.joinToString("\0"))`.
 *
 * <p>Failure semantics: a write failure is recorded (once per process) as
 * [dev.maplesu.manager.runtime.authorization.SuCodes.SU_AUDIT_WRITE_FAILED] and never
 * changes a decision.
 */
data class SuAuditEvent(
    val backend: String,
    val event: String,
    val bootId: String? = null,
    val attemptId: String? = null,
    val callerUid: Int? = null,
    val callerPackages: List<String> = emptyList(),
    val decision: String? = null,
    val reason: String? = null,
    val sessionId: String? = null,
    val argv0: String? = null,
    val argvSha256: String? = null,
    val gate: String? = null,
    val exitCode: Int? = null,
    val durationMs: Long? = null,
    val rev: Long? = null,
    val source: String? = null,
    /** Free-form diagnostic for stage lines; never carries a command or a secret. */
    val detail: String? = null,
    val ts: Long = System.currentTimeMillis(),
)

object SuAuditLog {
    const val FILE = "su-audit.log"
    const val ROTATED = "su-audit.log.1"
    const val LIMIT_BYTES = 256 * 1024
    const val TAIL_LINES = 200

    /** Root-side mirror (P2, best effort): the file Normal's `sulog` already reads. */
    const val ROOT_MIRROR = "/data/adb/maplesu/logs/su.log"

    @Volatile
    private var writeFailureLogged = false

    @JvmStatic
    fun file(context: Context): File {
        val protected = context.createDeviceProtectedStorageContext().dataDir
            ?: context.filesDir.parentFile ?: context.filesDir
        return File(protected, FILE)
    }

    @JvmStatic
    fun exists(context: Context): Boolean = runCatching { file(context).isFile }.getOrDefault(false)

    /**
     * Appends one event; returns false when the line could not be written.
     *
     * <p>Rotation happens before the append so a single line is never split across the
     * two files: the reader's last-N-lines query stays parseable.
     */
    @JvmStatic
    fun append(context: Context, event: SuAuditEvent): Boolean =
        write(file(context), event, LIMIT_BYTES)

    @JvmStatic
    fun write(file: File, event: SuAuditEvent, limitBytes: Int = LIMIT_BYTES): Boolean = try {
        val parent = file.absoluteFile.parentFile
        if (parent != null && !parent.isDirectory) parent.mkdirs()
        if (file.isFile && file.length() + 256 > limitBytes) {
            runCatching {
                val rotated = File(file.absoluteFile.parentFile, ROTATED)
                if (rotated.exists()) rotated.delete()
                file.renameTo(rotated)
            }
        }
        /*
         * Two writers share this file: the `:root_directory` endpoint (app uid) and the
         * one-shot root tool (`SuperuserTool`, uid 0). A file created by the root tool is
         * root-owned, so without this the app-uid endpoint's next append would fail with
         * EACCES and the log would silently stop. The parent directory is app-private
         * (0700), so widening the file's own mode exposes it to nobody else.
         */
        if (file.isFile) {
            runCatching { file.setReadable(true, false) }
            runCatching { file.setWritable(true, false) }
        }
        FileOutputStream(file, true).use { output ->
            output.write(line(event).toByteArray(Charsets.UTF_8))
            output.write('\n'.code)
        }
        runCatching { file.setReadable(true, false) }
        runCatching { file.setWritable(true, false) }
        true
    } catch (_: Throwable) {
        markWriteFailure()
        false
    }

    /** Last [limit] readable lines; a missing file is an empty list, never an error. */
    @JvmStatic
    @JvmOverloads
    fun tail(context: Context, limit: Int = TAIL_LINES): List<String> = try {
        val file = file(context)
        if (!file.isFile) emptyList()
        else file.readLines(Charsets.UTF_8).filter { it.isNotBlank() }.takeLast(limit.coerceAtLeast(0))
    } catch (_: Throwable) {
        emptyList()
    }

    /** The single JSONL serializer; pure, so the host test can assert its exact field set. */
    @JvmStatic
    fun line(event: SuAuditEvent): String {
        val fields = LinkedHashMap<String, String?>()
        fields["ts"] = event.ts.toString()
        fields["bootId"] = event.bootId
        fields["attemptId"] = event.attemptId
        fields["backend"] = event.backend
        fields["event"] = event.event
        fields["callerUid"] = event.callerUid?.toString()
        fields["callerPackages"] = event.callerPackages.takeIf { it.isNotEmpty() }?.let { packages ->
            packages.joinToString(",", "[", "]") { '"' + escape(it) + '"' }
        }
        fields["decision"] = event.decision
        fields["reason"] = event.reason
        fields["sessionId"] = event.sessionId
        fields["argv0"] = event.argv0
        fields["argvSha256"] = event.argvSha256
        fields["gate"] = event.gate
        fields["exitCode"] = event.exitCode?.toString()
        fields["durationMs"] = event.durationMs?.toString()
        fields["rev"] = event.rev?.toString()
        fields["source"] = event.source
        fields["detail"] = event.detail
        return fields.entries.joinToString(",", "{", "}") { (name, value) ->
            if (value == null) "\"$name\":null"
            else if (name == "callerPackages") "\"$name\":$value"
            else "\"$name\":\"" + escape(value) + "\""
        }
    }

    /**
     * `sha256(argv.joinToString("\0"))` first 16 hex digits - the only argv-derived
     * value the log may carry. It is a fingerprint for correlation, not a command.
     */
    @JvmStatic
    fun argvDigest(argv: List<String>): String = try {
        val digest = MessageDigest.getInstance("SHA-256")
            .digest(argv.joinToString("\u0000").toByteArray(Charsets.UTF_8))
        digest.take(8).joinToString("") { "%02x".format(Locale.ROOT, it.toInt() and 255) }
    } catch (_: Throwable) {
        ""
    }

    /** `argv0` is the program path only - never its arguments. */
    @JvmStatic
    fun argv0(argv: List<String>): String? = argv.firstOrNull()?.takeIf { it.isNotEmpty() }

    @JvmStatic
    fun markWriteFailure() {
        if (writeFailureLogged) return
        writeFailureLogged = true
        android.util.Log.w("MapleSUSu", "SU_AUDIT_WRITE_FAILED")
    }

    private fun escape(value: String): String = buildString(value.length) {
        for (character in value) {
            when (character) {
                '\\' -> append("\\\\")
                '"' -> append("\\\"")
                '\n' -> append("\\n")
                '\r' -> append("\\r")
                '\t' -> append("\\t")
                else -> if (character < ' ') {
                    append("\\u").append(String.format(Locale.ROOT, "%04x", character.code))
                } else {
                    append(character)
                }
            }
        }
    }
}
