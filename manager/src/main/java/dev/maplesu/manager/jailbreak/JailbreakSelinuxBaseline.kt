package dev.maplesu.manager.jailbreak

import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

/** Select observed history first; a normalized default never masquerades as a capture. */
internal object JailbreakSelinuxBaseline {
    data class Selection(val file: File?, val source: String, val detail: String? = null)

    @Synchronized fun select(raw: File, boot: String, attempt: String, windows: List<File>,
               trusted: (File) -> Boolean): Selection {
        var detail: String? = null
        for (candidate in windows) {
            val result = runCatching {
                check(trusted(candidate) && candidate.length() in 1..4096) { "JAILBREAK_SELINUX_WINDOW_OWNER" }
                val bytes = window(candidate.readText(), boot, attempt)
                val target = File(raw.path + ".window")
                atomicWrite(target, bytes)
                atomicWrite(File(target.path + ".boot"), "$boot\n".toByteArray())
                target
            }
            result.getOrNull()?.let { return Selection(it, "root-window") }
            detail = result.exceptionOrNull()?.message
        }
        val savedWindow = File(raw.path + ".window")
        if (runCatching { File(savedWindow.path + ".boot").readText().trim() == boot &&
                savedWindow.length() == 48L && validWindow(savedWindow.readBytes()) }.getOrDefault(false)) {
            return Selection(savedWindow, "root-window", detail)
        }
        if (runCatching { File(raw.path + ".boot").readText().trim() == boot &&
                raw.length() == 20L && stock(raw.readBytes()) }.getOrDefault(false)) {
            return Selection(raw, "pre-entry", detail)
        }
        return Selection(null, "normalized-default", detail ?: "JAILBREAK_SELINUX_BASELINE_MISSING")
    }

    fun stock(bytes: ByteArray): Boolean {
        if (bytes.size != 20) return false
        val fields = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        return fields.int == 1 && (fields.int and 1) == 0 && fields.int == 1 &&
            fields.run { int; int in 0..1 }
    }

    fun window(text: String, boot: String, attempt: String): ByteArray {
        val data = JSONObject(text)
        check(data.getString("schema") == "maplesu.selinux.window.v1" &&
            data.getString("provider") == "ghostlock" && data.getString("bootId") == boot &&
            data.getString("attempt") == attempt) { "JAILBREAK_SELINUX_WINDOW_BINDING" }
        fun words(values: JSONArray): LongArray {
            check(values.length() == 5) { "JAILBREAK_SELINUX_WINDOW_SIZE" }
            return LongArray(5) {
                checkNotNull(values.get(it).toString().toLongOrNull()?.takeIf { it in 0..0xffffffffL }) {
                    "JAILBREAK_SELINUX_WINDOW_INVALID"
                }
            }
        }
        val before = words(data.getJSONArray("before"))
        val after = words(data.getJSONArray("after"))
        val output = ByteBuffer.allocate(48).order(ByteOrder.LITTLE_ENDIAN)
        before.forEach { output.putInt(it.toInt()) }
        after.forEach { output.putInt(it.toInt()) }
        val from = data.getInt("restoreFrom")
        val to = data.getInt("restoreTo")
        output.putInt(from).putInt(to)
        check(validWindow(output.array())) { "JAILBREAK_SELINUX_WINDOW_INVALID" }
        return output.array()
    }

    private fun validWindow(bytes: ByteArray): Boolean {
        if (bytes.size != 48 || !stock(bytes.copyOfRange(0, 20)) || !stock(bytes.copyOfRange(20, 40))) return false
        val fields = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        val before = LongArray(5) { fields.int.toLong() and 0xffffffffL }
        val after = LongArray(5) { fields.int.toLong() and 0xffffffffL }
        return before[4] == after[4] && fields.int in 0..1 && fields.int == 1 &&
            ((after[1] - before[1]) and 0xffffffffL) < 0x7ffffffeL &&
            ((after[3] - before[3]) and 0xffffffffL) < 0x80000000L
    }

    @Synchronized fun atomicWrite(target: File, bytes: ByteArray) {
        val temporary = File(target.path + ".tmp")
        try {
            FileOutputStream(temporary).use { it.write(bytes); it.fd.sync() }
            check(temporary.renameTo(target)) { "JAILBREAK_SELINUX_SNAPSHOT_SAVE_FAILED" }
        } finally {
            temporary.delete()
        }
    }
}
