package dev.maplesu.client

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream

/**
 * One execution request, encoded exactly as the Root side reads it.
 *
 * <p>The wire form is a fixed big-endian header followed by length-prefixed UTF-8
 * strings. Field order, limits and validation mirror the Root side's reader, so a
 * malformed request is rejected here with a typed [CooperativeSuException] instead
 * of being sent and failing with an opaque transport error.
 *
 * <p>No credential, token or identity field exists in this frame. The Root side
 * takes the caller's identity from Binder, never from these bytes.
 */
data class SuRequest(
    /** Absolute path of the executable the Root side will run. */
    val executable: String,
    /** argv including argv[0]. */
    val arguments: List<String>,
    /** `NAME=value` entries only. */
    val environment: List<String> = emptyList(),
    /** Absolute working directory. */
    val directory: String = "/",
    /** Bit 0 stdin, bit 1 stdout, bit 2 stderr: which streams live on the PTY. */
    val terminals: Int = 0,
    /** Linux uid the child runs as; 0 for root. */
    val targetUid: Int = 0,
    /** Request the global mount namespace; the Root side may refuse it. */
    val globalMount: Boolean = false,
    /** rows, cols, xpixel, ypixel. */
    val window: IntArray = intArrayOf(0, 0, 0, 0),
) {
    // IntArray makes the generated equals/hashCode identity-based; that is why this
    // is a data class with an explicit note rather than a silent surprise.
    override fun equals(other: Any?): Boolean = this === other
    override fun hashCode(): Int = System.identityHashCode(this)

    fun encode(): ByteArray {
        try {
            validate()
        } catch (failure: IllegalArgumentException) {
            throw CooperativeSuException("SU_REQUEST_INVALID", failure.message, failure)
        }
        val bytes = ByteArrayOutputStream()
        DataOutputStream(bytes).use { out ->
            out.writeInt(MAGIC)
            out.writeInt(terminals)
            out.writeInt(targetUid)
            out.writeInt(if (globalMount) 1 else 0)
            window.forEach(out::writeInt)
            fun text(value: String) {
                val encoded = value.toByteArray(Charsets.UTF_8)
                out.writeInt(encoded.size)
                out.write(encoded)
            }
            text(executable)
            text(directory)
            out.writeInt(arguments.size)
            arguments.forEach(::text)
            out.writeInt(environment.size)
            environment.forEach(::text)
            out.flush()
        }
        val frame = bytes.toByteArray()
        if (frame.size > MAX_FRAME) {
            throw CooperativeSuException("SU_FRAME_TOO_LARGE", "encoded ${frame.size} > $MAX_FRAME bytes")
        }
        return frame
    }

    private fun validate() {
        require(terminals in 0..7) { "SU_REQUEST_INVALID: terminals" }
        require(targetUid >= 0) { "SU_REQUEST_INVALID: targetUid" }
        requirePath(executable, "executable")
        requirePath(directory, "directory")
        require(arguments.size in 1..256) { "SU_REQUEST_INVALID: argument count" }
        require(arguments.first().isNotEmpty()) { "SU_REQUEST_INVALID: argv[0] empty" }
        arguments.forEach { requireText(it, "argument") }
        require(environment.size in 0..512) { "SU_REQUEST_INVALID: environment count" }
        environment.forEach {
            requireText(it, "environment")
            require(it.indexOf('=') > 0) { "SU_REQUEST_INVALID: environment entry needs NAME=value" }
        }
        require(window.size == 4 && window.all { it in 0..65535 }) { "SU_REQUEST_INVALID: window" }
        val textTotal = (listOf(executable, directory) + arguments + environment)
            .sumOf { it.toByteArray(Charsets.UTF_8).size }
        require(textTotal <= MAX_TEXT) { "SU_FRAME_TOO_LARGE: text $textTotal > $MAX_TEXT bytes" }
    }

    private fun requirePath(value: String, field: String) {
        requireText(value, field)
        require(value.startsWith('/')) { "SU_REQUEST_INVALID: $field must be absolute" }
    }

    private fun requireText(value: String, field: String) {
        require('\u0000' !in value) { "SU_REQUEST_INVALID: $field contains NUL" }
        // Reject strings whose UTF-8 round trip is lossy instead of silently
        // changing the bytes the Root side will execute.
        val encoded = value.toByteArray(Charsets.UTF_8)
        require(String(encoded, Charsets.UTF_8) == value) { "SU_REQUEST_INVALID: $field is not valid UTF-8" }
    }

    private companion object {
        const val MAGIC = 0x4d535531
        /** Root side rejects anything larger. */
        const val MAX_FRAME = 140_000
        const val MAX_TEXT = 131_072
    }
}
