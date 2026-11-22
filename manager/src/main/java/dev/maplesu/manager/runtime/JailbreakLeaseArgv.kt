package dev.maplesu.manager.runtime

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.util.Base64

/** Lease management argv1: execution arguments only; cwd and environment stay inherited. */
internal object JailbreakLeaseArgv {
    private const val MAX_ARGUMENTS = 256
    private const val MAX_BYTES = 131_072
    private const val MAX_FRAME = 4 + 4 * MAX_ARGUMENTS + MAX_BYTES

    fun encode(arguments: Array<String>): String {
        require(arguments.size in 1..MAX_ARGUMENTS) { "JAILBREAK_EXECUTOR_BAD_ARGV" }
        val frame = ByteArrayOutputStream()
        val output = DataOutputStream(frame)
        output.writeInt(arguments.size)
        var remaining = MAX_BYTES
        for (value in arguments) {
            require(value.length <= remaining && '\u0000' !in value) { "JAILBREAK_EXECUTOR_BAD_ARGV" }
            val bytes = value.toByteArray(Charsets.UTF_8)
            require(bytes.size <= remaining && bytes.toString(Charsets.UTF_8) == value) { "JAILBREAK_EXECUTOR_BAD_ARGV" }
            remaining -= bytes.size
            output.writeInt(bytes.size)
            output.write(bytes)
        }
        return Base64.getEncoder().encodeToString(frame.toByteArray())
    }

    fun decode(encoded: String): List<String> {
        require(encoded.length <= ((MAX_FRAME + 2) / 3) * 4)
        val frame = Base64.getDecoder().decode(encoded)
        require(frame.size <= MAX_FRAME)
        val input = DataInputStream(ByteArrayInputStream(frame))
        val count = input.readInt().also { require(it in 1..MAX_ARGUMENTS) }
        var remaining = MAX_BYTES
        val arguments = List(count) {
            val length = input.readInt()
            require(length in 0..remaining && length <= input.available())
            remaining -= length
            val bytes = ByteArray(length).also(input::readFully)
            bytes.toString(Charsets.UTF_8).also { value ->
                require('\u0000' !in value && value.toByteArray(Charsets.UTF_8).contentEquals(bytes))
            }
        }
        require(input.available() == 0)
        return arguments
    }
}
