package dev.maplesu.manager.runtime.ultra

import java.io.File
import java.security.MessageDigest

internal object UltraPolicyBackendArtifact {
    fun read(source: File, sha256: String, size: Long): ByteArray {
        require(sha256.matches(Regex("[0-9a-f]{64}")) && size in 64L..33_554_432L)
        require(source.length() == size)
        val bytes = ByteArray(size.toInt())
        source.inputStream().use { input ->
            var offset = 0
            while (offset < bytes.size) {
                val count = input.read(bytes, offset, bytes.size - offset)
                require(count > 0)
                offset += count
            }
            require(input.read() == -1)
        }
        val actual = MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02x".format(it.toInt() and 255) }
        require(actual == sha256)
        return bytes
    }
}
