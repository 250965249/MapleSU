package dev.maplesu.manager.runtime.ultra

import java.nio.file.Files
import java.security.MessageDigest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class UltraPolicyBackendArtifactTest {
    @Test fun validatesTheExactPackagedBytesBeforeNativePublication() {
        val file = Files.createTempFile("policy-backend", ".so").toFile()
        try {
            val bytes = ByteArray(8193) { (it % 251).toByte() }
            val sha = MessageDigest.getInstance("SHA-256").digest(bytes)
                .joinToString("") { "%02x".format(it.toInt() and 255) }
            file.writeBytes(bytes)
            assertArrayEquals(bytes, UltraPolicyBackendArtifact.read(file, sha, bytes.size.toLong()))
            file.writeBytes(bytes.clone().also { it[4096] = (it[4096].toInt() xor 1).toByte() })
            assertThrows(IllegalArgumentException::class.java) {
                UltraPolicyBackendArtifact.read(file, sha, bytes.size.toLong())
            }
            file.writeBytes(bytes)
            for ((digest, size) in listOf(sha to 64L, sha to 33_554_433L, sha.uppercase() to bytes.size.toLong(),
                                           "../wrong" to bytes.size.toLong(), sha to 0L)) {
                assertThrows(IllegalArgumentException::class.java) { UltraPolicyBackendArtifact.read(file, digest, size) }
            }
        } finally {
            file.delete()
        }
    }
}
