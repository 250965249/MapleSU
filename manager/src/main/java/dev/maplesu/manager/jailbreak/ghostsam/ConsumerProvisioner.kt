package dev.maplesu.manager.jailbreak.ghostsam

import java.io.File
import java.security.MessageDigest

/**
 * Locates the self-built V2 consumer (libmaplesu_ghostsam_consumer.so) and verifies its
 * digest against a pinned manifest value. Missing/mismatched => fail closed, never launch.
 */
class ConsumerProvisioner(
    private val nativeLibraryDir: File,
    private val expectedSha256: String,   // pinned hex; empty => refuse (fail-closed)
) {
    data class Resolved(val path: String, val sha256: String)

    fun resolve(): Resolved {
        if (expectedSha256.length != 64) throw LeaseWireException("DIGEST_MISMATCH")
        val candidate = File(nativeLibraryDir, "libmaplesu_ghostsam_consumer.so")
        if (!candidate.isFile) throw LeaseWireException("CONSUMER_MISSING")
        val digest = MessageDigest.getInstance("SHA-256").digest(candidate.readBytes())
        val hex = digest.joinToString("") { "%02x".format(it) }
        if (hex != expectedSha256.lowercase()) throw LeaseWireException("DIGEST_MISMATCH")
        return Resolved(candidate.absolutePath, hex)
    }
}
