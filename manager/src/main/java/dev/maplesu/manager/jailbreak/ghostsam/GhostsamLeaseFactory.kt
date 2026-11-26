package dev.maplesu.manager.jailbreak.ghostsam

import android.net.LocalServerSocket
import java.io.IOException
import java.security.SecureRandom
import java.util.Arrays
import java.util.UUID

/**
 * V2 MapleSU-side self-owned lease construction (t21 §4.3). Generates endpoint/nonce/boot/uid
 * WITHOUT calling the upstream RootShellLease.prepare()/consumerArgv() (no argv nonce path).
 */
class GhostsamLeaseFactory(
    private val bootIdReader: () -> String = { java.io.File("/proc/sys/kernel/random/boot_id").readText().trim() },
    private val uidProvider: () -> Int = { android.os.Process.myUid() },
) {
    data class Lease(val endpoint: String, val nonce: ByteArray, val nonceHex: String,
                     val managerUid: Int, val bootId: String, val provider: String,
                     val server: LocalServerSocket) {
        fun stdinPacket(): ByteArray = StdinTlv.encode(nonce, endpoint, managerUid, bootId)
    }

    fun create(provider: String = "ghostlock", uid: Int = uidProvider()): Lease {
        if (uid < 10000) throw LeaseWireException("LEASE_ORDINARY_APP_UID_REQUIRED")
        val boot = bootIdReader()
        if (!CommandBuilder.bootId(boot)) throw LeaseWireException("LEASE_BOOT_ID_UNAVAILABLE")
        if (provider != "ghostlock" && provider != "dirtyfrag") throw LeaseWireException("LEASE_PROVIDER_INVALID")
        val nonce = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val endpoint = "maplesu-jb-" + UUID.randomUUID().toString().lowercase()
        // N2: the factory creates and owns the listener bound to this exact endpoint.
        val server = try {
            LocalServerSocket(endpoint)
        } catch (e: IOException) {
            throw LeaseWireException("GHOSTSAM_ENDPOINT_BIND_FAILED")
        }
        return Lease(endpoint, nonce, nonce.joinToString("") { "%02x".format(it) }, uid, boot, provider, server)
    }

    /** N2: close the listener and zero the nonce; safe to call on success and failure. */
    fun close(lease: Lease) {
        runCatching { lease.server.close() }
        Arrays.fill(lease.nonce, 0)
    }
}
