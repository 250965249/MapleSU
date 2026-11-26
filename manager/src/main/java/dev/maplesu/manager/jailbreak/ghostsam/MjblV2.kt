package dev.maplesu.manager.jailbreak.ghostsam

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.security.MessageDigest

/** Named wire failure. Tokens match the design contract (§2.2 / t19). */
class LeaseWireException(val token: String) : Exception(token)

/**
 * MJBL v2 self-built encoder/decoder (MapleSU side, GhostSam adapter V2).
 * Integers are BIG-ENDIAN (DataInputStream/DataOutputStream). No Android APIs.
 * Limits per t19 P6: boot_id <= 128 bytes, domain <= 256 bytes.
 */
object MjblV2 {
    const val MAGIC = 0x4D4A424C
    const val VERSION_V2 = 2
    const val PROVIDER_GHOSTLOCK = 1
    const val PROVIDER_DIRTYFRAG = 2
    const val CAPABILITY_ROOT_WORKER = 1
    const val BOOT_MAX = 128
    const val DOMAIN_MAX = 256

    data class Identity(
        val provider: Int, val pid: Int, val uid: Int, val starttime: Long,
        val bootId: String, val domain: String, val enforcing: Int, val seccomp: Int,
    )

    fun encode(
        provider: Int, pid: Int, uid: Int, starttime: Long, nonce: ByteArray,
        bootId: String, domain: String, enforcing: Int, seccomp: Int,
        capability: Int = CAPABILITY_ROOT_WORKER,
    ): ByteArray {
        if (nonce.size != 32) throw LeaseWireException("LEASE_NONCE_INVALID")
        if (provider != PROVIDER_GHOSTLOCK && provider != PROVIDER_DIRTYFRAG) throw LeaseWireException("LEASE_PROVIDER_INVALID")
        if (enforcing != 0 && enforcing != 1) throw LeaseWireException("LEASE_ENFORCING_INVALID")
        if (seccomp !in 0..2) throw LeaseWireException("LEASE_SECCOMP_UNAVAILABLE")
        val boot = bootId.toByteArray(Charsets.UTF_8)
        val dom = domain.toByteArray(Charsets.UTF_8)
        if (boot.size > BOOT_MAX) throw LeaseWireException("LEASE_BOOT_ID_INVALID")
        if (dom.size > DOMAIN_MAX) throw LeaseWireException("LEASE_DOMAIN_INVALID")
        val bytes = ByteArrayOutputStream()
        DataOutputStream(bytes).use { out ->
            out.writeInt(MAGIC); out.writeInt(VERSION_V2); out.writeInt(provider)
            out.writeInt(pid); out.writeInt(uid)
            out.writeInt((starttime ushr 32).toInt()); out.writeInt(starttime.toInt())
            out.writeInt(capability); out.write(nonce)
            out.writeInt(boot.size); out.write(boot)
            out.writeInt(dom.size); out.write(dom)
            out.writeInt(enforcing); out.writeInt(seccomp)
        }
        return bytes.toByteArray()
    }

    fun decode(data: ByteArray, expectedNonce: ByteArray, expectedBootId: String,
               peerPid: Int, peerUid: Int, expectedStarttime: Long? = null): Identity {
        val input = DataInputStream(ByteArrayInputStream(data))
        fun u32(): Int = input.readInt()
        if (u32() != MAGIC) throw LeaseWireException("LEASE_MAGIC_INVALID")
        if (u32() != VERSION_V2) throw LeaseWireException("LEASE_VERSION_INVALID")
        val provider = u32()
        if (provider != PROVIDER_GHOSTLOCK && provider != PROVIDER_DIRTYFRAG) throw LeaseWireException("LEASE_PROVIDER_INVALID")
        val pid = u32()
        if (pid != peerPid || pid <= 1) throw LeaseWireException("LEASE_SHELL_PID_INVALID")
        val uid = u32()
        if (peerUid != 0) throw LeaseWireException("LEASE_ROOT_PEER_REQUIRED")
        if (uid != peerUid) throw LeaseWireException("LEASE_UID_MISMATCH")
        val hi = u32().toLong() and 0xFFFFFFFFL
        val lo = u32().toLong() and 0xFFFFFFFFL
        val starttime = (hi shl 32) or lo
        // v2 anti-pid-reuse: a zero or mismatched starttime is rejected (upstream token name).
        if (starttime == 0L || (expectedStarttime != null && starttime != expectedStarttime))
            throw LeaseWireException("LEASE_WORKER_STARTTIME_INVALID")
        if (u32() != CAPABILITY_ROOT_WORKER) throw LeaseWireException("LEASE_CAPABILITY_MISSING")
        val nonce = ByteArray(32); input.readFully(nonce)
        if (!MessageDigest.isEqual(nonce, expectedNonce)) throw LeaseWireException("LEASE_NONCE_MISMATCH")
        val bootLen = u32()
        if (bootLen < 0 || bootLen > BOOT_MAX) throw LeaseWireException("LEASE_BOOT_ID_INVALID")
        val boot = ByteArray(bootLen); input.readFully(boot)
        if (String(boot, Charsets.UTF_8) != expectedBootId) throw LeaseWireException("LEASE_BOOT_ID_MISMATCH")
        val domLen = u32()
        if (domLen < 0 || domLen > DOMAIN_MAX) throw LeaseWireException("LEASE_DOMAIN_INVALID")
        val dom = ByteArray(domLen); input.readFully(dom)
        val enforcing = u32(); if (enforcing != 0 && enforcing != 1) throw LeaseWireException("LEASE_ENFORCING_INVALID")
        val seccomp = u32(); if (seccomp !in 0..2) throw LeaseWireException("LEASE_SECCOMP_UNAVAILABLE")
        if (input.available() != 0) throw LeaseWireException("LEASE_FRAME_TRAILING")
        return Identity(provider, pid, uid, (hi shl 32) or lo, String(boot, Charsets.UTF_8), String(dom, Charsets.UTF_8), enforcing, seccomp)
    }
}
