package dev.maplesu.manager.jailbreak.ghostsam

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * V2 consumer stdin first-packet TLV (MapleSU-side custom, per t21 §4.3): carries the lease
 * parameters that must NOT appear in argv — nonce(32), endpoint, uid, boot_id.
 * Layout: repeated [tag u8][len u16 BE][value], terminated by tag 0x00 (no length/value).
 */
object StdinTlv {
    const val NONCE = 0x01
    const val ENDPOINT = 0x02
    const val UID = 0x03
    const val BOOT = 0x04
    const val END = 0x00

    fun encode(nonce: ByteArray, endpoint: String, uid: Int, bootId: String): ByteArray {
        require(nonce.size == 32) { "LEASE_NONCE_INVALID" }
        val out = ByteArrayOutputStream()
        fun put(tag: Int, value: ByteArray) {
            require(value.size <= 0xFFFF) { "LEASE_TLV_TOO_LONG" }
            out.write(tag)
            out.write(byteArrayOf((value.size ushr 8).toByte(), value.size.toByte()))
            out.write(value)
        }
        put(NONCE, nonce)
        put(ENDPOINT, endpoint.toByteArray(Charsets.UTF_8))
        put(UID, ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(uid).array())
        put(BOOT, bootId.toByteArray(Charsets.UTF_8))
        out.write(END)
        return out.toByteArray()
    }
}
