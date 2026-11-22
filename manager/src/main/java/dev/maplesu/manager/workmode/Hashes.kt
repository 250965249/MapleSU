package dev.maplesu.manager.workmode

import java.io.File
import java.io.IOException
import java.io.InputStream
import java.security.MessageDigest

/** 纯 JVM 哈希工具（sha256 canonical 计算统一入口，禁止各处各写一套）。 */
object Hashes {
    fun sha256(bytes: ByteArray): String =
        toHex(MessageDigest.getInstance("SHA-256").digest(bytes))

    /**
     * 流式 sha256：**整块读进堆之前**用它（boot/init_boot 基线镜像 96 MiB 起）。
     *
     * 64 KiB 缓冲循环喂 [MessageDigest]，堆占用恒定（不随文件大小增长）。
     * 返回语义与 `sha256(file.readBytes())` 一致：文件不存在/不可读时抛出
     * [IOException]（`FileNotFoundException` 是其子类），由调用方决定如何处理——
     * 本方法**不吞异常、也不返回伪造的哈希**。
     */
    @Throws(IOException::class)
    fun sha256(file: File): String = file.inputStream().use { sha256(it) }

    /** 流式 sha256（[InputStream] 版本）；不关闭调用方的流，读失败抛 [IOException]。 */
    @Throws(IOException::class)
    fun sha256(input: InputStream): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(STREAM_BUFFER_BYTES)
        while (true) {
            val read = input.read(buffer)
            if (read < 0) break
            if (read == 0) continue
            digest.update(buffer, 0, read)
        }
        return toHex(digest.digest())
    }

    fun sha256Hex(text: String): String = sha256(text.toByteArray(Charsets.UTF_8))

    /** 前 [hexChars] 位（例如 apkPathHash=32、packageHash=16）。 */
    fun shortSha256(text: String, hexChars: Int = 32): String {
        require(hexChars in 1..64) { "HASH_LENGTH_INVALID" }
        return sha256Hex(text).take(hexChars)
    }

    private fun toHex(digest: ByteArray): String {
        val out = StringBuilder(digest.size * 2)
        for (value in digest) {
            val v = value.toInt() and 0xff
            out.append(HEX[v ushr 4]).append(HEX[v and 0x0f])
        }
        return out.toString()
    }

    /** 流式缓冲：64 KiB（对齐分区/文件系统块，不显著放大堆）。 */
    private const val STREAM_BUFFER_BYTES = 64 * 1024

    private const val HEX = "0123456789abcdef"
}
