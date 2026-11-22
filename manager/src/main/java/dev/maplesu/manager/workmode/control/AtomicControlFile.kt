package dev.maplesu.manager.workmode.control

import dev.maplesu.manager.workmode.Hashes
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.nio.channels.FileChannel
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption

enum class ShaCheck { OK, MISSING, MISMATCH }

/**
 * 所有控制面写入的唯一路径。
 *
 * 语义与 `InstallerBootTransaction.save` 一致：
 * 同目录 tmp → fchmod 0600 → write → fd.sync() → ATOMIC_MOVE → fsync(dir) → 读回校验。
 * 禁止 "write 到目标名"、"先删后写"、"Strings 直写"。
 *
 * 主机说明：Windows 上目录 fsync / POSIX chmod 不可用 → 尽力而为（不抛错）；
 * 设备侧由 root 适配器补 `chown 0:0`（本类只保证内容与原子替换）。
 */
object AtomicControlFile {

    private val writeLock = Any()

    fun writeUtf8(target: File, bytes: ByteArray, readBackSha256: String? = null) {
        val parent = target.parentFile ?: throw IOException("CONTROL_DIR_INVALID")
        if (!parent.isDirectory) throw IOException("CONTROL_DIR_INVALID")
        val expected = readBackSha256?.lowercase() ?: Hashes.sha256(bytes)
        synchronized(writeLock) {
            val temporary = File(parent, ".${target.name}.tmp-${java.util.UUID.randomUUID()}")
            try {
                FileOutputStream(temporary).use { output ->
                    output.write(bytes)
                    output.flush()
                    output.fd.sync()
                }
                ControlPermissions.setPermissions(temporary, 0x180) // 0600
                moveAtomically(temporary, target)
                syncDirectory(parent)
                val actual = Hashes.sha256(target.readBytes())
                if (actual != expected) throw IOException("CONTROL_WRITE_FAILED")
            } finally {
                if (temporary.exists()) temporary.delete()
            }
        }
    }

    /**
     * 写 canonical JSON + 可选 `.sha256` 兄弟文件。
     * 读回校验的是"落盘字节的 sha"，不是"传入对象的 sha"。
     */
    fun writeJson(target: File, canonicalJson: String, writeSha256: Boolean = true) {
        val bytes = canonicalJson.toByteArray(Charsets.UTF_8)
        val sha = Hashes.sha256(bytes)
        writeUtf8(target, bytes, sha)
        if (writeSha256) {
            val shaBytes = sha.toByteArray(Charsets.UTF_8)
            writeUtf8(shaFile(target), shaBytes, Hashes.sha256(shaBytes))
        }
    }

    fun readUtf8(target: File, maxBytes: Int = 1 shl 20): String? {
        if (!target.isFile) return null
        if (target.length() > maxBytes) return null
        return runCatching { target.readText(Charsets.UTF_8) }.getOrNull()
    }

    fun readBytes(target: File, maxBytes: Int = 1 shl 20): ByteArray? {
        if (!target.isFile) return null
        if (target.length() > maxBytes) return null
        return runCatching { target.readBytes() }.getOrNull()
    }

    /** 校验兄弟 .sha256；缺失 = 无校验（旧版本文件），不匹配 = 损坏。 */
    fun verifySha(target: File): ShaCheck {
        if (!target.isFile) return ShaCheck.MISSING
        val shaFile = shaFile(target)
        if (!shaFile.isFile) return ShaCheck.MISSING
        val expected = runCatching { shaFile.readText(Charsets.UTF_8).trim().lowercase() }.getOrNull()
            ?: return ShaCheck.MISMATCH
        if (!expected.matches(Regex("[0-9a-f]{64}"))) return ShaCheck.MISMATCH
        val actual = runCatching { Hashes.sha256(target.readBytes()) }.getOrNull()
            ?: return ShaCheck.MISMATCH
        return if (actual == expected) ShaCheck.OK else ShaCheck.MISMATCH
    }

    fun shaFile(target: File): File = File(target.parentFile, "${target.name}.sha256")

    /** append-only + fsync（evidence.jsonl / WAL 用）。 */
    fun appendLine(target: File, line: String): Long {
        val parent = target.parentFile ?: throw IOException("CONTROL_DIR_INVALID")
        if (!parent.isDirectory) throw IOException("CONTROL_DIR_INVALID")
        val payload = buildString {
            if (target.isFile && target.length() > 0) {
                // 保证上一条以换行结尾（半写现场由调用方判定）
                val last = runCatching { target.inputStream().use { it.readBytes() } }.getOrNull()
                if (last != null && last.isNotEmpty() && last.last() != '\n'.code.toByte()) append('\n')
            }
            append(line)
            append('\n')
        }
        synchronized(writeLock) {
            FileOutputStream(target, true).use { output ->
                output.write(payload.toByteArray(Charsets.UTF_8))
                output.flush()
                output.fd.sync()
            }
        }
        return target.length()
    }

    fun syncDirectory(directory: File) {
        // POSIX: 打开目录 fd 并 fsync；Windows 上打开目录会失败 → 尽力而为。
        runCatching {
            FileChannel.open(directory.toPath(), StandardOpenOption.READ).use { it.force(true) }
        }
    }

    private fun moveAtomically(source: File, target: File) {
        try {
            Files.move(
                source.toPath(), target.toPath(),
                StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING,
            )
        } catch (_: AtomicMoveNotSupportedException) {
            Files.move(source.toPath(), target.toPath(), StandardCopyOption.REPLACE_EXISTING)
        }
    }
}
