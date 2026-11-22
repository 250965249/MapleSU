// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.ksu

import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * 主机可用的合成镜像夹具（不读取任何真机私有镜像）。
 *
 * 只构造测试需要的三种形态：
 * - `stock`：OEM init_boot ramdisk（只有 init，无任何 SU 残留）；
 * - `ksu`：上游布局（init + init.real + kernelsu.ko + ksu_config，可选 maplesu_id）；
 * - `foreign`：7K 双条目布局（额外 sevenk.ko）。
 *
 * 容器是 AOSP boot v4（`init_boot` 无 kernel 段，ramdisk 紧跟 4096 字节头）。
 */
object KsuImageFixtures {

    private const val S_IFREG = 0x81a4 // 0100644
    private const val S_IFDIR = 0x41ed // 0040755
    private const val PAGE = 4096

    fun cpio(entries: List<Pair<String, ByteArray>>): ByteArray {
        val out = ByteArrayOutputStream()
        fun hex(value: Int, width: Int) {
            out.write(String.format("%0${width}x", value).toByteArray(Charsets.US_ASCII))
        }

        for ((name, content) in entries) {
            val nameBytes = name.toByteArray(Charsets.UTF_8) + byteArrayOf(0)
            out.write("070701".toByteArray(Charsets.US_ASCII))
            hex(1, 8) // ino
            hex(if (name.endsWith("/")) S_IFDIR else S_IFREG, 8) // mode
            hex(0, 8) // uid
            hex(0, 8) // gid
            hex(1, 8) // nlink
            hex(0, 8) // mtime
            hex(content.size, 8) // filesize
            hex(0, 8) // devmajor
            hex(0, 8) // devminor
            hex(0, 8) // rdevmajor
            hex(0, 8) // rdevminor
            hex(nameBytes.size, 8) // namesize
            hex(0, 8) // check
            out.write(nameBytes)
            pad4(out)
            out.write(content)
            pad4(out)
        }
        // TRAILER!!!
        val trailer = "TRAILER!!!".toByteArray(Charsets.US_ASCII) + byteArrayOf(0)
        out.write("070701".toByteArray(Charsets.US_ASCII))
        hex(1, 8); hex(S_IFREG, 8); hex(0, 8); hex(0, 8); hex(1, 8); hex(0, 8)
        hex(0, 8); hex(0, 8); hex(0, 8); hex(0, 8); hex(0, 8); hex(trailer.size, 8); hex(0, 8)
        out.write(trailer)
        pad4(out)
        return out.toByteArray()
    }

    fun stockRamdisk(): ByteArray = cpio(
        listOf(
            "init" to "stock-android-init".toByteArray(),
            "system/" to ByteArray(0),
            "system/bin/" to ByteArray(0),
            "system/bin/sh" to "stock-shell".toByteArray(),
            "fstab.qcom" to "stock-fstab".toByteArray(),
        ),
    )

    fun ksuRamdisk(withMaplesuId: Boolean = false): ByteArray {
        val entries = mutableListOf(
            "init" to "new-ksuinit".toByteArray(),
            "init.real" to "stock-android-init".toByteArray(),
            "kernelsu.ko" to "KO-PAYLOAD-ours".toByteArray(),
            "ksu_config" to "kmi=android15-6.6".toByteArray(),
        )
        if (withMaplesuId) entries += "maplesu_id" to ByteArray(0)
        return cpio(entries)
    }

    fun foreignSevenkRamdisk(): ByteArray = cpio(
        listOf(
            "init" to "new-ksuinit".toByteArray(),
            "init.real" to "stock-android-init".toByteArray(),
            "kernelsu.ko" to "KO-PAYLOAD".toByteArray(),
            "sevenk.ko" to "SEVENK-KO".toByteArray(),
            "ksu_config" to "kmi=android15-6.6".toByteArray(),
        ),
    )

    /** AOSP boot v4（init_boot：kernel_size=0，ramdisk @4096）。 */
    fun bootV4(ramdisk: ByteArray): ByteArray {
        val total = align((PAGE + ramdisk.size).toLong(), PAGE.toLong()).toInt()
        val image = ByteArray(total)
        val header = ByteBuffer.wrap(image).order(ByteOrder.LITTLE_ENDIAN)
        header.put("ANDROID!".toByteArray(Charsets.US_ASCII))
        header.putInt(8, 0) // kernel_size
        header.putInt(12, ramdisk.size) // ramdisk_size
        header.putInt(20, 1584) // header_size (v4)
        header.putInt(40, 4) // header_version
        System.arraycopy(ramdisk, 0, image, PAGE, ramdisk.size)
        return image
    }

    fun stockImage(): ByteArray = bootV4(stockRamdisk())

    fun ksuImage(withMaplesuId: Boolean = false): ByteArray =
        bootV4(ksuRamdisk(withMaplesuId))

    fun foreignImage(): ByteArray = bootV4(foreignSevenkRamdisk())

    fun write(dir: File, name: String, bytes: ByteArray): File =
        File(dir, name).apply {
            parentFile?.mkdirs()
            writeBytes(bytes)
        }

    /**
     * boot-patch 用的假 root shell：从命令行里解析 `-b/-o/--out-name`，
     * 把预先给定的候选字节写到 outDir/outName，并记录收到的整条命令。
     */
    class FakeBootPatchRunner(private val candidateBytes: ByteArray?) : KsuRootCommandRunner {
        val commands = mutableListOf<String>()
        var exitCode: Int = 0
        var stderr: String = ""

        override fun run(commandLine: String, timeoutMs: Long): KsuShellResult {
            commands += commandLine
            val tokens = splitCommandLine(commandLine)
            if (exitCode != 0 || candidateBytes == null) {
                return KsuShellResult(exitCode, emptyList(), listOf(stderr))
            }
            val source = tokens.indexOf("-b").let { if (it >= 0) tokens.getOrNull(it + 1) else null }
            val outDir = tokens.indexOf("-o").let { if (it >= 0) tokens.getOrNull(it + 1) else null }
            val outName = tokens.indexOf("--out-name").let { if (it >= 0) tokens.getOrNull(it + 1) else null }
            require(source != null && outDir != null && outName != null) {
                "fake runner received an unexpected command: $commandLine"
            }
            val dir = File(outDir!!).apply { mkdirs() }
            File(dir, outName!!).writeBytes(candidateBytes)
            return KsuShellResult(0, listOf("patched"), emptyList())
        }
    }

    /** 按 shell 单引号规则拆分命令行（与 [KsuInstallProducer.shellJoin] 对称）。 */
    fun splitCommandLine(line: String): List<String> {
        val tokens = mutableListOf<String>()
        val current = StringBuilder()
        var inSingle = false
        var index = 0
        fun flush() {
            if (current.isNotEmpty()) {
                tokens += current.toString()
                current.clear()
            }
        }
        while (index < line.length) {
            val char = line[index]
            when {
                inSingle -> if (char == '\'') inSingle = false else current.append(char)
                char == '\'' -> inSingle = true
                char == ' ' -> flush()
                else -> current.append(char)
            }
            index++
        }
        flush()
        return tokens
    }

    private fun pad4(out: ByteArrayOutputStream) {
        while (out.size() % 4 != 0) out.write(0)
    }

    private fun align(value: Long, page: Long): Long = (value + page - 1) / page * page
}
