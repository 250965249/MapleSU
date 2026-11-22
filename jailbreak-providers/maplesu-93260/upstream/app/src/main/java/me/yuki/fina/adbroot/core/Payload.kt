package me.yuki.fina.adbroot.core

import android.content.Context
import java.io.File
import java.util.zip.GZIPInputStream

/**
 * 打包在 assets/payload 里的设备端组件。
 *
 * 资产名（专业命名）与设备上的落地名分开：
 *   assets/payload/cred_bootstrap        → /data/local/tmp/louise
 *   assets/payload/root_dispatcher.sh    → /data/local/tmp/louise_cmd.sh
 *   assets/payload/kprobe_trigger        → /data/local/tmp/probe
 *   assets/payload/kallsyms_6.12.58.dat → /data/local/tmp/PD2546-symbols.json
 */
object Payload {

    private data class Item(val device: String, val asset: String)

    private val ITEMS = listOf(
        Item("louise", "payload/cred_bootstrap"),
        Item("louise_cmd.sh", "payload/root_dispatcher.sh"),
        Item("probe", "payload/kprobe_trigger.bin"),
        Item("PD2546-symbols.json", "payload/kallsyms_6.12.58.bin"),
    )

    /** 这些在 assets 里是 .gz，落地时解压（符号表 15.4 MB → 1.4 MB）。 */
    private val GZIPPED = setOf("PD2546-symbols.json", "probe")

    fun dir(context: Context): File = File(context.filesDir, "payload")

    /** 首次启动（或资产更新后）把 payload 解到 filesDir/payload。 */
    fun ensure(context: Context): File {
        val out = dir(context)
        out.mkdirs()
        for (item in ITEMS) {
            val name = item.device
            val dst = File(out, name)
            val gz = GZIPPED.contains(name)

            if (gz) {
                // 压缩包没法比长度，够大就当作已解压好
                if (dst.exists() && dst.length() > 1_000_000L) continue
            } else {
                val assetLen = runCatching {
                    context.assets.open(item.asset).use { it.available().toLong() }
                }.getOrDefault(-1L)
                if (dst.exists() && assetLen > 0 && dst.length() == assetLen) continue
            }

            val tmp = File(dst.absolutePath + ".tmp")
            tmp.delete()
            runCatching {
                context.assets.open(item.asset).use { input ->
                    val stream = if (gz) GZIPInputStream(input, 1 shl 16) else input
                    tmp.outputStream().use { output -> stream.copyTo(output, 1 shl 16) }
                }
                tmp.renameTo(dst)
                dst.setExecutable(true, false)
            }.onFailure {
                tmp.delete()
            }
        }
        return out
    }
}
