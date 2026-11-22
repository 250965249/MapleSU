package me.yuki.fina.adbroot.core

/**
 * PD2546（iQOO 15 Ultra，6.12.58-android16-6-gdd6fd5c98918-abogki543627742-4k）的链接期地址。
 *
 * 全部来自 data/PD2546-symbols.json（与 boot.img 里的 Image 一一对应），
 * 运行时真正要用的地址 = 这里的值 + KASLR slide。
 */
object KernelMap {

    const val KMI = "android16-6.12"
    const val KERNEL_UAPI = 6
    const val KERNEL_RELEASE = "6.12.58-android16-6-gdd6fd5c98918-abogki543627742-4k"

    val IMAGE_BASE = u64("ffffffc080000000")
    val KPROBE_TABLE = u64("ffffffc08279f6e8")
    val LOAD_MODULE = u64("ffffffc080502688")
    val MODULE_NOTIFY_LIST = u64("ffffffc0825d7d28")
    val TRACE_MODULE_NOTIFY = u64("ffffffc08057d2a4")
    val TRACE_SYS_EXIT = u64("ffffffc0826d93e0")
    val GOLDEN = u64("61C8864680B583EB")
    val KERNEL_ADDR_MIN = u64("ffffff8000000000")

    /** kprobe_table 的桶号：标准 jhash 乘法取高位。 */
    fun bucket(loadModule: Long): Int = ((loadModule * GOLDEN) ushr 58).toInt()

    fun u64(hex: String): Long = java.lang.Long.parseUnsignedLong(hex.removePrefix("0x"), 16)

    fun parseU64(text: String): Long? = runCatching { u64(text.trim()) }.getOrNull()

    fun hex(v: Long?): String = if (v == null) "null" else "0x" + java.lang.Long.toUnsignedString(v, 16)
}
