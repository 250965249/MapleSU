package me.yuki.fina.adbroot.core

/**
 * Kernel addresses of the profile bound to this run.
 *
 * The retained flow reads these values directly, so this object keeps its
 * original shape and delegates to the bound [KernelProfile]. The compiled
 * default is PD2546 (iQOO 15 Ultra,
 * `6.12.58-android16-6-gdd6fd5c98918-abogki543627742-4k`), whose link-time
 * addresses come from `data/PD2546-symbols.json` and match its boot image one
 * to one; the running value is the static address plus the KASLR slide.
 *
 * [bind] is called once, before the flow starts, with the profile the catalog
 * resolved for the running `uname -r`. This object never resolves a release and
 * never relaxes a match: an unbound process keeps the compiled default, which
 * `RootFlow.checkKernel` still compares against the live release.
 */
object KernelMap {
    @Volatile
    private var boundProfile: KernelProfile = KernelProfiles.DEFAULT_PROFILE

    @Volatile
    private var boundRelease: String = KernelProfiles.DEFAULT_RELEASE

    /** The profile this process is using. */
    val profile: KernelProfile get() = boundProfile

    /**
     * Binds [profile] for [release]. Returns false - and changes nothing - when
     * the profile does not serve that exact release.
     */
    fun bind(profile: KernelProfile, release: String): Boolean {
        // Only the retained engine patches link-time addresses. A Shark profile
        // runs through its own runner and must never reach this table.
        if (profile.engine != KernelEngine.RETAINED) return false
        if (profile.addresses == null) return false
        if (!profile.serves(release)) return false
        boundProfile = profile
        boundRelease = release
        return true
    }

    /** Restores the compiled default; used by host tests and a fresh process. */
    fun reset() {
        boundProfile = KernelProfiles.DEFAULT_PROFILE
        boundRelease = KernelProfiles.DEFAULT_RELEASE
    }

    private fun addresses(): KernelAddresses =
        checkNotNull(boundProfile.addresses) { "profile ${boundProfile.id} has no address table" }

    val KERNEL_RELEASE: String get() = boundRelease
    val KMI: String get() = boundProfile.kmi
    val KERNEL_UAPI: Int get() = boundProfile.kernelUapi

    val IMAGE_BASE: Long get() = addresses().imageBase
    val KPROBE_TABLE: Long get() = addresses().kprobeTable
    val LOAD_MODULE: Long get() = addresses().loadModule
    val MODULE_NOTIFY_LIST: Long get() = addresses().moduleNotifyList
    val TRACE_MODULE_NOTIFY: Long get() = addresses().traceModuleNotify
    val TRACE_SYS_EXIT: Long get() = addresses().traceSysExit

    val GOLDEN = u64("61C8864680B583EB")
    val KERNEL_ADDR_MIN = u64("ffffff8000000000")

    /** kprobe_table 的桶号：标准 jhash 乘法取高位。 */
    fun bucket(loadModule: Long): Int = ((loadModule * GOLDEN) ushr 58).toInt()

    fun u64(hex: String): Long = java.lang.Long.parseUnsignedLong(hex.removePrefix("0x"), 16)

    fun parseU64(text: String): Long? = runCatching { u64(text.trim()) }.getOrNull()

    fun hex(v: Long?): String = if (v == null) "null" else "0x" + java.lang.Long.toUnsignedString(v, 16)
}
