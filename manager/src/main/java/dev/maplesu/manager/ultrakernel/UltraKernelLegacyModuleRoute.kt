package dev.maplesu.manager.ultrakernel

/** Target config and executable CFI identities decide the route, never a release/device list. */
internal object UltraKernelLegacyModuleRoute {
    fun required(kernel: ByteArray): Boolean {
        val symbols = UltraKernelKallsymsTable.decode(kernel)
        val checker = symbols.offsetsOf("__cfi_check").distinct()
        val slowpaths = listOf("__cfi_slowpath", "__cfi_slowpath_diag").flatMap {
            symbols.offsetsOf(it) + symbols.offsetsOf("$it.cfi_jt")
        }
        if (checker.isEmpty() && slowpaths.isEmpty()) return false
        check(checker.size == 1 && slowpaths.isNotEmpty()) { "ULTRA_KERNEL_LEGACY_CFI_IDENTITY" }
        val config = UltraKernelResidentAbi.targetConfig(kernel)
        check(config["CONFIG_CFI"] == "y" || config["CONFIG_CFI_CLANG"] == "y") {
            "ULTRA_KERNEL_LEGACY_CFI_CONFIG"
        }
        return true
    }
}
