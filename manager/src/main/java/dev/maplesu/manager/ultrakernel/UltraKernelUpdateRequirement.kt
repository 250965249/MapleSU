package dev.maplesu.manager.ultrakernel

/** Retired executors are recognized only inside a completely verified installed spec. */
internal object UltraKernelUpdateRequirement {
    fun required(spec: UltraKernelSpec?, credential: UltraKernelCredential): Boolean {
        if (spec == null || !credential.sdkMetadataValid || spec.key != secretText(credential)) return false
        return spec.patches.count { patch ->
            val body = patch.replacement
            val call = when (body.size) { 140 -> 0x40; 180 -> 0x68; else -> return@count false }
            fun word(at: Int) = UltraKernelA64.le32Bits(body, at)
            word(0) == UltraKernelA64.RET &&
                word(4) and 0xffc003ff.toInt() == 0x91000231.toInt() &&
                word(8) == UltraKernelA64.stpPre(11, 17, 31, -2) &&
                word(call) == UltraKernelA64.blr(10) &&
                body.indices.step(4).count { word(it) == UltraKernelA64.blr(10) } == 1
        } == 1
    }

    fun requirePreserved(expected: UltraKernelCredential?, candidate: UltraKernelCredential?) {
        check(expected == null || expected == candidate) { "ULTRA_KERNEL_UPGRADE_IDENTITY_CHANGED" }
    }

    private fun secretText(credential: UltraKernelCredential): String {
        val bytes = credential.copySecret()
        return try { bytes.toString(Charsets.US_ASCII) } finally { bytes.fill(0) }
    }
}
