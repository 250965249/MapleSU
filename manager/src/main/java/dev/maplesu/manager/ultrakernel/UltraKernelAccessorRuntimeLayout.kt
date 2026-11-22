package dev.maplesu.manager.ultrakernel

/** Partial target evidence is retained for diagnosis; only complete, typed evidence may be bound. */
internal object UltraKernelAccessorRuntimeLayout {
    data class Resolution(
        val layout: UltraKernelLayout,
        val missing: Map<String, String>,
        val memberSignatures: Map<String, String> = emptyMap(),
        val source: String = "accessor:v2",
        val ownerSizes: Map<String, Int> = emptyMap(),
    )

    fun resolve(kernel: ByteArray, symbols: UltraKernelSymbols, needed: Set<String>): Resolution {
        // A malformed target BTF must remain a BTF error, not silently change evidence sources.
        require(symbols.offsetOf("__start_BTF") == null) { "ULTRA_KERNEL_ACCESSOR_BTF_PRESENT" }
        val ownerSizes = needed.map { it.substringBefore('.') }.distinct().mapNotNull { owner ->
            UltraKernelOwnerSizes.size(symbols, kernel, owner)?.let { owner to it }
        }.toMap()
        val fields = linkedMapOf<String, UltraKernelLayoutField>()
        val missing = linkedMapOf<String, String>()
        for (name in needed.sorted()) {
            val field = try {
                UltraKernelStructOffsets.runtimeAccessorField(symbols, kernel, name)
            } catch (error: UltraKernelGenerateException) {
                missing[name] = error.message ?: "STRUCT_ACCESSOR_UNRESOLVED:$name"
                continue
            }
            fields[name] = field
            if (field.ownerSizeBytes == null) missing[name] = "STRUCT_OWNER_EXTENT_UNPROVEN:${name.substringBefore('.')}"
        }
        // LDR/STR width alone proves neither typedef identity, signedness nor atomic/refcount semantics.
        return Resolution(UltraKernelLayout(fields), missing, ownerSizes = ownerSizes)
    }
}