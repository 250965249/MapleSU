package dev.maplesu.manager.ultrakernel

/**
 * Places movable recipe groups without ever writing across a real function.
 *
 * Kallsyms has no function sizes. The next symbol is therefore a conservative occupied boundary.
 * Function capacity and a matching digest do not prove that a function is unused. Every movable
 * group is relocated, preserving normal and exception callers. Relocated groups use padding inside
 * `_stext.._etext` only after every destination byte is proven to be zero or an AArch64 NOP.
 */
internal object UltraKernelCaveAllocator {
    private const val MAX_BRANCH_DISTANCE = (1L shl 27) - 4L
    private const val ALIGNMENT = 4

    /** Half-open byte range. */
    data class Span(val start: Int, val end: Int) {
        init {
            require(start >= 0 && end > start) { "ULTRA_KERNEL_CAVE_SPAN_INVALID" }
        }

        fun overlaps(other: Span): Boolean = start < other.end && other.start < end
        fun contains(start: Int, end: Int): Boolean = this.start <= start && end <= this.end
    }

    data class Placement(
        val cave: String,
        val base: Int,
        val originalBase: Int?,
        val span: Span,
        val shifted: Boolean,
    ) {
        val shiftedFrom: Int? get() = if (shifted) originalBase else null
    }

    class Allocation(
        val placements: Map<String, Placement>,
        val siteByRole: Map<String, Int>,
        val symbols: UltraKernelSymbols,
    )

    /**
     * Resolve all sites and assign a destination to every movable group. [excluded] contains
     * destinations rejected by a previous assembly attempt because a branch did not encode.
     */
    fun allocate(
        recipe: UltraKernelRecipe,
        symbols: UltraKernelSymbols,
        kernel: ByteArray,
        excluded: Set<Span> = emptySet(),
        metadataDisplacement: Int? = null,
        preservedExecutor: Int? = null,
    ): Allocation {
        val originalSites = LinkedHashMap<String, Int>()
        val runtimeSites = runtimePatchSites(symbols, kernel)
        val occupied = ArrayList<Span>(runtimeSites)

        // Every original hook site remains occupied even when a different cave group moves.
        for (record in recipe.records) {
            val base = symbols.offsetOf(record.symbol) ?: continue
            val site = hookSite(record, base, symbols, kernel)
            if (record.delta >= 0 && record.length > 0 && site >= 0 &&
                site + record.length <= kernel.size
            ) {
                originalSites[record.role] = site.toInt()
                occupied += Span(site.toInt(), site.toInt() + record.length)
            }
        }

        val groups = linkedMapOf<String, MutableList<UltraKernelRecipe.Record>>()
        for (record in recipe.records) {
            record.cave?.let { cave -> groups.getOrPut(cave) { ArrayList() } += record }
        }
        for ((cave, records) in groups) {
            // Pure metadata slots may have no historical host (for example, without KVM).
            // Preserve the recipe's existing host requirements for executable code groups.
            val base = symbols.offsetOf(cave) ?: if (records.all { it.space == RECIPE_SLOT && it.constructed }) continue else {
                throw UltraKernelGenerateException(
                    UltraKernelGenerateCodes.SITE_SYMBOL_MISSING,
                    "${records.first().role}:$cave",
                )
            }
            val end = symbols.nextOffset(base)?.coerceAtMost(symbols.imageSize) ?: symbols.imageSize
            occupied += Span(base, maxOf(base + groupSpan(records, base, symbols.imageSize), end))
        }

        val executor = recipe.records.singleOrNull { it.code == "printfn-bracket" }
        val reservedExecutor = preservedExecutor?.let { start ->
            val record = requireNotNull(executor)
            val span = Span(start, start + groupSpan(groups.getValue(requireNotNull(record.cave)),
                symbols.offsetOf(record.cave), symbols.imageSize))
            val textStart = symbols.offsetOf("_stext") ?: symbols.offsetOf("_text")
            val textEnd = symbols.offsetOf("_etext")?.coerceAtMost(kernel.size)
            if (textStart == null || textEnd == null || start < textStart || span.end > textEnd ||
                start % ALIGNMENT != 0 ||
                (start until span.end step ALIGNMENT).any { !isPaddingWord(kernel, it) } ||
                symbols.hasSymbolIn(start, span.end) || runtimeReused(symbols.nameBefore(start)) ||
                (occupied + excluded).any { it.overlaps(span) }
            ) throw UltraKernelGenerateException(UltraKernelGenerateCodes.CAVE_UNAVAILABLE,
                "EXECUTOR_IDENTITY_PADDING_UNAVAILABLE")
            occupied += span
            span
        }

        val placements = LinkedHashMap<String, Placement>()
        for ((cave, records) in groups) {
            val originalBase = symbols.offsetOf(cave)
            val span = groupSpan(records, originalBase, symbols.imageSize)
            val candidate = if (cave == executor?.cave && reservedExecutor != null) {
                occupied.remove(reservedExecutor)
                reservedExecutor.start
            } else findPadding(
                kernel, symbols, span, occupied + excluded, cave, recipe.records,
                placements, originalSites,
            ) ?: throw UltraKernelGenerateException(
                UltraKernelGenerateCodes.CAVE_UNAVAILABLE,
                "$cave:need=$span:excluded=${excluded.size}",
            )
            placements[cave] = Placement(
                cave, candidate, originalBase,
                Span(candidate, candidate + span), shifted = true,
            )
            occupied += Span(candidate, candidate + span)
        }

        // An installed SDK key includes the BLR-to-metadata displacement. Move its data cave,
        // rather than re-encoding that key and selecting a different /data directory on upgrade.
        val metadata = recipe.records.singleOrNull { it.role == "free_initmem+0x0" }
        if (metadataDisplacement != null && executor != null && metadata?.cave != null) {
            val callSite = placements.getValue(requireNotNull(executor.cave)).base.toLong() +
                executor.delta + UltraKernelBodies.EXECUTOR_CALL_OFFSET
            val existingEnvelope = recipe.records.any { record ->
                val dataOffset = when (record.role) {
                    "free_initmem+0x0" -> 4
                    "__traceiter_kvm_userspace_exit+0x70" -> 0
                    else -> return@any false
                }
                val base = record.cave?.let { placements[it]?.base }
                    ?: originalSites[record.role]?.minus(record.delta) ?: return@any false
                base.toLong() + record.delta + dataOffset - callSite == metadataDisplacement.toLong()
            }
            if (!existingEnvelope) {
                val previous = placements.getValue(metadata.cave)
                val destination = callSite + metadataDisplacement - metadata.delta - 4
                val length = previous.span.end - previous.span.start
                val textStart = symbols.offsetOf("_stext") ?: symbols.offsetOf("_text")
                val textEnd = symbols.offsetOf("_etext")?.coerceAtMost(kernel.size)
                val start = destination.toInt()
                val end = destination + length
                val available = textStart != null && textEnd != null && destination >= textStart &&
                    end <= textEnd && destination % ALIGNMENT == 0L &&
                    (start until end.toInt() step ALIGNMENT).all { isPaddingWord(kernel, it) } &&
                    !symbols.hasSymbolIn(start, end.toInt()) &&
                    !runtimeReused(symbols.nameBefore(start)) &&
                    (occupied.filter { it != previous.span } + excluded)
                        .none { it.overlaps(Span(start, end.toInt())) } &&
                    branchesReach(metadata.cave, start, recipe.records, placements, originalSites)
                if (!available) {
                    if (preservedExecutor == null) {
                        val required = previous.base.toLong() + metadata.delta + 4 - metadataDisplacement -
                            executor.delta - UltraKernelBodies.EXECUTOR_CALL_OFFSET
                        if (required >= 0 && required + executor.length <= kernel.size) {
                            return allocate(recipe, symbols, kernel, excluded, metadataDisplacement, required.toInt())
                        }
                    }
                    throw UltraKernelGenerateException(UltraKernelGenerateCodes.CAVE_UNAVAILABLE,
                        "METADATA_IDENTITY_PADDING_UNAVAILABLE")
                }
                occupied.remove(previous.span)
                val span = Span(start, end.toInt())
                placements[metadata.cave] = Placement(metadata.cave, start, previous.originalBase,
                    span, shifted = true)
                occupied += span
            }
        }

        // Hook records stay inside their own function. Capacity uses the resolved instruction,
        // not a reference build's delta; movable caves never change these kernel entry points.
        val groupedRoles = groups.values.flatten().mapTo(HashSet()) { it.role }
        for (record in recipe.records) {
            if (record.role in groupedRoles) continue
            val base = symbols.offsetOf(record.symbol) ?: if (record.optional) continue else {
                throw UltraKernelGenerateException(
                    UltraKernelGenerateCodes.SITE_SYMBOL_MISSING,
                    "${record.role}:${record.symbol}",
                )
            }
            val site = originalSites[record.role]?.toLong() ?: base.toLong() + record.delta
            if (record.delta < 0 || record.length <= 0 || site < 0 ||
                site + record.length > kernel.size
            ) {
                throw UltraKernelGenerateException(
                    UltraKernelGenerateCodes.SITE,
                    "SITE_OUT_OF_IMAGE:${record.role}",
                )
            }
            if (runtimeSites.any { it.overlaps(Span(site.toInt(), site.toInt() + record.length)) }) {
                throw UltraKernelGenerateException(UltraKernelGenerateCodes.SITE,
                    "RUNTIME_PATCH_CONFLICT:${record.role}")
            }
            val next = symbols.nextOffset(base)?.coerceAtMost(kernel.size) ?: kernel.size
            if (site + record.length > next &&
                !acceptedSlot(record, kernel, symbols)
            ) {
                throw UltraKernelGenerateException(
                    UltraKernelGenerateCodes.CAVE_TOO_SMALL,
                    "${record.role}:need=${site - base + record.length}:room=${next - base}:" +
                        "next=${symbols.nameAt(next) ?: "0x${next.toString(16)}"}",
                )
            }
        }

        val sites = LinkedHashMap<String, Int>()
        for (record in recipe.records) {
            sites[record.role] = if (record.cave == null) {
                originalSites[record.role] ?: continue
            } else {
                val placement = placements.getValue(record.cave)
                val site = placement.base.toLong() + record.delta
                if (record.delta < 0 || site < 0 || site + record.length > kernel.size) {
                    throw UltraKernelGenerateException(
                        UltraKernelGenerateCodes.SITE,
                        "SITE_OUT_OF_IMAGE:${record.role}",
                    )
                }
                site.toInt()
            }
        }

        val overrides = placements.values.filter { it.shifted }.associate { it.cave to it.base }
        return Allocation(placements, sites, OverrideSymbols(symbols, overrides))
    }

    private fun hookSite(
        record: UltraKernelRecipe.Record,
        base: Int,
        symbols: UltraKernelSymbols,
        kernel: ByteArray,
    ): Long {
        // Keep PAC at its unwind address even if dynamic-SCS symbols were stripped or renamed.
        // PACIASP can also be a BTI landing pad; neither depends on a kallsyms feature marker.
        if (record.role == "do_execveat_common+0x0" && record.symbol == "do_execveat_common" &&
            record.cave == null && record.delta == 0 && record.length == 4
        ) return base + 4L
        // This role is the k22 AVC return hook, not a build-independent +0x28 offset.
        // B to its helper is a tail call: the kernel must already have restored SP, FP and LR
        // (including SCS/PAC). On framed 6.1 builds +0x28 is still in the function body.
        // Replacing an actual RET leaves the target's own prologue/epilogue intact; on the
        // reference build the first RET is still +0x28, preserving every shipped patch byte.
        if (record.role == "avc_denied+0x28" && record.symbol == "avc_denied" &&
            record.cave == null && record.length == 4
        ) {
            val end = symbols.nextOffset(base)?.coerceAtMost(kernel.size) ?: kernel.size
            for (site in base until end - 3 step ALIGNMENT) {
                if (UltraKernelA64.le32Bits(kernel, site) == UltraKernelA64.RET) return site.toLong()
            }
            throw UltraKernelGenerateException(
                UltraKernelGenerateCodes.SITE,
                "HOOK_RETURN_NOT_FOUND:${record.symbol}",
            )
        }
        return base.toLong() + record.delta
    }

    /** True when the AArch64 B/BL signed imm26 displacement can reach [target] from [source]. */
    fun withinBranchRange(source: Long, target: Long): Boolean {
        val delta = target - source
        return delta % 4L == 0L && delta >= -(1L shl 27) && delta <= MAX_BRANCH_DISTANCE
    }

    private fun groupSpan(
        records: List<UltraKernelRecipe.Record>,
        originalBase: Int?,
        imageSize: Int,
    ): Int {
        var span = 0
        for (record in records) {
            val site = (originalBase ?: 0).toLong() + record.delta
            if (record.delta < 0 || record.length <= 0 || site < 0 ||
                site + record.length > imageSize
            ) {
                throw UltraKernelGenerateException(
                    UltraKernelGenerateCodes.SITE,
                    "SITE_OUT_OF_IMAGE:${record.role}",
                )
            }
            span = maxOf(span, record.delta + record.length)
        }
        return alignUp(span)
    }

    private fun findPadding(
        kernel: ByteArray,
        symbols: UltraKernelSymbols,
        need: Int,
        occupied: List<Span>,
        cave: String,
        records: List<UltraKernelRecipe.Record>,
        placed: Map<String, Placement>,
        originalSites: Map<String, Int>,
    ): Int? {
        // _text includes the Image/PE headers and their alignment padding. Those bytes are not
        // runtime executable text even when they look like zero/NOP caves.
        val textStart = symbols.offsetOf("_stext") ?: symbols.offsetOf("_text") ?: return null
        val textEnd = symbols.offsetOf("_etext")?.coerceAtMost(kernel.size) ?: return null
        if (textStart !in 0 until textEnd || need <= 0 || need > textEnd - textStart) return null
        val first = alignUp(textStart)
        var runStart = -1
        var candidateStart = -1
        var position = first
        while (position + ALIGNMENT <= textEnd) {
            if (isPaddingWord(kernel, position)) {
                if (runStart < 0) {
                    runStart = position
                    candidateStart = position
                }
                while (candidateStart >= 0 && candidateStart + need <= position + ALIGNMENT) {
                    val candidate = Span(candidateStart, candidateStart + need)
                    val blocker = occupied.firstOrNull { it.overlaps(candidate) }
                    if (blocker != null) {
                        candidateStart = alignUp(maxOf(candidateStart + ALIGNMENT, blocker.end))
                        continue
                    }
                    if (candidate.end <= textEnd &&
                        !symbols.hasSymbolIn(candidate.start, candidate.end) &&
                        !runtimeReused(symbols.nameBefore(candidate.start)) &&
                        branchesReach(cave, candidate.start, records, placed, originalSites)
                    ) {
                        return candidate.start
                    }
                    candidateStart += ALIGNMENT
                }
            } else {
                runStart = -1
                candidateStart = -1
            }
            position += ALIGNMENT
        }
        return null
    }

    /** These instructions are rewritten after the image is loaded, even if their bytes look spare. */
    internal fun runtimePatchSites(symbols: UltraKernelSymbols, kernel: ByteArray): List<Span> {
        val result = ArrayList<Span>()
        fun table(startName: String, endName: String, stride: Int, visit: (Int) -> Unit) {
            val start = symbols.offsetOf(startName) ?: return
            val end = symbols.offsetOf(endName) ?: throw UltraKernelGenerateException(
                UltraKernelGenerateCodes.SITE, "RUNTIME_PATCH_TABLE_INVALID:$startName")
            if (start < 0 || end < start || end > kernel.size || (end - start) % stride != 0) {
                throw UltraKernelGenerateException(UltraKernelGenerateCodes.SITE,
                    "RUNTIME_PATCH_TABLE_INVALID:$startName")
            }
            for (at in start until end step stride) visit(at)
        }
        fun add(start: Long, length: Int) {
            if (length > 0 && start >= 0 && start + length <= kernel.size) {
                result += Span(start.toInt(), start.toInt() + length)
            }
        }
        for ((startName, endName) in listOf(
            "__entry_text_start" to "__entry_text_end",
            "__irqentry_text_start" to "__irqentry_text_end",
        )) {
            val start = symbols.offsetOf(startName) ?: continue
            val end = symbols.offsetOf(endName) ?: continue
            add(start.toLong(), end - start)
        }
        // arm64 jump_entry: signed PREL32 code, PREL32 target, PREL64 key.
        table("__start___jump_table", "__stop___jump_table", 16) { at ->
            add(at.toLong() + UltraKernelA64.le32Bits(kernel, at), 4)
        }
        // arm64 alt_instr: PREL32 original/replacement, u16 feature, u8 lengths.
        table("__alt_instructions", "__alt_instructions_end", 12) { at ->
            add(at.toLong() + UltraKernelA64.le32Bits(kernel, at), kernel[at + 10].toInt() and 0xff)
            // Replacement bytes can themselves be NOPs. They are copied into live code by
            // apply_alternatives, so treating the source as padding corrupts boot just as surely.
            add(at.toLong() + 4 + UltraKernelA64.le32Bits(kernel, at + 4), kernel[at + 11].toInt() and 0xff)
        }
        return result
    }

    private fun branchesReach(
        cave: String,
        candidate: Int,
        records: List<UltraKernelRecipe.Record>,
        placed: Map<String, Placement>,
        originalSites: Map<String, Int>,
    ): Boolean {
        for (sourceRecord in records) {
            val sourceBase = sourceRecord.cave?.let { placed[it]?.base }
                ?: originalSites[sourceRecord.role]
                ?: continue
            val sourceSite = if (sourceRecord.cave == cave) candidate + sourceRecord.delta
                else sourceBase + sourceRecord.delta
            for (reloc in sourceRecord.relocs) {
                if (reloc.targetSymbol != cave) continue
                val branch = reloc.kind == UltraKernelRecipe.KIND_BRANCH ||
                    (reloc.kind == UltraKernelRecipe.KIND_WORD &&
                        reloc.op == UltraKernelRecipe.OP_BRANCH)
                if (branch && !withinBranchRange(
                        (sourceSite + reloc.at).toLong(),
                        (candidate + reloc.targetDelta).toLong(),
                    )
                ) return false
            }
        }
        return true
    }

    private fun isPaddingWord(kernel: ByteArray, offset: Int): Boolean {
        if (offset < 0 || offset + 4 > kernel.size || offset % ALIGNMENT != 0) return false
        val word = UltraKernelA64.le32Bits(kernel, offset)
        return word == 0 || word == UltraKernelA64.NOP
    }

    private fun runtimeReused(symbol: String?): Boolean {
        val name = symbol ?: return false
        return name.startsWith("__init") || name.startsWith("_init") ||
            name.startsWith("__exception") || name.startsWith("__entry") || name.startsWith("__meminit")
    }

    private fun acceptedSlot(
        record: UltraKernelRecipe.Record,
        kernel: ByteArray,
        symbols: UltraKernelSymbols,
    ): Boolean {
        if (record.space != RECIPE_SLOT) return false
        val base = symbols.offsetOf(record.symbol) ?: return false
        val site = base.toLong() + record.delta
        if (site < 0 || site + record.length > kernel.size) return false
        val digest = UltraKernelRecipe.sha256Of(
            kernel.copyOfRange(site.toInt(), site.toInt() + record.length),
        )
        return digest == record.slotExpectedSha256 ||
            digest in record.slotAcceptedSha256
    }

    private fun alignUp(value: Int): Int =
        (value + ALIGNMENT - 1) and (ALIGNMENT - 1).inv()

    private class OverrideSymbols(
        private val base: UltraKernelSymbols,
        private val overrides: Map<String, Int>,
    ) : UltraKernelSymbols by base {
        override fun offsetOf(name: String): Int? = overrides[name] ?: base.offsetOf(name)
    }

    private const val RECIPE_SLOT = "slot"
}
