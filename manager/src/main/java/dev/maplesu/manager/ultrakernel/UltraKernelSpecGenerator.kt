package dev.maplesu.manager.ultrakernel

import java.io.File

/**
 * On-device Ultra spec *generation*: turn "a boot image plus a 48 byte device credential" into a
 * [UltraKernelPlan] when the release catalogue has no shipped asset for that kernel.
 *
 * Why this exists. The catalogue ships one reviewed spec per release, and every one of them has a
 * single device's secret baked into three records. A kernel build that nobody has published an
 * asset for used to be a dead end (`ULTRA_KERNEL_RELEASE_UNSUPPORTED`). The recipe makes that dead end
 * removable without pretending the result is verified:
 *
 *  1. every record site is a `(symbol, delta)` pair, resolved on this kernel's own `kallsyms`;
 *  2. every address inside a blob is a relocation, recomputed for this kernel;
 *  3. the credential is written into the declared slots, so the same recipe fits any device;
 *  4. the digests the builder will later demand are *derived* here, never pinned.
 *
 * The output is always [UltraKernelPlan.Origin.GENERATED], which means
 * [UltraKernelPlan.SupportLevel.EXPERIMENTAL] - no observation made locally can change that. What is
 * reported next to it is [UltraKernelPlan.SiteEvidence]: how many of the recipe's sites still carried
 * the reference build's pristine bytes. `18/18` on 6.6.89 is what "identical to k22" means; `3/18`
 * on 6.1.25 means the addresses were relocated onto a kernel whose instruction sequences differ,
 * which is no longer reported as an experimental plan at all: [requireFullSiteCoverage] refuses it
 * (`ULTRA_KERNEL_GENERATE_SITE_COVERAGE`) before a plan exists, because a patch set whose code bodies
 * were compiled for another kernel is a half-finished candidate, not a weak one.
 *
 * Nothing here opens a partition, starts a process, or reads the credential store.
 */
internal class UltraKernelSpecGenerator(
    private val recipe: UltraKernelRecipe = UltraKernelRecipe.k22(),
    private val vivoVrFilter: Boolean = false,
    private val managerClaimAssets: UltraKernelAssetSource? = null,
    private val deploymentNamespace: UltraKernelDeploymentNamespace? = null,
) {

    /** Recipe identity, for receipts and diagnostics. */
    val recipeId: String get() = recipe.id

    private val newDeploymentNamespace by lazy { UltraKernelDeploymentNamespace.create() }

    /** Generate a plan from a boot image (decoded here exactly the way the builder decodes it). */
    fun generate(boot: File, credential: UltraKernelCredential): UltraKernelPlan {
        if (!boot.isFile || boot.length() == 0L) {
            throw UltraKernelGenerateException(UltraKernelGenerateCodes.BASE, "missing")
        }
        return generate(UltraKernelPlan.readKernel(boot), credential)
    }

    /**
     * Generate a plan for an already-decoded raw kernel.
     *
     * @throws UltraKernelGenerateException `ULTRA_KERNEL_GENERATE_KALLSYMS` when the kernel's symbol
     *         table cannot be walked, `..._SITE_SYMBOL_MISSING` / `..._TARGET_SYMBOL_MISSING` when a
     *         symbol this recipe needs is gone, `..._RESIDUE` when a rendered address was left
     *         frozen, `..._SITE_COVERAGE` when fewer than all sites carry the reference build's
     *         pristine bytes, `..._CAVE_TOO_SMALL` / `..._CAVE_UNAVAILABLE` when a movable group
     *         has no proven executable padding, and `..._APPLY` when the records do not fit the
     *         kernel they were rendered for.
     */
    fun generate(kernel: ByteArray, credential: UltraKernelCredential): UltraKernelPlan {
        if (kernel.isEmpty()) throw UltraKernelGenerateException(UltraKernelGenerateCodes.BASE, "empty")
        require(deploymentNamespace == null || managerClaimAssets != null) { "ULTRA_KERNEL_DEPLOYMENT_SUPPORT_MISSING" }
        val release = UltraKernelSpec.releaseOf(kernel)
        if (release.isEmpty() || release == RELEASE_AMBIGUOUS) {
            throw UltraKernelGenerateException(
                UltraKernelGenerateCodes.BASE,
                "release=${release.ifEmpty { "unreadable" }}",
            )
        }
        // Generation is decided by this target's symbols, field semantics and instruction sites.
        // The release catalogue's series list does not establish any of those facts.
        val profileSymbols = UltraKernelKallsymsTable.decode(kernel)
        val symbols = UltraKernelExecveEntry.resolve(profileSymbols, kernel)
        val rendered = recipe.renderDetailed(symbols, kernel, credential,
            preservedMetadataDisplacement = credential.metadataDisplacement.takeIf { credential.sdkMetadataValid })
        // Fail closed *before* anything is offered to the builder: a frozen address renders to
        // bytes that are correct on the reference kernel only, so no later check could catch it.
        val residue = recipe.residue(symbols, rendered.records)
        if (residue.isNotEmpty()) {
            throw UltraKernelGenerateException(
                UltraKernelGenerateCodes.RESIDUE,
                residue.joinToString(" | "),
            )
        }
        val match = recipe.generatedCoverage(rendered.records)
        // The pristine-byte match is recorded, not gated: on 6.1.25 it is `3/18` and that is the
        // expected result once the bodies are generated here, not a defect.
        val reference = recipe.siteMatch(rendered.records)
        val evidence = UltraKernelPlan.SiteEvidence(
            matching = match.matching,
            total = match.total,
            differingRoles = match.differingRoles,
            residue = residue,
            referenceOrigMatch = "${reference.matching}/${reference.total}",
            skippedRoles = rendered.skipped,
        )
        // Refuse a plan that still carries reference machine code for any record (see SITE_COVERAGE).
        requireFullSiteCoverage(evidence)
        val records = rendered.records.map { item ->
            UltraKernelPlan.PatchRecord(
                role = item.role,
                offset = item.site.toLong(),
                original = item.original,
                replacement = item.replacement,
                cave = item.cave,
                caveBase = item.cave?.let { rendered.placements[it]?.base?.toLong() },
                caveOffset = item.caveOffset,
                shiftedFrom = item.shiftedFrom?.toLong(),
            )
        }
        val filteredRecords = if (vivoVrFilter) records + UltraKernelVivoFilter.records(kernel, records) else records
        val allRecords = managerClaimAssets?.let { source ->
            val payload = UltraKernelManagerClaimPayload.load(source, release)
            UltraKernelManagerClaimCarrier.connect(kernel, symbols, filteredRecords, payload,
                if (payload.deploymentBootEntryOffset == null) {
                    require(deploymentNamespace == null) { "ULTRA_KERNEL_DEPLOYMENT_SUPPORT_MISSING" }
                    null
                } else deploymentNamespace ?: newDeploymentNamespace, profileSymbols)
        } ?: filteredRecords
        val metadata = records.single { it.role == "free_initmem+0x0" }
        val executor = records.single { it.role == "__drm_printfn_coredump+0x0" }
        // SDK locator uses LR - 4 + parser_root_key_info(key). Find the actual BLR,
        // after cave placement; symbol offsets or an arbitrary 48-byte key are insufficient.
        val call = executor.replacement.indices.step(4).single { at ->
            UltraKernelA64.le32Bits(executor.replacement, at) == UltraKernelA64.blr(10)
        }
        val callSite = executor.offset + call
        val existingDelta = credential.metadataDisplacement
        val existingEnvelope = records.firstOrNull { record ->
            val dataOffset = when (record.role) {
                "free_initmem+0x0" -> 4
                "__traceiter_kvm_userspace_exit+0x70" -> 0
                else -> return@firstOrNull false
            }
            record.offset + dataOffset - callSite == existingDelta?.toLong()
        }
        // The reference key already addresses the duplicate traceiter envelope. Keep a working
        // key byte for byte; arbitrary device keys bind to free_initmem's final placement.
        val metadataDelta = if (existingEnvelope != null ||
            rendered.records.any { it.record.code == "metadata-rebase" }
        ) requireNotNull(existingDelta) else Math.toIntExact(metadata.offset + 4 - callSite)
        val plan = UltraKernelPlan.fromRecords(
            kernelRelease = release,
            records = allRecords,
            credential = credential,
            origin = UltraKernelPlan.Origin.GENERATED,
            evidence = evidence,
            baseKernelSha256 = sha256Hex(kernel),
            sdkMetadataDisplacement = metadataDelta,
            layout = rendered.layout,
        ).rebind(credential)
        val applied = try {
            plan.apply(kernel)
        } catch (error: IllegalStateException) {
            throw UltraKernelGenerateException(
                UltraKernelGenerateCodes.APPLY,
                error.message ?: error.javaClass.simpleName,
            )
        }
        return plan.withDerived(applied.derived)
    }

    private companion object {
        /** `KernelIdentity.AMBIGUOUS`; inlined to keep this class free of an extra dependency. */
        const val RELEASE_AMBIGUOUS = "AMBIGUOUS"
    }
}

/**
 * Refuse a plan in which some record's replacement was not generated for this kernel.
 *
 * Before the code bodies were generated, this gate compared each site's *pristine* bytes with the
 * reference build's and refused anything short of `18/18` - the right call while the nine shellcode
 * blobs were that build's compilation product, because a differing site proved the bytes about to be
 * written had never been compiled for this kernel.
 *
 * Now every record's replacement is assembled here from the target kernel's own symbol offsets,
 * lengths and `task_struct` field offsets, so the invariant that matters is different and stronger:
 * a record whose replacement is still carried machine code is a foreign blob, and there must be
 * none. `matching != total` therefore means "a record would ship someone else's machine code", not
 * "the addresses moved".
 *
 * `total == 0` is refused as well: a plan with no record is not a plan.
 *
 * @throws UltraKernelGenerateException `ULTRA_KERNEL_GENERATE_SITE_COVERAGE` with
 *         `detail = "<matching>/<total> differing=<roles>"` (no credential, no kernel bytes).
 */
internal fun requireFullSiteCoverage(evidence: UltraKernelPlan.SiteEvidence) {
    if (evidence.total > 0 && evidence.matching == evidence.total) return
    val differing = evidence.differingRoles.joinToString(",")
    throw UltraKernelGenerateException(
        UltraKernelGenerateCodes.SITE_COVERAGE,
        buildString {
            append(evidence.matching).append('/').append(evidence.total)
            if (differing.isNotEmpty()) append(" differing=").append(differing)
        },
    )
}

/**
 * A [UltraKernelPatchAsset] backed by a locally generated plan instead of a shipped spec file.
 *
 * This is the seam that lets a generated plan go through the *unchanged* builder chain: the
 * builder only ever asks an asset for a spec reload and for the digests it must reproduce, and both
 * answers are derivable from the plan. Two things are deliberately left empty:
 *
 *  - [specAsset] - there is no asset file; the spec text is produced by
 *    [UltraKernelPlan.specText] and never written into `assets/`;
 *  - [knownBaseImageSha256] / [knownBaseImageBootSha256] - there is no device-proven stock image
 *    for a generated plan, so the builder's "known image" gate stays off. That is correct: it must
 *    not be able to claim a pinned-output match it does not have. Every other gate - the 18 record
 *    originals, the recomputed kernel digest, the changed-byte count, the container rebuild and the
 *    read-back kernel/boot digests - still runs and still fails closed.
 */
internal class UltraKernelGeneratedAsset private constructor(
    val plan: UltraKernelPlan,
    private val imageSizeBytesValue: Long,
    private val ramdiskSizeValue: Long,
    private val specDigest: String,
) : UltraKernelPatchAsset {

    override val id: String = "generated-" + plan.kernelRelease.map { character ->
        if (character.isLetterOrDigit() || character == '.' || character == '-' || character == '_') {
            character
        } else {
            '-'
        }
    }.joinToString("").take(48)

    override val label: String = "现场生成 · ${plan.kernelRelease}"
    override val summary: String = buildString {
        append("本机由 recipe ${plan.records.size} 条记录生成，未上机验证")
        plan.evidence?.let { append("（站点 ${it.summary}）") }
    }
    override val status: String = STATUS
    override val ready: Boolean = true
    override val debugOnly: Boolean = false
    override val debugReason: String = ""

    override val specAsset: String = ""
    override val specSha256: String = specDigest
    override val patches: Int = plan.records.size
    override val kernelRelease: String = plan.kernelRelease

    override val baseKernelSha256: String = plan.baseKernelSha256

    /** Derived, not pinned: the digest of the kernel those very records produce from that base. */
    override val expectedKernelSha256: String = plan.derived?.patchedKernelSha256
        ?: throw UltraKernelGenerateException(
            UltraKernelGenerateCodes.APPLY,
            "plan-not-applied:${plan.kernelRelease}",
        )

    override val knownBaseImageSha256: String = ""
    override val knownBaseImageBootSha256: String = ""
    override val imageSizeBytes: Long = imageSizeBytesValue
    override val ramdiskSize: Long = ramdiskSizeValue
    override val source: String = SOURCE
    override val verification: String = UltraKernelPatchAsset.VERIFICATION_EXPERIMENTAL
    override val generated: UltraKernelPlan.Derived? = plan.derived

    companion object {
        const val STATUS = "generated"

        /**
         * `source` for a generated plan. Deliberately not [UltraKernelPatchAsset.SOURCE_SAMPLE]: a
         * generated asset is not derived from a real boot image, and the receipt has to say so.
         */
        const val SOURCE = "generated"

        /**
         * @throws UltraKernelGenerateException `ULTRA_KERNEL_GENERATE_APPLY` when [plan] was never
         *         applied - an un-applied plan has no digest to demand, and a build that demanded
         *         nothing would be the silent downgrade this path exists to prevent.
         */
        fun of(
            plan: UltraKernelPlan,
            imageSizeBytes: Long,
            ramdiskSize: Long,
            specText: String,
        ): UltraKernelGeneratedAsset {
            if (plan.derived == null) {
                throw UltraKernelGenerateException(
                    UltraKernelGenerateCodes.APPLY,
                    "plan-not-applied:${plan.kernelRelease}",
                )
            }
            return UltraKernelGeneratedAsset(
                plan = plan,
                imageSizeBytesValue = imageSizeBytes,
                ramdiskSizeValue = ramdiskSize,
                specDigest = sha256Hex(specText.toByteArray(Charsets.UTF_8)),
            )
        }
    }
}
