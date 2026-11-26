package dev.maplesu.manager.jailbreak.ghostsam

/**
 * Registration metadata for the GhostSam V2 backend within the MapleSU jailbreak surface.
 *
 * IMPORTANT (scope): the concrete admission/routing wiring points
 * (`JailbreakAdmission.JailbreakMethod`, `JailbreakRequest.ROUTABLE_BACKENDS`,
 * `JailbreakController` dispatch) live OUTSIDE the t24 in-scope paths and are therefore NOT
 * modified here. This descriptor is what those points must consume; the exact proposed edit
 * anchors are recorded in the implementation report §"产品层接线".
 */
object GhostsamBackend {
    const val KEY = "ghostsam"
    const val ARTIFACT = "libmaplesu_ghostsam_consumer.so"
    val capabilities: Set<String> = setOf("RAW_ROOT_LEASE")

    /**
     * Pinned consumer digest from the packaged asset `ghostsam_consumer.sha256`.
     * Missing/garbled asset returns "" so ConsumerProvisioner fails closed (DIGEST_MISMATCH).
     */
    fun expectedConsumerSha256(context: android.content.Context): String = runCatching {
        context.assets.open("ghostsam_consumer.sha256").bufferedReader().use { it.readText().trim() }
    }.getOrElse { "" }

    data class Readiness(val artifactPresent: Boolean, val primitiveReachable: Boolean) {
        val ready: Boolean get() = artifactPresent && primitiveReachable
    }

    /** Cheap, read-only readiness for UI gating (never creates or writes anything). */
    fun readiness(context: android.content.Context): Readiness {
        val artifact = java.io.File(context.applicationInfo.nativeLibraryDir, ARTIFACT).isFile
        val primitive = java.io.File("/data/local/tmp/temp_su.sock").exists()
        return Readiness(artifact, primitive)
    }

    /**
     * Facts for the single capability gate. The lease route must NOT carry any Ultra field:
     * the gate rejects Ultra-state pollution, it does not block a normal lease. Only lease
     * facts are provided here, so the V2 success path passes the gate and RAW_ROOT_LEASE is
     * declared. Any caller that injects an activated Ultra field is still rejected.
     */
    fun ghostsamFacts(): Map<String, Any?> = mapOf(
        "jailbreakLeaseValid" to true,
        "leaseCapability" to "RAW_ROOT_LEASE",
        "r7" to "A_JAILBREAK",
    )

    /** Backward-compatible alias; also carries no Ultra fields. */
    fun ultraFacts(): Map<String, Any?> = ghostsamFacts()

    /** Mirrors the fail-closed admission posture expected of every provider. */
    fun admissionBlockers(ownerOnly: Boolean, arm64: Boolean, artifactDigestOk: Boolean,
                          ghostSamPrimitiveAvailable: Boolean): List<String> = buildList {
        if (!ownerOnly) add("PROVIDER_OWNER_ONLY")
        if (!arm64) add("PROVIDER_ABI_UNSUPPORTED")
        if (!artifactDigestOk) add("ARTIFACT_UNVERIFIED")
        if (!ghostSamPrimitiveAvailable) add("GHOSTSAM_PRIMITIVE_DENIED")
    }
}
