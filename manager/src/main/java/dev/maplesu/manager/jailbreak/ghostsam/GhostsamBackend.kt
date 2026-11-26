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

    /** Mirrors the fail-closed admission posture expected of every provider. */
    fun admissionBlockers(ownerOnly: Boolean, arm64: Boolean, artifactDigestOk: Boolean,
                          ghostSamPrimitiveAvailable: Boolean): List<String> = buildList {
        if (!ownerOnly) add("PROVIDER_OWNER_ONLY")
        if (!arm64) add("PROVIDER_ABI_UNSUPPORTED")
        if (!artifactDigestOk) add("ARTIFACT_UNVERIFIED")
        if (!ghostSamPrimitiveAvailable) add("GHOSTSAM_PRIMITIVE_DENIED")
    }
}
