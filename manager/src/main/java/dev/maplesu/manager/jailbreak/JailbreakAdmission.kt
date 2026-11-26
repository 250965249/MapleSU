package dev.maplesu.manager.jailbreak

import android.content.Context
import me.yuki.fina.adbroot.core.KernelCatalog
import me.yuki.fina.adbroot.core.KernelProfiles
import me.yuki.fina.adbroot.core.KernelResolution
import me.yuki.fina.adbroot.core.Payload
import java.io.IOException

enum class JailbreakMethod(val wireName: String) {
    GHOSTLOCK("ghostlock"), DIRTYFRAG("dirtyfrag"), MAPLESU_93260("maplesu_93260"), GHOSTSAM("ghostsam")
}

data class JailbreakTarget(
    val androidRelease: String,
    val sdk: Int,
    val kernelRelease: String,
    val abi: String,
    val manufacturer: String,
    val soc: String,
    val fingerprint: String,
    val bootId: String,
    val selinuxState: String,
    val securityPatch: String = "",
    /** Commercial model name, observations only (never part of a profile match). */
    val model: String = "",
    /** Build device codename, observations only. */
    val device: String = "",
)

/** Reasons an attempt cannot start. Each maps to a condition that is actually observed. */
enum class JailbreakBlocker {
    TARGET_IDENTITY_MISSING,
    ABI_UNSUPPORTED,
    EXACT_KMI_UNSUPPORTED,
    GHOSTLOCK_EXACT_PROFILE_MISSING,
    ARTIFACT_UNVERIFIED,
    /** A KMI-compatible kernel whose exact build was never measured. */
    TARGET_NOT_VERIFIED,
    SECONDARY_USER_UNSUPPORTED,
    /** This exact build is not in the 98260 catalog at all. */
    MAPLESU_93260_KERNEL_UNSUPPORTED,
    /** The build's 98260 variant is known, but its payload is not packaged. */
    MAPLESU_93260_PROFILE_NOT_PACKAGED,
}

/**
 * Admission for one attempt. It reports observed facts only: a missing exact
 * profile stays missing, an unmeasured build stays unverified, and an unsupported
 * kernel release stays unsupported. Nothing here marks the device supported,
 * installed or rooted.
 */
data class JailbreakAssessment(
    val method: JailbreakMethod,
    val sourceCommit: String,
    val blockers: List<JailbreakBlocker>,
    val notes: List<String>,
    val kmi: String? = null,
    val profileKey: String? = null,
    /** The escalation variant the catalog recognised, packaged or not. */
    val methodLabel: String? = null,
    /**
     * Things the attempt can run into but must not be silently disabled for: an
     * unmeasured firmware, a missing exact profile or an unproven KMI family. The
     * provider decides at run time and fails with its own name; the UI only warns.
     */
    val warnings: List<JailbreakBlocker> = emptyList(),
) {
    val canStart: Boolean get() = blockers.isEmpty()
}

object JailbreakAdmission {
    const val GHOSTLOCK_COMMIT = "b67359641c8663e5184abba73ecdf2c456dce3e7"
    const val DIRTYFRAG_COMMIT = "ccd61e7c516df1469d335e41638e881328136dbc"
    // GhostSam provider (MapleSU-side V2 adapter). Local source label, not an upstream pin.
    const val GHOSTSAM_COMMIT = "ghostsam-v2-local"

    fun assess(
        method: JailbreakMethod,
        target: JailbreakTarget,
        ghostlockReleases: Set<String> = emptySet(),
        verifiedTarget: Boolean = false,
        kmiPackaged: Boolean = false,
        maplesu93260Catalog: KernelCatalog = KernelCatalog.builtIn(),
    ): JailbreakAssessment {
        val blockers = mutableListOf<JailbreakBlocker>()
        val warnings = mutableListOf<JailbreakBlocker>()
        // The SELinux state is an observation, not part of exact-target identity:
        // an ordinary App is not allowed to read selinuxfs on this platform, and
        // its absence must not read as a target mismatch.
        val identity = listOf(target.kernelRelease, target.abi, target.bootId) +
            if (method == JailbreakMethod.GHOSTLOCK || method == JailbreakMethod.GHOSTSAM) listOf(target.androidRelease,
                target.manufacturer, target.soc, target.fingerprint) else emptyList()
        /*
         * Only the owner may start a provider. The executor refused this late; the UI
         * must say so before the button looks ready.
         */
        // myUid() is unavailable on the JVM host, where this must stay a no-op.
        runCatching { android.os.Process.myUid() }.getOrNull()?.let { uid ->
            if (uid / 100_000 != 0) blockers += JailbreakBlocker.SECONDARY_USER_UNSUPPORTED
        }
        if (target.sdk <= 0 || identity.any { value ->
                value.isBlank() || value.trim().equals("unknown", ignoreCase = true) ||
                    value.trim().equals("null", ignoreCase = true)
            }) {
            blockers += JailbreakBlocker.TARGET_IDENTITY_MISSING
        }
        if (target.abi != "arm64-v8a") blockers += JailbreakBlocker.ABI_UNSUPPORTED
        var kmi: String? = null
        var profileKey: String? = null
        var methodLabel: String? = null
        val notes = mutableListOf<String>()
        when (method) {
            JailbreakMethod.MAPLESU_93260 -> {
                /*
                 * Only an exact `uname -r` served by a packaged profile may start.
                 * A build whose 98260 variant is known from the catalog is named and
                 * refused with its own blocker: the flow patches build-specific
                 * addresses, so "same KMI family" is not evidence it can run.
                 */
                val resolution = KernelProfiles.resolve(target.kernelRelease, maplesu93260Catalog)
                methodLabel = resolution.variant
                kmi = when (resolution) {
                    is KernelResolution.Packaged -> resolution.profile.kmi
                    is KernelResolution.Declared -> resolution.entry.kmi ?: resolution.release.kmi
                    is KernelResolution.Unsupported -> resolution.release.kmi
                }
                when (resolution) {
                    is KernelResolution.Packaged -> {
                        profileKey = resolution.profile.id
                        notes += "profile:" + resolution.profile.id
                        notes += "variant:" + resolution.profile.variant
                    }
                    is KernelResolution.Declared -> {
                        blockers += JailbreakBlocker.MAPLESU_93260_PROFILE_NOT_PACKAGED
                        notes += "declared:" + resolution.entry.variant
                    }
                    is KernelResolution.Unsupported ->
                        blockers += JailbreakBlocker.MAPLESU_93260_KERNEL_UNSUPPORTED
                }
                notes += "source:3.8.10"
            }
            JailbreakMethod.GHOSTLOCK -> {
                // The pinned profile set is release-exact. The product carries the
                // set and resolves this release; a release outside it fails here
                // with its own name instead of a blanket "not integrated" block.
                if (target.kernelRelease in ghostlockReleases) {
                    profileKey = target.kernelRelease
                    notes += "profile-packaged"
                } else {
                    // Warn, do not disable: the provider may still be attempted on this
                    // firmware and reports its own outcome.
                    warnings += JailbreakBlocker.GHOSTLOCK_EXACT_PROFILE_MISSING
                    notes += "profile-missing:" + target.kernelRelease
                }
            }
            JailbreakMethod.GHOSTSAM -> {
                // Same admission surface as other providers: target identity above,
                // artifact presence in verifyArtifacts(), capability gate in the adapter.
                notes += "provider:ghostsam"
                notes += "capability:RAW_ROOT_LEASE"
            }
            JailbreakMethod.DIRTYFRAG -> {
                kmi = try {
                    DirtyfragAttempt.exactKmi(target.kernelRelease)
                } catch (error: IOException) {
                    warnings += JailbreakBlocker.EXACT_KMI_UNSUPPORTED
                    null
                }
                // A KMI family is a build candidate, not a measured target.
                if (kmi != null && !verifiedTarget) warnings += JailbreakBlocker.TARGET_NOT_VERIFIED
                if (kmi == null && !kmiPackaged) warnings += JailbreakBlocker.EXACT_KMI_UNSUPPORTED
                // Distribution gate, not a runtime gate: still unresolved for the
                // fork's own additions and the committed prebuilt module.
                notes += "license-unresolved"
            }
        }
        if (target.sdk > 0 && target.bootId.isBlank())
            blockers += JailbreakBlocker.TARGET_IDENTITY_MISSING
        val commit = when (method) {
            JailbreakMethod.MAPLESU_93260 -> "source-package-3.8.10"
            JailbreakMethod.GHOSTLOCK -> GHOSTLOCK_COMMIT
            JailbreakMethod.DIRTYFRAG -> DIRTYFRAG_COMMIT
            JailbreakMethod.GHOSTSAM -> GHOSTSAM_COMMIT
        }
        return JailbreakAssessment(
            method = method,
            sourceCommit = commit,
            blockers = blockers.distinct(),
            notes = notes.toList(),
            kmi = kmi,
            profileKey = profileKey,
            methodLabel = methodLabel,
            warnings = warnings.distinct(),
        )
    }

    /**
     * Device-aware admission used by the real UI and by the final executor path.
     *
     * S01 (review 2026-10-26): the UI called the fact-free overload, so both
     * providers were blocked by default even on a matching target. The facts now
     * come from the packaged resources and the measured target table - the same
     * sources the executor uses - instead of from the caller's convenience
     * parameters.
     */
    fun assess(context: Context, method: JailbreakMethod, target: JailbreakTarget): JailbreakAssessment {
        /*
         * The exact-profile fact is "this release is servable": either the packaged
         * manifest carries it or the user confirmed an imported document for it.
         * Both are exact `uname -r` matches; nothing here matches a KMI family.
         */
        val releases = ghostlockReleases(context) + importedGhostlockReleases(context)
        val kmiPackaged = runCatching { DirtyfragAttempt.exactKmi(target.kernelRelease) }.isSuccess
        val verified = JailbreakTargets.verdict(JailbreakTargets.PROVIDER_DIRTYFRAG,
            target.kernelRelease, target.fingerprint, target.soc, target.securityPatch,
            kmiPackaged) == JailbreakTargets.Verdict.VERIFIED_TARGET
        return assess(method, target, releases, verified, kmiPackaged,
            maplesu93260Catalog(context))
    }

    /**
     * The packaged 98260 catalog, or the compiled default when the manifest is
     * unreadable. A missing asset must never turn a working device into an
     * unsupported one; the payload digests are still checked by
     * [verifyArtifacts] before the attempt starts.
     */
    private fun maplesu93260Catalog(context: Context): KernelCatalog = runCatching {
        Payload.catalog(context)
    }.getOrElse { KernelCatalog.builtIn() }

    /** Packaged-artifact identity check; IO. Returns a blocker when the APK does not carry the entries. */
    fun verifyArtifacts(context: Context, method: JailbreakMethod): JailbreakBlocker? {
        val names = when (method) {
            JailbreakMethod.MAPLESU_93260 -> listOf("libmaplesu_dirtyfrag_bootstrap.so")
            JailbreakMethod.GHOSTLOCK -> listOf("libmaplesu_ghostlock_provider.so",
                "libmaplesu_root_consumer.so")
            JailbreakMethod.DIRTYFRAG -> listOf("libdfroot.so",
                "libmaplesu_dirtyfrag_bootstrap.so", "libmaplesu_root_consumer.so")
            JailbreakMethod.GHOSTSAM -> listOf("libmaplesu_ghostsam_consumer.so")
        }
        return try {
            names.forEach { JailbreakArtifacts.require(context, it) }
            if (method == JailbreakMethod.MAPLESU_93260) Payload.verify(context)
            null
        } catch (_: IOException) {
            JailbreakBlocker.ARTIFACT_UNVERIFIED
        }
    }

    /** Releases this build can serve for Ghostlock, read from the packaged manifest. */
    fun ghostlockReleases(context: Context): Set<String> = try {
        GhostlockProfiles.from(context).releases().toSet()
    } catch (_: IOException) {
        emptySet()
    }

    /**
     * Releases served by a confirmed imported profile (OTA/image parse or
     * `offsets.conf` import). The store is fail-closed: an unreadable or
     * corrupted file contributes nothing.
     */
    fun importedGhostlockReleases(context: Context): Set<String> = runCatching {
        dev.maplesu.ghostlock.extract.GhostlockProfileStore
            .openIn(context.filesDir).confirmedReleases()
    }.getOrElse { emptySet() }
}
