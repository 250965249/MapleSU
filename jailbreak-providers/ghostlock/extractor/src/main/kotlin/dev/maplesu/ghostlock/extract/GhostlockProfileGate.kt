package dev.maplesu.ghostlock.extract

/**
 * The one availability decision for Ghostlock on this device.
 *
 * The rule the product ships:
 *
 * 1. the packaged upstream support list carries this exact `uname -r` -> offer;
 * 2. otherwise a **confirmed** imported document whose `release` is exactly this
 *    `uname -r` -> offer (this is what a successful OTA/image parse produces);
 * 3. otherwise refuse, with a reason the UI turns into one human sentence.
 *
 * Exact string equality in both cases. There is no prefix, KMI-family,
 * case-insensitive or "close enough" match: a profile measured on a nearby build
 * belongs to a different kernel. A list that cannot be read, a store that cannot
 * be parsed and an empty release all refuse.
 */
object GhostlockProfileGate {
    sealed interface Decision {
        /** The packaged list carries this release. */
        data object Packaged : Decision

        /** A confirmed imported document carries this exact release. */
        data class Imported(val name: String) : Decision

        /** Refused. [detail] is diagnostics, never user copy. */
        data class Unsupported(val reason: Reason, val detail: String = "") : Decision
    }

    enum class Reason {
        /** The measured release is empty; there is nothing to match. */
        KERNEL_UNKNOWN,

        /** No packaged list at all (asset absent or unreadable). */
        LIST_MISSING,

        /** A usable list and no matching profile anywhere. */
        NOT_LISTED,
    }

    fun decide(
        release: String,
        packagedSupported: Boolean,
        store: GhostlockProfileStore? = null,
        packagedListUsable: Boolean = true,
    ): Decision {
        if (release.isBlank()) return Decision.Unsupported(Reason.KERNEL_UNKNOWN)
        if (packagedSupported) return Decision.Packaged
        val imported = store?.confirmedFor(release)
        if (imported != null) return Decision.Imported(imported.name)
        if (!packagedListUsable) return Decision.Unsupported(Reason.LIST_MISSING)
        return Decision.Unsupported(Reason.NOT_LISTED, release)
    }

    /** True when [decision] allows an attempt. */
    fun isOffered(decision: Decision): Boolean =
        decision is Decision.Packaged || decision is Decision.Imported

    /**
     * The paste/parse affordance is shown exactly when no profile matches, and
     * never when the packaged list or a confirmed import already covers this
     * kernel. Keeping this here (not in Compose) makes the rule testable.
     */
    fun offersParser(decision: Decision): Boolean = !isOffered(decision)
}
