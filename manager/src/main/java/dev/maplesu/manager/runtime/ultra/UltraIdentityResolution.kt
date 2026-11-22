package dev.maplesu.manager.runtime.ultra

import dev.maplesu.manager.ultrakernel.UltraKernelCredential
import java.util.concurrent.CancellationException

/** A backup is only a candidate; only a live key-based uid-0 result permits persistence. */
internal object UltraIdentityResolution {
    interface Port {
        fun currentKey(): String?
        fun blocked(): Boolean
        fun bootId(): String?
        fun rootUid(key: String): Int?
        fun kernelKey(): String? = null
        fun restoreBootSession(): String? = null
        fun brokerKey(): String?
        fun backupKey(): String?
        fun installKeys(): List<String> = emptyList()
        fun imageKeys(): Sequence<String> = emptySequence()
        fun attempted(source: String, index: Int, root: Boolean) {}
        fun store(expected: String?, key: String): Boolean
        fun accepted(key: String)
    }

    fun recover(port: Port, bootSessionResult: String? = null): String {
        // Only an established temporary owner ends recovery. A failed no-key su
        // read or an expired boot record says nothing about the permanent broker.
        if (bootSessionResult == "BOOT_SDK_CURRENT" || bootSessionResult == "BOOT_SDK_RESTORED") {
            return bootSessionResult
        }
        if (port.blocked()) return "RECOVERY_SUSPENDED"
        val boot = port.bootId() ?: return "RECOVERY_BOOT_UNAVAILABLE"
        val original = port.currentKey()
        val tried = mutableSetOf<String>()
        fun changed() = Thread.currentThread().isInterrupted || port.blocked() ||
            port.bootId() != boot || port.currentKey() != original
        fun tryKey(source: String, key: String?): String? {
            if (changed()) return "RECOVERY_SCOPE_CHANGED"
            if (!valid(key) || !tried.add(requireNotNull(key))) return null
            val uid = recoveryCandidate { port.rootUid(key) }
            port.attempted(source, tried.size, uid == 0)
            if (changed()) return "RECOVERY_SCOPE_CHANGED"
            if (uid != 0) return null
            var stored = false
            UltraReinstallPairing.recover(key, rootUid = { uid },
                store = { stored = port.store(original, it) },
                refreshAuthorization = { if (stored) port.accepted(it) })
            if (!stored) return "RECOVERY_STORE_FAILED"
            return if (key == original) "RECOVERY_LOCAL_KEY_VERIFIED" else "RECOVERED"
        }
        tryKey("local", original)?.let { return it }
        // The running kernel verifies the caller's installed manager identity.
        // Its reply remains a candidate until the same live SDK proof succeeds.
        tryKey("kernel", recoveryCandidate { port.kernelKey() })?.let { return it }

        // External flashing has no manager transaction receipt. Saved image keys
        // remain candidates until the running kernel itself accepts one.
        for (key in recoveryCandidate { port.installKeys() }.orEmpty()) {
            tryKey("install", key)?.let { return it }
        }

        // A healthy current key/owner must not wait for no-key su or old recovery
        // material. A missing app boot record is not evidence that it owns the SDK.
        val restored = recoveryCandidate { port.restoreBootSession() }
        if (restored == "BOOT_SDK_CURRENT" || restored == "BOOT_SDK_RESTORED") return restored
        if (changed()) return "RECOVERY_SCOPE_CHANGED"

        // The environment-owned broker survives app data deletion and UID changes.
        // Its response still needs the same live proof as an on-disk backup.
        tryKey("broker", recoveryCandidate { port.brokerKey() })?.let { return it }
        tryKey("backup", recoveryCandidate { port.backupKey() })?.let { return it }
        try {
            for (key in port.imageKeys()) {
                tryKey("image", key)?.let { return it }
            }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            return "RECOVERY_SCOPE_CHANGED"
        } catch (_: Exception) {
            if (changed()) return "RECOVERY_SCOPE_CHANGED"
        }
        if (changed()) return "RECOVERY_SCOPE_CHANGED"
        return "RECOVERY_ROOT_NOT_VERIFIED"
    }

    fun installCandidates(pending: String?, exports: Map<String, *>): List<String> =
        installCandidates(listOfNotNull(pending), exports)

    fun installCandidates(pending: List<String>, exports: Map<String, *>): List<String> {
        val hashes = exports.keys.filter { it.matches(Regex("[0-9a-f]{64}")) }
            .sortedWith(compareByDescending<String> { (exports["at:$it"] as? Long) ?: 0L }.thenBy { it })
        return (pending + hashes.mapNotNull { exports[it] as? String })
            .filter(::valid).distinct()
    }

    private fun valid(key: String?) = key != null && UltraKernelCredential.isValid(key) &&
        UltraKernelCredential.of(key).sdkMetadataValid
}

/** Candidate I/O may fail, but cancellation ends the recovery scope. */
internal inline fun <T> recoveryCandidate(read: () -> T): T? = try {
    if (Thread.currentThread().isInterrupted) null else read()
} catch (cancelled: CancellationException) {
    throw cancelled
} catch (_: InterruptedException) {
    Thread.currentThread().interrupt()
    null
} catch (_: Exception) {
    null
}
