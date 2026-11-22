package dev.maplesu.manager.runtime

import android.content.Context
import dev.maplesu.manager.runtime.authorization.AndroidApplicationIdentities
import dev.maplesu.manager.runtime.authorization.AuthorizationSnapshot
import dev.maplesu.manager.runtime.authorization.ManagerSuperuserPolicy
import dev.maplesu.manager.runtime.authorization.SuperuserControl
import dev.maplesu.manager.runtime.authorization.SuperuserWire

/** A denial prefilter; the central authority still approves every endpoint handover. */
internal object NativeSuAdmission {
    @Volatile private var candidates = emptySet<Int>()

    fun accept(snapshot: AuthorizationSnapshot?) {
        // A transient read failure is not a revocation. The authority is checked
        // again before every handover; keeping this hint permits that retry.
        if (snapshot == null) return
        candidates = if (snapshot.corrupt || !snapshot.enabled) emptySet()
            else snapshot.grants.keys.filterTo(HashSet()) { !snapshot.revoked(it) }
    }

    fun update(context: Context, snapshot: AuthorizationSnapshot?) {
        accept(snapshot)
        runCatching {
            if (android.app.Application.getProcessName() != context.packageName + ":root_directory") {
                com.maplesu.core.ui.util.ProviderCall.call(context.contentResolver,
                    android.net.Uri.parse("content://" + NativeSuDirectoryProvider.AUTHORITY),
                    "refreshSuDiscovery", null, android.os.Bundle().apply {
                        putString("snapshot", snapshot?.let(SuperuserWire::encode))
                    })
            }
        }
    }

    /** Every unlisted caller takes the same in-memory path, with no Root/PM/file I/O. */
    fun eligible(caller: Int): Boolean = caller in candidates

    fun authorized(context: Context, caller: Int): Boolean = runCatching {
        val snapshot = SuperuserControl.snapshot(context) ?: return@runCatching false
        allowed(context, caller, snapshot)
    }.getOrDefault(false)

    private fun allowed(context: Context, caller: Int, snapshot: AuthorizationSnapshot): Boolean {
        val packages = context.packageManager.getPackagesForUid(caller)?.toList() ?: return false
        val identity = AndroidApplicationIdentities(context).read(caller)
        return ManagerSuperuserPolicy.decide(snapshot, caller, identity, packages).allowed
    }
}

/** Caller UID is captured by the Binder adapter, never accepted from the request. */
internal fun <T> discoverNativeSuEndpoint(
    caller: Int, manager: Int, eligible: () -> Boolean,
    authorized: () -> Boolean, endpoint: () -> T?,
): T? {
    if (caller != manager && (!eligible() || !authorized())) return null
    return endpoint()
}
