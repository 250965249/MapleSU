package com.maplesu.core.data.repository

import dev.maplesu.manager.runtime.authorization.ApplicationIdentity
import dev.maplesu.manager.runtime.authorization.AuthorizationSnapshot

/** One read-only authority revision per Hook page, not a time-limited lookup per row. */
internal class HookAppListSnapshot private constructor(
    private val authority: AuthorizationSnapshot,
    private val identities: Map<Int, ApplicationIdentity?>,
) {
    val pendingApply: Boolean get() = authority.pendingApply()

    // Keep a stored grant visible while the master switch is off. Execution still uses
    // ManagerSuperuserPolicy, including its switch, tombstone and live identity checks.
    fun isGranted(packageName: String, uid: Int): Boolean =
        !authority.revoked(uid) && authority.grantOf(uid)?.members?.containsKey(packageName) == true

    fun isStale(packageName: String, uid: Int): Boolean =
        isGranted(packageName, uid) && authority.grantOf(uid)?.matches(identities[uid]) != true

    companion object {
        fun read(
            snapshot: () -> AuthorizationSnapshot?,
            identityOf: (Int) -> ApplicationIdentity?,
        ): HookAppListSnapshot {
            val authority = checkNotNull(snapshot()) { "HOOK_AUTHORITY_UNAVAILABLE" }
            check(!authority.corrupt) { "HOOK_AUTHORITY_CORRUPT" }
            val identities = authority.grants.keys.filterNot(authority::revoked)
                .associateWith(identityOf)
            return HookAppListSnapshot(authority, identities)
        }
    }
}
