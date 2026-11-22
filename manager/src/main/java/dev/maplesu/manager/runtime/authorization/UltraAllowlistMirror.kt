package dev.maplesu.manager.runtime.authorization

import dev.maplesu.manager.runtime.ultra.UltraAuthorizationAttempt
import dev.maplesu.manager.runtime.ultra.suAuthLogCode
import dev.maplesu.manager.runtime.ultra.SuUidProfile

/** Fresh SDK list + live install identities; no cache may stand in for a readback. */
internal interface UltraAllowlistPort {
    val supportsUidProfiles: Boolean get() = false
    fun beginIdentityRead(revision: Long): Boolean = true
    fun uidProfiles(): Map<Int, SuUidProfile>? = null
    fun reconcileUidMapping(): Boolean = false
    fun setAllowed(uid: Int, packageName: String, allowed: Boolean): UltraAuthorizationAttempt = setAllowed(packageName, allowed)
    fun packages(): Set<String>?
    fun identity(uid: Int): ApplicationIdentity?
    fun uniquelyMapped(packageName: String, uid: Int): Boolean = true
    fun setAllowed(packageName: String, allowed: Boolean): UltraAuthorizationAttempt
}

/** Boot SDK mirrors the Hook authority, including disables, tombstones and identity changes. */
internal class UltraAllowlistMirror(
    private val port: UltraAllowlistPort,
    private val protectedPackages: Set<String> = setOf("dev.maplesu.manager", "android", "com.android.shell"),
) : SuperuserMirror {
    override val backend: String = BACKEND

    override fun apply(snapshot: AuthorizationSnapshot): MirrorOutcome = try {
        if (snapshot.corrupt) MirrorOutcome.failure("AUTHORITY_UNREADABLE") else sync(snapshot)
    } catch (error: Exception) {
        MirrorOutcome.failure(error.javaClass.simpleName)
    }

    private fun sync(snapshot: AuthorizationSnapshot): MirrorOutcome {
        if (port.supportsUidProfiles) return syncUids(snapshot)
        val before = port.packages() ?: return MirrorOutcome.failure("SDK_LIST_UNREADABLE")
        var lastAttempt: UltraAuthorizationAttempt? = null
        val desired = linkedMapOf<String, Boolean>()
        for (tomb in snapshot.tombs) {
            if (tomb.packageName.isNotBlank() && tomb.packageName !in protectedPackages) desired[tomb.packageName] = false
        }
        var ambiguous = false
        for (record in snapshot.grants.values) {
            if (record.packageName in protectedPackages) continue
            val allowed = ManagerSuperuserPolicy.decide(snapshot, record.uid, port.identity(record.uid)).allowed
            val mapped = !allowed || port.uniquelyMapped(record.packageName, record.uid)
            if (!mapped) ambiguous = true
            desired[record.packageName] = desired[record.packageName] == true || (allowed && mapped)
        }
        for (pkg in before - protectedPackages - desired.keys) desired[pkg] = false
        // Revoke before granting. The SDK's manager/self entries are not authority records.
        val changes = desired.entries.sortedBy { it.value }
        for ((pkg, allow) in changes) {
            // Package membership does not verify its current uid; repeated add refreshes it without revoking first.
            if (allow || pkg in before) {
                val attempt = port.setAllowed(pkg, allow)
                lastAttempt = attempt
                if (!attempt.succeeded) return MirrorOutcome.failure(
                    "SDK_APPLY_FAILED:$pkg error=${suAuthLogCode(requireNotNull(attempt.error))} ${attempt.diagnosticSummary}")
            }
        }
        val detail = lastAttempt?.diagnosticSummary.orEmpty()
        val after = runCatching { port.packages() }.getOrNull()
            ?: return MirrorOutcome.failure("SDK_READBACK_UNREADABLE $detail".trimEnd())
        return if (ambiguous) MirrorOutcome.failure("SDK_PACKAGE_GLOBAL_UID_AMBIGUOUS $detail".trimEnd())
        else if (after - protectedPackages == desired.filterValues { it }.keys) MirrorOutcome(true, detail)
        else MirrorOutcome.failure("SDK_READBACK_MISMATCH $detail".trimEnd())
    }

    private fun syncUids(snapshot: AuthorizationSnapshot): MirrorOutcome {
        if (!port.beginIdentityRead(snapshot.rev)) return MirrorOutcome.failure("SDK_CURRENT_IDENTITY_UNREADABLE")
        val before = port.uidProfiles() ?: run {
            // This explicit apply may rebuild the existing authority once. Ordinary
            // list/readback paths stay read-only and never replay a grant.
            if (!port.reconcileUidMapping()) return MirrorOutcome.failure("SDK_UID_LIST_UNREADABLE")
            port.uidProfiles() ?: return MirrorOutcome.failure("SDK_UID_LIST_UNREADABLE_AFTER_RECONCILE")
        }
        // Manager has a signed full-UID authority record too; disabling/revoking it
        // must close standard su while its authenticated Owner transport stays separate.
        val protectedUidPackages = protectedPackages intersect setOf("android", "com.android.shell")
        val protectedUids = before.values.filter { it.packageName in protectedUidPackages }.mapTo(hashSetOf()) { it.uid }
        val desired = linkedMapOf<Int, SuUidProfile>()
        for (tomb in snapshot.tombs) {
            val name = tomb.packageName.takeIf { it.isNotBlank() } ?: before[tomb.uid]?.packageName ?: continue
            if (name !in protectedUidPackages) desired[tomb.uid] = SuUidProfile(tomb.uid, false, name)
        }
        for (identity in snapshot.grants.values) {
            if (identity.packageName in protectedUidPackages) continue
            val allow = ManagerSuperuserPolicy.decide(snapshot, identity.uid, port.identity(identity.uid)).allowed
            desired[identity.uid] = SuUidProfile(identity.uid, allow, identity.packageName)
        }
        for ((uid, profile) in before) {
            if (uid !in protectedUids && uid !in desired && profile.allow) desired[uid] = profile.copy(allow = false)
        }
        var last: UltraAuthorizationAttempt? = null
        for ((uid, profile) in desired.entries.sortedBy { it.value.allow }) {
            if (!profile.allow && before[uid]?.allow == false) continue
            val attempt = port.setAllowed(uid, profile.packageName, profile.allow)
            last = attempt
            if (!attempt.succeeded || !attempt.decisionVerified) return MirrorOutcome.failure(
                "SDK_UID_APPLY_FAILED:$uid ${attempt.diagnosticSummary}")
        }
        val after = port.uidProfiles() ?: return MirrorOutcome.failure("SDK_UID_READBACK_UNREADABLE ${last?.diagnosticSummary.orEmpty()}")
        val wanted = desired.values.filter { it.allow }.mapTo(hashSetOf()) { it.uid }
        val observed = after.values.filter { it.allow && it.uid !in protectedUids }.mapTo(hashSetOf()) { it.uid }
        val deniesMatch = desired.values.filter { !it.allow }.all { after[it.uid]?.allow == false }
        return if (wanted == observed && deniesMatch) MirrorOutcome(true, last?.diagnosticSummary.orEmpty())
            else MirrorOutcome.failure("SDK_UID_READBACK_MISMATCH ${last?.diagnosticSummary.orEmpty()}")
    }

    companion object { const val BACKEND = "ULTRA_ALLOWLIST" }
}
