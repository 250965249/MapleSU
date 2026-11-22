package dev.maplesu.manager.workmode.superuser

import dev.maplesu.manager.workmode.control.schema.Tomb
import dev.maplesu.manager.runtime.ultra.SuUidProfile

/** `A_ULTRA` native full-UID decisions, with a centralized legacy package adapter. */
interface UltraSuperuserPort {
    val supportsUidProfiles: Boolean get() = false
    fun uidProfiles(): Map<Int, SuUidProfile>? = null
    fun setUidAllowed(uid: Int, packageName: String, allowed: Boolean): Boolean = false
    fun isActive(): Boolean
    fun grantedPackages(): Set<String>
    fun isGranted(packageName: String): Boolean
    fun uidForPackage(packageName: String): Int?
    fun identity(packageName: String, uid: Int): IdentitySnapshot?
    fun packagesForUid(uid: Int): List<String>
    fun grant(packageName: String): Boolean
    fun revoke(packageName: String): Boolean
}

/** Full UID stays intact; [ApplyPlanner]/[IdentityRules] retain shared-UID all-or-none policy. */
class UltraSuperuserBackend(private val port: UltraSuperuserPort) : SuperuserBackend {
    override val id: BackendId = BackendId.A_ULTRA

    override fun available(): Boolean = runCatching { port.isActive() }.getOrDefault(false)

    override fun enumerate(): List<GrantView> {
        if (!available()) return emptyList()
        if (port.supportsUidProfiles) {
            val profiles = port.uidProfiles() ?: throw IllegalStateException("A_ULTRA_UID_READ_FAILED")
            return profiles.values.filter { it.allow }.sortedBy { it.uid }.flatMap { profile ->
                port.packagesForUid(profile.uid).sorted().mapNotNull { name ->
                    if (ProtectedIdentities.isProtected(profile.uid, name)) null else {
                        val identity = port.identity(name, profile.uid)
                            ?: throw IllegalStateException("A_ULTRA_IDENTITY_CHECK_FAILED:${profile.uid}")
                        check(identity.uid == profile.uid && identity.packageName == name) { "A_ULTRA_IDENTITY_CHECK_FAILED:${profile.uid}" }
                        GrantView(profile.uid, name, true, Granularity.UID_PACKAGE_PROFILE, identity)
                    }
                }
            }
        }
        val views = ArrayList<GrantView>()
        for (packageName in port.grantedPackages().sorted()) {
            val uid = port.uidForPackage(packageName) ?: continue
            if (ProtectedIdentities.isProtected(uid, packageName)) continue
            val identity = port.identity(packageName, uid) ?: continue
            views.add(GrantView(uid, packageName, true, Granularity.PACKAGE, identity))
        }
        return views
    }

    override fun apply(desired: List<GrantView>, tombs: List<Tomb>, rev: Long): ApplyReport {
        if (port.supportsUidProfiles) return applyUids(desired, tombs, rev)
        if (!available()) {
            return ApplyReport.reject(id, desired, rev, "A_ULTRA_UNAVAILABLE", "ultra environment inactive")
        }
        val failures = ArrayList<ApplyFailure>()
        val revokePackages = LinkedHashSet<String>()
        for (tomb in tombs) {
            if (ProtectedIdentities.isProtected(tomb.uid, tomb.packageName)) continue
            revokePackages.add(tomb.packageName)
        }
        for (view in desired) {
            if (!view.allow && !ProtectedIdentities.isProtected(view.uid, view.packageName)) {
                revokePackages.add(view.packageName)
            }
        }
        for (packageName in revokePackages) {
            if (!port.isGranted(packageName)) continue
            if (!port.revoke(packageName)) {
                failures.add(
                    ApplyFailure(0, packageName, ApplyReport.OP_REVOKE, "A_ULTRA_REVOKE_FAILED"),
                )
            }
        }
        val grantPackages = LinkedHashSet<String>()
        for (view in desired) {
            if (view.allow && !ProtectedIdentities.isProtected(view.uid, view.packageName)) {
                grantPackages.add(view.packageName)
            }
        }
        for (packageName in grantPackages) {
            if (port.isGranted(packageName)) continue
            if (!port.grant(packageName)) {
                failures.add(
                    ApplyFailure(0, packageName, ApplyReport.OP_GRANT, "A_ULTRA_GRANT_FAILED"),
                )
            }
        }
        return if (failures.isEmpty()) ApplyReport.success(id, rev)
        else ApplyReport(emptyList(), failures, rev)
    }

    override fun verify(): List<GrantView> = enumerate()

    private fun applyUids(desired: List<GrantView>, tombs: List<Tomb>, rev: Long): ApplyReport {
        val decisions = linkedMapOf<Int, Pair<String, Boolean>>()
        for (tomb in tombs) {
            if (!ProtectedIdentities.isProtected(tomb.uid, tomb.packageName))
                decisions[tomb.uid] = tomb.packageName to false
        }
        for ((uid, views) in desired.groupBy { it.uid }) {
            val eligible = views.filterNot { ProtectedIdentities.isProtected(it.uid, it.packageName) }
            if (eligible.isNotEmpty()) decisions[uid] = eligible.first().packageName to eligible.all { it.allow }
        }
        fun failed(code: String) = ApplyReport(emptyList(), decisions.map { (uid, decision) ->
            ApplyFailure(uid, decision.first, if (decision.second) ApplyReport.OP_GRANT else ApplyReport.OP_REVOKE, code)
        }, rev)
        if (!available()) return failed("A_ULTRA_UNAVAILABLE")
        if (port.uidProfiles() == null) return failed("A_ULTRA_UID_READ_FAILED")
        val failures = arrayListOf<ApplyFailure>()
        for ((uid, decision) in decisions.entries.sortedBy { it.value.second }) {
            val (name, allow) = decision
            // A cached allow bit carries neither current install identity nor delivery proof.
            if (!port.setUidAllowed(uid, name, allow)) failures += ApplyFailure(uid, name,
                if (allow) ApplyReport.OP_GRANT else ApplyReport.OP_REVOKE,
                if (allow) "A_ULTRA_GRANT_FAILED" else "A_ULTRA_REVOKE_FAILED")
        }
        val after = port.uidProfiles() ?: run {
            for ((uid, decision) in decisions) {
                if (failures.none { it.uid == uid }) failures += ApplyFailure(uid, decision.first,
                    if (decision.second) ApplyReport.OP_GRANT else ApplyReport.OP_REVOKE,
                    "A_ULTRA_UID_READBACK_FAILED")
            }
            return ApplyReport(emptyList(), failures, rev)
        }
        for ((uid, decision) in decisions) {
            if (after[uid]?.allow != decision.second && failures.none { it.uid == uid })
                failures += ApplyFailure(uid, decision.first,
                    if (decision.second) ApplyReport.OP_GRANT else ApplyReport.OP_REVOKE,
                    "A_ULTRA_UID_READBACK_MISMATCH")
        }
        return if (failures.isEmpty()) ApplyReport.success(id, rev) else ApplyReport(emptyList(), failures, rev)
    }

    override fun packageNamesForUid(uid: Int): List<String> = port.packagesForUid(uid)
}
