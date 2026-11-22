package dev.maplesu.manager.runtime.authorization

import com.maplesu.core.Natives

/** Android-facing conversion only; the authority and its parser stay platform independent. */
internal object ManagerSuProfiles {
    fun fromNative(profile: Natives.Profile): SuProfile = SuProfile(
        profile.name, profile.currentUid, profile.allowSu, profile.rootUseDefault, profile.rootTemplate,
        profile.uid, profile.gid, profile.groups.toList(), profile.capabilities.toList(), profile.context,
        profile.namespace, profile.nonRootUseDefault, profile.umountModules, profile.flags,
    ).validated()

    fun toNative(profile: SuProfile): Natives.Profile = Natives.Profile(
        profile.name, currentUid = profile.currentUid, allowSu = profile.allowSu,
        rootUseDefault = profile.rootUseDefault, rootTemplate = profile.rootTemplate,
        uid = profile.uid, gid = profile.gid, groups = profile.groups.toList(),
        capabilities = profile.capabilities.toList(), context = profile.context, namespace = profile.namespace,
        nonRootUseDefault = profile.nonRootUseDefault, umountModules = profile.umountModules, flags = profile.flags,
    )

    fun read(snapshot: AuthorizationSnapshot, name: String, identity: ApplicationIdentity): Natives.Profile {
        check(!snapshot.corrupt) { "PROFILE_AUTHORITY_UNREADABLE" }
        val record = snapshot.profileOf(identity.uid)
        check((identity.uid in snapshot.profileRev) == (record != null)) { "AUTH_STORE_PROFILE_MISSING" }
        if (record == null) return Natives.Profile(name, currentUid = identity.uid,
            allowSu = !snapshot.revoked(identity.uid) && snapshot.grantOf(identity.uid)?.matches(identity) == true)
        check(record.identity.matches(identity)) { "PROFILE_IDENTITY_CHANGED" }
        return toNative(record.profile.copy(name = name, allowSu = record.profile.allowSu && !snapshot.revoked(identity.uid)))
    }
}
