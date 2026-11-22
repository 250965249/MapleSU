package dev.maplesu.manager.runtime.authorization

import com.maplesu.core.Natives

/** The existing fixed-environment backend cannot apply custom KSU credentials or unmount policy. */
internal fun supportsFixedSuProfile(profile: Natives.Profile): Boolean =
    if (profile.allowSu) profile.rootUseDefault && profile.rules.isEmpty()
    else profile.nonRootUseDefault
