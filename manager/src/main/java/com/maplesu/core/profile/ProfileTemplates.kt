package com.maplesu.core.profile

import com.maplesu.core.Natives
import com.maplesu.core.data.model.TemplateInfo
import com.maplesu.core.toRawFlags

internal fun Natives.Profile.withRootFlags(flags: List<Natives.Profile.RootProfileFlag>): Natives.Profile =
    copy(flags = flags.toRawFlags(), rootUseDefault = false)

/** A template supplies root settings; the target application and non-root policy stay intact. */
internal fun Natives.Profile.withTemplate(id: String, template: TemplateInfo): Natives.Profile {
    require(template.flags.all { it in Natives.Profile.RootProfileFlag.entries.indices })
    return copy(
        rootTemplate = id,
        rootUseDefault = false,
        uid = template.uid,
        gid = template.gid,
        groups = template.groups.toList(),
        capabilities = template.capabilities.toList(),
        context = template.context,
        namespace = template.namespace,
        rules = template.rules.joinToString("\n"),
        flags = template.flags.fold(0L) { bits, flag -> bits or (1L shl flag) },
    )
}
