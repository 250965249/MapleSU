package com.maplesu.core.ui.screen.appprofile

import com.maplesu.core.Natives
import com.maplesu.core.ui.util.getKsuDaemonPath
import com.maplesu.core.ui.util.getRootShell
import com.maplesu.core.ui.util.setSepolicy

internal fun loadKsuProfileRules(
    profile: Natives.Profile,
    readRules: (String) -> String? = ::readKsuSepolicy,
): Natives.Profile? = if (!profile.allowSu) profile else
    readRules(profile.name)?.let { profile.copy(rules = it) }

internal fun saveKsuProfileWithRules(
    profile: Natives.Profile,
    writeProfile: (Natives.Profile) -> Natives.ProfileWriteResult = Natives::setAppProfileDetailed,
    writeRules: (String, String) -> Boolean = ::setSepolicy,
): Natives.ProfileWriteResult {
    val written = writeProfile(profile)
    if (!written.succeeded || !profile.allowSu || profile.rootUseDefault) return written
    // ksud policy application is separate from the committed kernel profile, including an empty file.
    val policy = runCatching { writeRules(profile.name, profile.rules) }
    if (policy.getOrDefault(false)) return written
    return written.copy(pendingApply = true, code = "PROFILE_SEPOLICY_APPLY_FAILED",
        detail = listOf(written.detail, policy.exceptionOrNull()?.javaClass?.simpleName.orEmpty())
            .filter { it.isNotEmpty() }.joinToString("; "))
}

private fun readKsuSepolicy(name: String): String? {
    if (name.isEmpty() || name == "." || name == ".." || name.any { it in "/\u0000\n\r" }) return null
    fun quote(value: String) = "'" + value.replace("'", "'\\''") + "'"
    val key = quote(name)
    val file = quote("/data/adb/ksu/profile/selinux/$name")
    // Pinned ksud defs.rs owns this existing path. Only a proven absent file means empty rules.
    val command = """(
        for directory in /data/adb /data/adb/ksu /data/adb/ksu/profile /data/adb/ksu/profile/selinux; do
            if [ -d "${'$'}directory" ]; then
                [ -r "${'$'}directory" ] && [ -x "${'$'}directory" ] || exit 1
            elif [ -e "${'$'}directory" ] || [ -L "${'$'}directory" ]; then
                exit 1
            else
                exit 0
            fi
        done
        if [ -e $file ] || [ -L $file ]; then
            ${quote(getKsuDaemonPath())} profile get-sepolicy $key
        fi
    )""".trimIndent()
    return runCatching {
        val result = getRootShell().newJob().add(command).to(ArrayList(), null).exec()
        if (result.isSuccess) result.out.joinToString("\n") else null
    }.getOrNull()
}
