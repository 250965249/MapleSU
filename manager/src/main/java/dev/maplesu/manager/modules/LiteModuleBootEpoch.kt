package dev.maplesu.manager.modules

import android.content.Context
import android.provider.Settings
import java.io.File
import java.util.UUID

/** Module stages belong to a framework boot; Hook credentials still belong to the kernel boot. */
internal object LiteModuleBootEpoch {
    fun read(context: Context): String = id(
        File("/proc/sys/kernel/random/boot_id").readText().trim(),
        runCatching { Settings.Global.getInt(context.contentResolver, Settings.Global.BOOT_COUNT) }.getOrNull(),
    )

    internal fun id(kernelBoot: String, frameworkBoot: Int?): String {
        require(kernelBoot.matches(Regex("[a-f0-9-]{36}")))
        // Without a framework counter keep the previous kernel-only deduplication.
        // Never treat an app process restart as a new module boot.
        if (frameworkBoot == null || frameworkBoot < 0) return kernelBoot
        return UUID.nameUUIDFromBytes("$kernelBoot:$frameworkBoot".toByteArray(Charsets.UTF_8)).toString()
    }
}
