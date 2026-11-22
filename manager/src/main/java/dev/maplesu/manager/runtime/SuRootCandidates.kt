package dev.maplesu.manager.runtime

import android.content.Context
import java.io.File

/** One inventory for the SU readiness probe and installation; names never carry private paths. */
internal object SuRootCandidates {
    data class Candidate(val source: String, val argv: List<String>)

    const val LEGACY_MAPLESU_SU = "/dev/maplesu/bin/su"
    val KSU_SU_PATHS = listOf("/system/bin/su", "/system/xbin/su", "/sbin/su", "/data/adb/ksu/bin/su")

    fun all(context: Context): List<Candidate> = buildList {
        fun su(source: String, path: String) {
            add(Candidate(source, listOf(path, "-c", "/system/bin/sh")))
        }
        // Ultra intercepts exec of this path even if stat() cannot see a file. It needs no key.
        su("maplesu-su:ultra", "/system/bin/su")
        val published = listOf(
            "current" to runCatching { SuPublication.suPath(context) }.getOrNull(),
            "previous" to runCatching { SuPublication.previousDirectory(context)?.let { "$it/su" } }.getOrNull(),
            "legacy" to LEGACY_MAPLESU_SU,
        )
        // stat() visibility is not an execution result; keep known paths in the probe list.
        for ((name, path) in published) {
            if (path != null) su("maplesu-su:$name", path)
        }
        for (path in KSU_SU_PATHS) {
            su("ksu-su:$path", path)
        }
        su("path-su", "su")
        val ksud = File(context.applicationInfo.nativeLibraryDir, "libksud_ksu.so")
        if (ksud.isFile) add(Candidate("ksu-debug-su", listOf(ksud.absolutePath, "debug", "su")))
    }.distinctBy { it.argv }
}
