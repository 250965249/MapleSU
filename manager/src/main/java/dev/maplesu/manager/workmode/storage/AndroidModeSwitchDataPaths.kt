package dev.maplesu.manager.workmode.storage

import dev.maplesu.manager.compat.ultraPreferences

import android.content.Context
import dev.maplesu.manager.runtime.MapleSuCredentialStore
import dev.maplesu.manager.workmode.WorkMode
import java.io.File

/** Construct in the manager process, then freeze both direction lists before switching. */
class AndroidModeSwitchDataPaths(
    context: Context,
    registeredExternal: Map<WorkMode, List<String>> = emptyMap(),
) : ModeSwitchDataPaths {
    private val paths: ModeSwitchDataPaths

    init {
        val app = context.applicationContext ?: context
        val ultra = app.ultraPreferences("maplesu-ultra", Context.MODE_PRIVATE)
        val key = ultra.getString("rootKey", null)?.takeIf { it.isNotBlank() }
            ?: ultra.getString("rootKeySuspended", null)
        val credential = MapleSuCredentialStore(app).load()
        try {
            val previous = File(app.filesDir, "published-directory").takeIf { it.isFile }
                ?.readText()?.trim()?.takeIf { it.isNotEmpty() }
            val runtimeName = app.ultraPreferences("runtime_deployment", Context.MODE_PRIVATE)
                .getString("directory_name", null)?.takeIf { it.isNotBlank() }
            paths = ModeSwitchDataPaths.fromLocal(
                rootKey = key,
                credential = credential,
                previousPublication = previous,
                runtimeDirectory = runtimeName?.let { "/data/$it" },
                registeredExternal = registeredExternal,
            )
        } finally {
            credential?.fill(0)
        }
    }

    override fun entries(mode: WorkMode): List<MoveEntry> = paths.entries(mode)
}
