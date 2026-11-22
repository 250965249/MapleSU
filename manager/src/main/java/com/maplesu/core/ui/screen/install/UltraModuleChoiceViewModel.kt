package com.maplesu.core.ui.screen.install

import android.content.Context
import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dev.maplesu.manager.installer.InstallTargetMode
import dev.maplesu.manager.installer.InstallerServiceClient
import dev.maplesu.manager.modules.LiteScriptModuleBackend
import dev.maplesu.manager.modules.ModuleOperationService
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** A configuration change must not repeat a destructive choice or lose its running result. */
internal class UltraModuleChoiceViewModel : ViewModel() {
    data class State(
        val show: Boolean = false,
        val busy: Boolean = false,
        val keepModules: Boolean? = null,
        val failed: Boolean = false,
    )

    private val mutable = MutableStateFlow(State())
    val state = mutable.asStateFlow()

    fun request() { if (!mutable.value.busy) mutable.value = State(show = true) }
    fun reset() { if (!mutable.value.busy) mutable.value = State() }
    fun dismiss() { if (!mutable.value.busy) mutable.value = mutable.value.copy(show = false) }
    fun keep() { if (mutable.value.show && !mutable.value.busy) mutable.value = State(keepModules = true) }

    fun remove(context: Context) {
        if (!mutable.value.show || mutable.value.busy) return
        mutable.value = mutable.value.copy(busy = true, failed = false)
        val app = context.applicationContext
        viewModelScope.launch {
            try {
                ModuleOperationService.run(app) {
                    withContext(Dispatchers.IO) {
                        LiteScriptModuleBackend.withMigrationCleanup {
                            val result = InstallerServiceClient.withService(app, persistent = true,
                                rootTarget = InstallTargetMode.ULTRA) { it.removeKsuModulesForUltra() }
                            check(result.getBoolean("complete")) { "MODULE_CLEANUP_INCOMPLETE" }
                        }
                    }
                }
                mutable.value = State(keepModules = false)
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                Log.w("MapleSUModules", "Ultra migration module cleanup failed", error)
                mutable.value = State(show = true, failed = true)
            }
        }
    }
}
