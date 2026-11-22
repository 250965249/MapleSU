package com.maplesu.core.ui.webui

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.webkit.JsPromptResult
import android.webkit.JsResult
import android.webkit.WebView
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import com.topjohnwu.superuser.Shell
import com.maplesu.core.R
import dev.maplesu.manager.modules.webui.ModuleWebUiSessions
import java.util.concurrent.atomic.AtomicBoolean

sealed class WebUIEvent {
    data object Loading : WebUIEvent()
    data object WebViewReady : WebUIEvent()
    data class Error(val message: String) : WebUIEvent()
    data object Close : WebUIEvent()
    data class ShowAlert(val message: String, val result: JsResult) : WebUIEvent()
    data class ShowConfirm(val message: String, val result: JsResult) : WebUIEvent()
    data class ShowPrompt(val message: String, val defaultValue: String, val result: JsPromptResult) : WebUIEvent()
    data class ShowFileChooser(val intent: Intent) : WebUIEvent()
}

class WebUIState {
    @Volatile
    internal var isDisposed = false
        private set
    @Volatile
    private var exitRequested = false
    var webView: WebView? = null
    @Volatile
    var rootShell: Shell? = null
    @Volatile
    var javascriptBridge: WebViewInterface? = null
    @Volatile
    var downloadBridge: WebUIDownloadInterface? = null
    @Volatile
    internal var httpBridge: AutoCloseable? = null
    @Volatile
    internal var assetHandler: SuFilePathHandler? = null
    private val resourceLock = Any()
    lateinit var modDir: String
    var moduleId: String? = null
    private var moduleSubscription: AutoCloseable? = null
    @Volatile
    private var moduleSubscriptionToken: AtomicBoolean? = null
    internal val isModuleSessionCurrent: Boolean
        get() = !isDisposed && !exitRequested && moduleSubscriptionToken?.get() != false

    internal fun attachRootShell(shell: Shell): Boolean = synchronized(resourceLock) {
        if (!isModuleSessionCurrent) false else { rootShell = shell; true }
    }

    internal fun bindModuleSession(activity: Activity, id: String,
                                   expectedRevision: Long = ModuleWebUiSessions.revision(id),
                                   ownerScope: ModuleWebUiSessions.OwnerScope? = null): Boolean {
        if (isDisposed || exitRequested) return false
        moduleSubscriptionToken?.set(false)
        moduleSubscription?.close()
        val token = AtomicBoolean(true)
        moduleSubscriptionToken = token
        moduleId = id
        val subscription = ModuleWebUiSessions.subscribe(id, expectedRevision, ownerScope) {
            token.set(false)
            if (moduleSubscriptionToken === token) retirePageResources()
            activity.runOnUiThread {
                if (!isDisposed && moduleSubscriptionToken === token) {
                    requestExit()
                    dispose(activity)
                }
            }
        }
        if (subscription == null) {
            token.set(false)
            requestExit()
            dispose(activity)
            return false
        }
        if (isDisposed || !token.get()) {
            subscription.close()
            return false
        }
        moduleSubscription = subscription
        return true
    }
    var moduleName: String = ""
    var moduleInfoJson: String? = null

    var uiEvent by mutableStateOf<WebUIEvent>(WebUIEvent.Loading)
    var isUrlLoaded = false
    @Volatile
    var currentInsets: Insets = Insets(0, 0, 0, 0)
    var isInsetsEnabled by mutableStateOf(false)
    var webCanGoBack by mutableStateOf(false)
    var filePathCallback: android.webkit.ValueCallback<Array<Uri>>? = null

    internal fun acceptsPage(view: WebView?): Boolean =
        isModuleSessionCurrent && uiEvent != WebUIEvent.Close && view != null && webView === view

    internal fun cancelPendingResult() {
        when (val event = uiEvent) {
            is WebUIEvent.ShowAlert -> event.result.cancel()
            is WebUIEvent.ShowConfirm -> event.result.cancel()
            is WebUIEvent.ShowPrompt -> event.result.cancel()
            else -> Unit
        }
        val callback = filePathCallback
        filePathCallback = null
        callback?.onReceiveValue(null)
    }

    private fun retirePageResources() {
        httpBridge?.close()
        javascriptBridge?.destroy()
        downloadBridge?.destroy()
        assetHandler?.destroy()
        val shell = synchronized(resourceLock) { rootShell.also { rootShell = null } }
        if (shell != null) cleanupWebUiResources { shell.close() }
    }

    fun onAlertResult() {
        if (!acceptsPage(webView)) return
        val event = uiEvent
        if (event is WebUIEvent.ShowAlert) {
            event.result.confirm()
            uiEvent = WebUIEvent.WebViewReady
        }
    }

    fun onConfirmResult(confirmed: Boolean) {
        if (!acceptsPage(webView)) return
        val event = uiEvent
        if (event is WebUIEvent.ShowConfirm) {
            if (confirmed) event.result.confirm() else event.result.cancel()
            uiEvent = WebUIEvent.WebViewReady
        }
    }

    fun onPromptResult(result: String?) {
        if (!acceptsPage(webView)) return
        val event = uiEvent
        if (event is WebUIEvent.ShowPrompt) {
            if (result != null) event.result.confirm(result) else event.result.cancel()
            uiEvent = WebUIEvent.WebViewReady
        }
    }

    fun onFileChooserResult(uris: Array<Uri>?) {
        if (!acceptsPage(webView)) return
        val callback = filePathCallback ?: return
        filePathCallback = null
        callback.onReceiveValue(uris)
        uiEvent = WebUIEvent.WebViewReady
    }

    fun requestExit() {
        exitRequested = true
        cancelPendingResult()
        uiEvent = WebUIEvent.Close
        retirePageResources()
    }

    fun dispose(activity: Activity) {
        if (isDisposed) return
        isDisposed = true
        moduleSubscriptionToken?.set(false)
        moduleSubscriptionToken = null
        moduleSubscription?.close()
        moduleSubscription = null
        retirePageResources()
        cancelPendingResult()
        downloadBridge = null
        httpBridge = null
        javascriptBridge = null
        assetHandler = null
        val view = webView
        webView = null
        try {
            activity.setTaskDescription(activity.getString(R.string.app_name))
        } finally {
            view?.let {
                (it.parent as? android.view.ViewGroup)?.removeView(it)
                it.destroy()
            }
        }
    }
}

