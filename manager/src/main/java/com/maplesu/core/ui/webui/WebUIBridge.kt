package com.maplesu.core.ui.webui

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.webkit.JsPromptResult
import android.webkit.JsResult
import android.webkit.ValueCallback
import android.webkit.WebChromeClient
import android.webkit.WebView
import androidx.webkit.RestrictionAllowlist
import androidx.webkit.WebViewBuilder
import androidx.webkit.WebViewFeature

/** HTTP modules keep their own request handling, including POST bodies. */
internal fun createHttpModuleWebView(context: Context, entryUrl: String, state: WebUIState): WebView {
    val origin = requireNotNull(ModuleWebOrigin.from(entryUrl)) { "Invalid module HTTP origin" }
    val restrictedBuilder = WebViewFeature.isFeatureSupported(WebViewFeature.WEBVIEW_BUILDER_EXPERIMENTAL_V1)
    val commands = WebViewInterface(state)
    val downloads = WebUIDownloadInterface(state)
    return try {
        (if (restrictedBuilder) WebViewBuilder(WebViewBuilder.PRESET_LEGACY)
            .restrictJavaScriptInterfaces()
            .addAllowlist(RestrictionAllowlist.Builder(setOf(origin.value))
                .addJavaScriptInterface(commands, "ksu")
                .addJavaScriptInterface(downloads, "ksu_download")
                .build())
            .build(context)
        else WebView(context).also { view ->
            if (WebViewFeature.isFeatureSupported(WebViewFeature.DOCUMENT_START_SCRIPT)) {
                val bridge = HttpWebUiBridge(state, view, commands, downloads)
                state.httpBridge = bridge
                try { bridge.install(origin) } catch (error: Exception) {
                    bridge.close()
                    state.httpBridge = null
                    view.destroy()
                    throw error
                }
            } else {
                // Match KernelSU on older providers: real nested objects are
                // available before loadUrl, with its all-frame interface scope.
                view.addJavascriptInterface(commands, "ksu")
                view.addJavascriptInterface(downloads, "ksu_download")
            }
        })
            .also {
                state.javascriptBridge = commands
                state.downloadBridge = downloads
            }
    } catch (error: Exception) {
        commands.destroy()
        downloads.destroy()
        throw error
    }
}

internal fun moduleWebChromeClient(webUIState: WebUIState): WebChromeClient = object : WebChromeClient() {
    override fun onJsAlert(view: WebView?, url: String?, message: String?, result: JsResult?): Boolean {
        if (message == null || result == null) return false
        if (!webUIState.acceptsPage(view)) { result.cancel(); return true }
        webUIState.cancelPendingResult()
        webUIState.uiEvent = WebUIEvent.ShowAlert(message, result)
        return true
    }

    override fun onJsConfirm(view: WebView?, url: String?, message: String?, result: JsResult?): Boolean {
        if (message == null || result == null) return false
        if (!webUIState.acceptsPage(view)) { result.cancel(); return true }
        webUIState.cancelPendingResult()
        webUIState.uiEvent = WebUIEvent.ShowConfirm(message, result)
        return true
    }

    override fun onJsPrompt(
        view: WebView?,
        url: String?,
        message: String?,
        defaultValue: String?,
        result: JsPromptResult?
    ): Boolean {
        if (message == null || result == null || defaultValue == null) return false
        if (!webUIState.acceptsPage(view)) { result.cancel(); return true }
        webUIState.cancelPendingResult()
        webUIState.uiEvent = WebUIEvent.ShowPrompt(message, defaultValue, result)
        return true
    }

    override fun onShowFileChooser(
        webView: WebView?, filePathCallback: ValueCallback<Array<Uri>>?, fileChooserParams: FileChooserParams?
    ): Boolean {
        if (!webUIState.acceptsPage(webView)) { filePathCallback?.onReceiveValue(null); return true }
        webUIState.cancelPendingResult()
        webUIState.filePathCallback = filePathCallback

        val intent = fileChooserParams?.createIntent() ?: Intent(Intent.ACTION_GET_CONTENT).apply { type = "*/*" }
        if (fileChooserParams?.mode == FileChooserParams.MODE_OPEN_MULTIPLE) {
            intent.putExtra(Intent.EXTRA_ALLOW_MULTIPLE, true)
        }
        webUIState.uiEvent = WebUIEvent.ShowFileChooser(intent)
        return true
    }
}
