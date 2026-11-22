package com.maplesu.core.ui.webui

import android.annotation.SuppressLint
import android.app.Activity
import android.app.ActivityManager
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.net.Uri
import android.os.Build
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebView
import androidx.webkit.WebViewAssetLoader
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import com.maplesu.core.R
import com.maplesu.core.data.model.AppInfo
import com.maplesu.core.data.repository.ModuleRepositoryImpl
import com.maplesu.core.ui.util.AppIconCache
import com.maplesu.core.ui.util.createRootShell
import com.maplesu.core.ui.util.withMainUserUid
import com.maplesu.core.ui.viewmodel.SuperUserViewModel
import java.io.File
import dev.maplesu.manager.modules.webui.ModuleWebUiSessions

internal fun webUIApps(): List<AppInfo> = runBlocking {
    SuperUserViewModel.loadApps(useCache = true).getOrNull()?.first.orEmpty()
}

fun Activity.setTaskDescription(label: String) {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
        @Suppress("DEPRECATION")
        setTaskDescription(ActivityManager.TaskDescription(label))
    } else {
        val taskDescription = ActivityManager.TaskDescription.Builder()
            .setLabel(label)
            .build()
        setTaskDescription(taskDescription)
    }
}

@SuppressLint("SetJavaScriptEnabled")
internal suspend fun prepareWebView(
    activity: Activity,
    moduleId: String,
    webUIState: WebUIState,
) {
    val moduleRevision = ModuleWebUiSessions.revision(moduleId)
    val ownerScope = dev.maplesu.manager.runtime.ultra.UltraEnvironmentProbe.webUiOwnerScope(activity)
    withContext(Dispatchers.IO) {
        val repo = ModuleRepositoryImpl()
        // 后端不可用（例如 Normal 下 KSU 端口未接线）是**显式错误**，不能折叠成
        // "no such module"：两者对用户的含义完全不同（审计 §5 的误报来源）。
        val modules = loadWebUiModules(repo).getOrElse { error ->
            withContext(Dispatchers.Main) {
                webUIState.uiEvent = WebUIEvent.Error(
                    error.message ?: activity.getString(R.string.no_such_module, moduleId),
                )
            }
            return@withContext
        }
        val moduleInfo = modules.find { info -> info.id == moduleId }

        if (moduleInfo == null) {
            withContext(Dispatchers.Main) {
                webUIState.uiEvent = WebUIEvent.Error(activity.getString(R.string.no_such_module, moduleId))
            }
            return@withContext
        }

        if (!moduleInfo.hasWebUi || !moduleInfo.enabled || moduleInfo.update || moduleInfo.remove) {
            withContext(Dispatchers.Main) {
                webUIState.uiEvent = WebUIEvent.Error(activity.getString(R.string.module_unavailable, moduleInfo.name))
            }
            return@withContext
        }

        val shell = try {
            createRootShell(true)
        } catch (error: Exception) {
            if (error is CancellationException) throw error
            withContext(Dispatchers.Main) {
                webUIState.uiEvent = WebUIEvent.Error(error.message ?: activity.getString(R.string.root_install_required))
            }
            return@withContext
        }
        var attached = false
        try {
            withContext(Dispatchers.Main) {
                if (webUIState.isDisposed ||
                    !webUIState.bindModuleSession(activity, moduleId, moduleRevision, ownerScope)) return@withContext
                if (!webUIState.attachRootShell(shell)) return@withContext
                attached = true
                try {
                    webUIState.moduleName = moduleInfo.name
                    webUIState.moduleId = moduleInfo.id
                    webUIState.moduleInfoJson = moduleInfo.webUiInfoJson
                    webUIState.modDir = "/data/adb/modules/${moduleId}"
                    activity.setTaskDescription(activity.getString(R.string.app_name) + " - ${moduleInfo.name}")

                    val webView = WebView(activity)
                    webUIState.webView = webView
                    webView.setBackgroundColor(Color.TRANSPARENT)

                    // P0 配置隔离：A=settings（原名等价）/ B=settings_B / 未判定按 SettingsPrefsPolicy。
                    val prefs = dev.maplesu.manager.workmode.storage.SettingsPrefsRouter(activity).prefs()
                    WebView.setWebContentsDebuggingEnabled(prefs.getBoolean("enable_web_debugging", false))

                    webView.settings.apply {
                        javaScriptEnabled = true
                        domStorageEnabled = true
                        allowFileAccess = false
                    }

                    val webRoot = File("${webUIState.modDir}/webroot")
                    val assetHandler = SuFilePathHandler(
                        activity, webRoot, shell,
                        { webUIState.currentInsets },
                        { enable -> if (webUIState.acceptsPage(webView)) webUIState.isInsetsEnabled = enable },
                        { webUIState.acceptsPage(webView) },
                    )
                    webUIState.assetHandler = assetHandler
                    val webViewAssetLoader = WebViewAssetLoader.Builder()
                        .setDomain("mui.kernelsu.org")
                        .addPathHandler(
                            "/",
                            assetHandler
                        )
                        .build()

                    // WebViewClient
                    webView.webViewClient = object : ModuleWebViewClient(webViewAssetLoader, { uri ->
                        try {
                            activity.startActivity(Intent(Intent.ACTION_VIEW, uri).addCategory(Intent.CATEGORY_BROWSABLE))
                        } catch (_: ActivityNotFoundException) {
                            // Keep the module page open when there is no browser installed.
                        }
                    }, { failedView ->
                        if (webUIState.webView === failedView) {
                            webUIState.requestExit()
                            webUIState.dispose(activity)
                        }
                    }) {
                        override fun shouldInterceptRequest(view: WebView, request: WebResourceRequest): WebResourceResponse? {
                            val url = request.url
                            if (!request.isForMainFrame && url.scheme.equals("ksu", ignoreCase = true) && url.host.equals("icon", ignoreCase = true)) {
                                val packageName = url.path?.substring(1)
                                if (!packageName.isNullOrEmpty()) {
                                    val appInfo = webUIApps()
                                        .find { it.packageName == packageName }
                                        ?.packageInfo?.applicationInfo
                                    if (appInfo != null) {
                                        val icon = AppIconCache.loadIconSync(activity, appInfo.withMainUserUid(activity), 512)
                                        val stream = java.io.ByteArrayOutputStream()
                                        icon.compress(android.graphics.Bitmap.CompressFormat.PNG, 100, stream)
                                        return WebResourceResponse(
                                            "image/png", null, 200, "OK",
                                            mapOf("Access-Control-Allow-Origin" to "*"),
                                            java.io.ByteArrayInputStream(stream.toByteArray())
                                        )
                                    } else {
                                        val errorMsg = "No such package"
                                        val errorStream = java.io.ByteArrayInputStream(errorMsg.toByteArray(Charsets.UTF_8))
                                        return WebResourceResponse(
                                            "text/plain",
                                            "utf-8",
                                            404,
                                            "Not Found",
                                            mapOf("Access-Control-Allow-Origin" to "*"),
                                            errorStream
                                        )
                                    }
                                }
                            }
                            return super.shouldInterceptRequest(view, request)
                        }

                        override fun onPageFinished(view: WebView, url: String?) {
                            super.onPageFinished(view, url)
                            view.evaluateJavascript(loadWebUIDownloadScript(activity), null)
                        }

                        override fun doUpdateVisitedHistory(view: WebView?, url: String?, isReload: Boolean) {
                            webUIState.webCanGoBack = view?.canGoBack() ?: false
                            if (webUIState.isInsetsEnabled) webUIState.webView?.evaluateJavascript(webUIState.currentInsets.js, null)
                            super.doUpdateVisitedHistory(view, url, isReload)
                        }
                    }

                    webView.webChromeClient = moduleWebChromeClient(webUIState)

                    // JS Interface
                    val webviewInterface = WebViewInterface(webUIState)
                    webUIState.downloadBridge = WebUIDownloadInterface(webUIState)
                    webUIState.javascriptBridge = webviewInterface
                    webView.addJavascriptInterface(webviewInterface, "ksu")
                    webView.addJavascriptInterface(webUIState.downloadBridge!!, "ksu_download")
                    webView.setDownloadListener { url, _, _, _, _ ->
                        if (Uri.parse(url).host != BlobDownloadHandler.HOST) webUIState.downloadBridge?.openExternal(url)
                    }
                    webUIState.uiEvent = WebUIEvent.WebViewReady
                } catch (error: Throwable) {
                    webUIState.dispose(activity)
                    throw error
                }
            }
        } finally {
            if (!attached) shell.close()
        }
    }
}

internal fun loadWebUIDownloadScript(context: Context): String =
    context.assets.open("webview/download.js").bufferedReader(Charsets.UTF_8).use { it.readText() }
