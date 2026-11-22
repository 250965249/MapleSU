package com.maplesu.core.ui.webui

import android.annotation.SuppressLint
import android.content.Intent
import android.content.SharedPreferences
import android.os.Bundle
import android.view.WindowManager
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.animation.Crossfade
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.lifecycleScope
import com.maplesu.core.data.repository.SettingsRepositoryImpl
import com.maplesu.core.ui.LocalUiMode
import com.maplesu.core.ui.MainActivity
import com.maplesu.core.ui.UiMode
import com.maplesu.core.ui.navigation3.LocalNavigator
import com.maplesu.core.ui.navigation3.Route
import com.maplesu.core.ui.navigation3.rememberNavigator
import com.maplesu.core.ui.theme.KernelSUTheme
import com.maplesu.core.ui.theme.ThemeController
import dev.maplesu.manager.t3.T3Runtime
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.launch
import top.yukonga.miuix.kmp.basic.InfiniteProgressIndicator

@SuppressLint("SetJavaScriptEnabled")
class WebUIActivity : ComponentActivity() {
    private val t3 by lazy { T3Runtime.get(applicationContext) }
    private val t3Owner = Any()
    private var t3DisableRedirected = false
    private var pageState by mutableStateOf(WebUIState())

    override fun onCreate(savedInstanceState: Bundle?) {

        enableEdgeToEdge()
        window.isNavigationBarContrastEnforced = false
        window.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_NOTHING)

        super.onCreate(savedInstanceState)
        t3.attach(t3Owner)
        lifecycleScope.launch {
            t3.secondsRemaining.collect { seconds ->
                if (seconds == 0) {
                    finishAffinity()
                    finishAndRemoveTask()
                } else if (seconds != null && !t3DisableRedirected) {
                    t3DisableRedirected = true
                    startActivity(Intent(this@WebUIActivity, MainActivity::class.java).addFlags(
                        Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP
                    ))
                }
            }
        }
        if (isFinishing) return

        setContent {
            val context = LocalContext.current
            // 与原生管理器监听同一份共享外观偏好。
            val prefs = com.maplesu.core.ui.util.AppearancePreferences.prefs(context)
            val settingsRepo = remember { SettingsRepositoryImpl() }
            var appSettings by remember { mutableStateOf(ThemeController.getAppSettings()) }
            var uiModeValue by remember { mutableStateOf(settingsRepo.uiMode) }
            val uiMode = remember(uiModeValue) {
                UiMode.fromValue(uiModeValue)
            }

            DisposableEffect(prefs) {
                val listener = SharedPreferences.OnSharedPreferenceChangeListener { _, key ->
                    if (key in listOf("color_mode", "key_color", "color_style", "color_spec", "miuix_monet")) {
                        appSettings = ThemeController.getAppSettings()
                    } else if (key == "ui_mode") {
                        uiModeValue = settingsRepo.uiMode
                        appSettings = ThemeController.getAppSettings()
                    }
                }
                prefs.registerOnSharedPreferenceChangeListener(listener)
                onDispose { prefs.unregisterOnSharedPreferenceChangeListener(listener) }
            }

            val navigator = rememberNavigator(Route.Module)
            CompositionLocalProvider(LocalUiMode provides uiMode, LocalNavigator provides navigator) {
                KernelSUTheme(appSettings = appSettings, uiMode = uiMode) {
                    key(pageState) {
                        MainContent(activity = this, webUIState = pageState, onFinish = { finish() })
                    }
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        pageState.dispose(this)
        setIntent(intent)
        pageState = WebUIState()
    }

    override fun onStart() {
        super.onStart()
        t3.foreground(t3Owner)
    }

    override fun onStop() {
        t3.background(t3Owner)
        super.onStop()
    }

    override fun onDestroy() {
        pageState.dispose(this)
        t3.destroy(t3Owner, isFinishing)
        super.onDestroy()
    }
}

@Composable
private fun MainContent(activity: ComponentActivity, webUIState: WebUIState, onFinish: () -> Unit) {
    val moduleId = remember { activity.intent.data?.getQueryParameter("id") }

    LaunchedEffect(moduleId) {
        if (moduleId == null) {
            onFinish()
            return@LaunchedEffect
        }
        prepareWebView(activity, moduleId, webUIState)
    }

    DisposableEffect(Unit) {
        onDispose { webUIState.dispose(activity) }
    }

    when (val event = webUIState.uiEvent) {
        is WebUIEvent.Error -> {
            LaunchedEffect(event) {
                Toast.makeText(activity, event.message, Toast.LENGTH_SHORT).show()
                onFinish()
            }
        }

        is WebUIEvent.Close -> {
            LaunchedEffect(event) { onFinish() }
        }

        else -> {}
    }
    val isLoading = webUIState.uiEvent is WebUIEvent.Loading

    Crossfade(targetState = isLoading, animationSpec = tween(300)) { loading ->
        if (loading) {
            LoadingContent()
        } else {
            WebUIScreen(webUIState = webUIState)
        }
    }
}

@Composable
private fun LoadingContent() {
    when (LocalUiMode.current) {
        UiMode.Miuix -> {
            Box(
                modifier = Modifier.fillMaxSize(),
                contentAlignment = Alignment.Center
            ) {
                InfiniteProgressIndicator()
            }
        }

        UiMode.Material -> {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .background(MaterialTheme.colorScheme.background),
                contentAlignment = Alignment.Center
            ) {
                androidx.compose.material3.LoadingIndicator()
            }
        }
    }
}
