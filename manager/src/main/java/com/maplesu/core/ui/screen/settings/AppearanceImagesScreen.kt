package com.maplesu.core.ui.screen.settings

import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.ArrowBack
import androidx.compose.material.icons.rounded.*
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.LargeFlexibleTopAppBar
import androidx.compose.material3.Text as MaterialText
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.maplesu.core.R
import com.maplesu.core.data.repository.SettingsRepositoryImpl
import com.maplesu.core.ui.LocalUiMode
import com.maplesu.core.ui.UiMode
import com.maplesu.core.ui.component.material.ExpressiveScaffold
import com.maplesu.core.ui.component.material.SegmentedColumn
import com.maplesu.core.ui.component.material.SegmentedListItem
import com.maplesu.core.ui.component.material.SegmentedSwitchItem
import com.maplesu.core.ui.component.material.TopBarBackButton
import com.maplesu.core.ui.component.material.expressiveTopAppBarColors
import com.maplesu.core.ui.navigation3.LocalNavigator
import com.maplesu.core.ui.screen.host.HiddenFlowText
import com.maplesu.core.ui.util.NavIcons
import com.maplesu.core.ui.util.AppearancePrefsPolicy
import com.maplesu.core.ui.util.WallpaperPrefs
import com.maplesu.core.ui.util.StatusDecoration
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.IconButton
import top.yukonga.miuix.kmp.basic.Scaffold
import top.yukonga.miuix.kmp.basic.TopAppBar
import top.yukonga.miuix.kmp.preference.ArrowPreference
import top.yukonga.miuix.kmp.preference.SwitchPreference
import top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme

private data class ImagesSnapshot(
    val decorationSource: String = AppearancePrefsPolicy.DECORATION_CHECK,
    val circle: Boolean = false,
    val navIcons: Set<String> = emptySet(),
    val anchor: Int = 0, val dim: Float = .35f, val zoom: Float = 1f, val hideText: Boolean = false,
)

/** Two native skins share image selection, save state and background IO. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppearanceImagesScreen() {
    val navigator = LocalNavigator.current
    val context = LocalContext.current
    val skin = LocalUiMode.current
    val prefsRepo = remember { SettingsRepositoryImpl() }
    val scope = rememberCoroutineScope()
    var snapshot by remember { mutableStateOf(ImagesSnapshot()) }
    var loaded by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var pendingNavKey by rememberSaveable { mutableStateOf<String?>(null) }
    var crop by rememberSaveable { mutableStateOf(false) }
    var revision by remember { mutableIntStateOf(0) }
    val appearanceRevision = WallpaperPrefs.observe()

    suspend fun readSnapshot(): ImagesSnapshot = withContext(Dispatchers.IO) {
        ImagesSnapshot(
            decorationSource = StatusDecoration.source(context),
            circle = prefsRepo.navIconCircle,
            navIcons = NavIcons.keys.filterTo(LinkedHashSet()) { NavIcons.has(context, it) },
            anchor = prefsRepo.statusDecorationAnchor, dim = prefsRepo.statusDecorationDim,
            zoom = prefsRepo.statusDecorationZoom, hideText = prefsRepo.statusDecorationHideText,
        )
    }
    LaunchedEffect(skin, revision, appearanceRevision, StatusDecoration.version, NavIcons.version) {
        snapshot = readSnapshot()
        loaded = true
    }
    fun save(operation: suspend () -> Boolean) {
        if (busy) return
        busy = true
        scope.launch {
            val ok = withContext(Dispatchers.IO) {
                try { operation() }
                catch (e: kotlinx.coroutines.CancellationException) { throw e }
                catch (_: Exception) { false }
            }
            snapshot = readSnapshot()
            busy = false
            revision++
            if (!ok) Toast.makeText(context, R.string.ui_d_image_unreadable, Toast.LENGTH_LONG).show()
        }
    }
    val pickDecoration = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        if (uri != null) save { StatusDecoration.save(context, uri) }
    }
    val pickNavIcon = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        val key = pendingNavKey
        pendingNavKey = null
        if (uri != null && key != null) save { NavIcons.save(context, key, uri) }
    }
    val enabled = loaded && !busy
    val navEntries = listOf(
        Triple("home", R.string.ui_d_nav_home, Icons.Rounded.Home),
        Triple("superuser", R.string.ui_d_nav_superuser, Icons.Rounded.Security),
        Triple("module", R.string.ui_d_nav_module, Icons.Rounded.Apps),
        Triple("setting", R.string.ui_d_nav_settings, Icons.Rounded.DisplaySettings),
    )
    val rows = buildList<@Composable () -> Unit> {
        add {
            ThemeDropdown(stringResource(R.string.ui_d_decoration),listOf(
                stringResource(R.string.ui_d_decoration_check),stringResource(R.string.ui_d_decoration_comic),
                stringResource(R.string.ui_d_decoration_custom)),when (snapshot.decorationSource) {
                    AppearancePrefsPolicy.DECORATION_COMIC -> 1
                    AppearancePrefsPolicy.DECORATION_CUSTOM -> 2
                    else -> 0
                }) { index ->
                    if (index == 2) pickDecoration.launch("image/*")
                    else save {
                        com.maplesu.core.ui.util.AppearancePreferences.prefs(context).edit().putString(
                            AppearancePrefsPolicy.DECORATION_SOURCE,if (index == 1) AppearancePrefsPolicy.DECORATION_COMIC else AppearancePrefsPolicy.DECORATION_CHECK).apply()
                        true
                    }
                }
        }
        if (snapshot.decorationSource == AppearancePrefsPolicy.DECORATION_CUSTOM) add {
            ImagePreference(stringResource(R.string.ui_d_decoration_custom),"",Icons.Rounded.Image,enabled) { pickDecoration.launch("image/*") }
        }
        if (snapshot.decorationSource != AppearancePrefsPolicy.DECORATION_CHECK) {
            add { ThemeDropdown(stringResource(R.string.ui_d_decoration_crop),
                androidx.compose.ui.res.stringArrayResource(R.array.ui_d_decoration_anchors).toList(),snapshot.anchor.coerceIn(0,3)) { value ->
                if (value == 3) crop=true else save { prefsRepo.statusDecorationAnchor=value; true }
            } }
            add { ThemeSlider(stringResource(R.string.ui_d_decoration_zoom),snapshot.zoom,1f..4f,enabled) { value ->
                save { prefsRepo.statusDecorationZoom=value; true }
            } }
            add { ThemeSlider(stringResource(R.string.ui_d_decoration_dim),snapshot.dim,enabled=enabled) { value ->
                save { prefsRepo.statusDecorationDim=value; true }
            } }
            add { ThemeSwitch(stringResource(R.string.ui_d_decoration_only),snapshot.hideText,enabled,
                summary=stringResource(R.string.ui_d_decoration_only_summary)) { value -> save { prefsRepo.statusDecorationHideText=value; true } } }
        }
        navEntries.forEach { (key, titleRes, icon) ->
            add {
                ImagePreference(stringResource(R.string.ui_d_nav_icon, stringResource(titleRes)),
                    stringResource(if (key in snapshot.navIcons) R.string.ui_d_decoration_custom else R.string.ui_d_nav_default),
                    icon, enabled) { pendingNavKey = key; pickNavIcon.launch("image/*") }
            }
        }
        add {
            when (LocalUiMode.current) {
                UiMode.Miuix -> SwitchPreference(
                    title = stringResource(R.string.ui_d_nav_circle), summary = stringResource(R.string.ui_d_nav_circle_summary),
                    checked = snapshot.circle, enabled = enabled,
                    onCheckedChange = { value ->
                        snapshot = snapshot.copy(circle = value)
                        save { prefsRepo.navIconCircle = value; true }
                    },
                )
                UiMode.Material -> SegmentedSwitchItem(
                    icon = Icons.Rounded.Image, title = stringResource(R.string.ui_d_nav_circle),
                    summary = stringResource(R.string.ui_d_nav_circle_summary), checked = snapshot.circle, enabled = enabled,
                    onCheckedChange = { value ->
                        snapshot = snapshot.copy(circle = value)
                        save { prefsRepo.navIconCircle = value; true }
                    },
                )
            }
        }
        add {
            ImagePreference(stringResource(R.string.ui_d_nav_reset), stringResource(R.string.ui_d_nav_reset_summary),
                Icons.Rounded.Restore, enabled && snapshot.navIcons.isNotEmpty()) {
                save { NavIcons.clearAll(context); true }
            }
        }
    }
    val status: @Composable () -> Unit = {
        Box(Modifier.fillMaxWidth().heightIn(min = 32.dp).padding(horizontal = 20.dp)) {
            if (busy || !loaded) HiddenFlowText(stringResource(if (busy) R.string.ui_polish_images_busy else R.string.ui_polish_images_loading), secondary = true)
        }
    }
    if (crop) com.maplesu.core.ui.component.material.DecorationCropDialog({ crop=false }) { x,y,zoom ->
        crop=false
        save {
            prefsRepo.statusDecorationAnchor=3; prefsRepo.statusDecorationBiasX=x; prefsRepo.statusDecorationBiasY=y
            prefsRepo.statusDecorationZoom=zoom; true
        }
    }
    CompositionLocalProvider(LocalThemeBusy provides (LocalThemeBusy.current || !enabled)) {
    when (LocalUiMode.current) {
        UiMode.Miuix -> Scaffold(
            topBar = {
                TopAppBar(title = stringResource(R.string.ui_d_custom_images), color = colorScheme.surface,
                    navigationIcon = {
                        IconButton(onClick = { navigator.pop() }) {
                            Icon(Icons.AutoMirrored.Rounded.ArrowBack, stringResource(R.string.ui_d_back), tint = colorScheme.onSurface)
                        }
                    })
            }, popupHost = { },
            contentWindowInsets = WindowInsets.safeDrawing.only(WindowInsetsSides.Horizontal),
        ) { padding ->
            LazyColumn(Modifier.fillMaxSize(), contentPadding = padding) {
                item { status() }
                item {
                    Card(Modifier.fillMaxWidth().padding(horizontal = 12.dp)) { rows.forEach { it() } }
                }
                item { Spacer(Modifier.windowInsetsBottomHeight(WindowInsets.safeDrawing).heightIn(min = 16.dp)) }
            }
        }
        UiMode.Material -> ExpressiveScaffold(
            topBar = {
                LargeFlexibleTopAppBar(title = { MaterialText(stringResource(R.string.ui_d_custom_images)) },
                    navigationIcon = { TopBarBackButton(onClick = { navigator.pop() }) }, colors = expressiveTopAppBarColors())
            },
            contentWindowInsets = WindowInsets.safeDrawing,
        ) { padding ->
            LazyColumn(Modifier.fillMaxSize().padding(padding)) {
                item { status() }
                item { SegmentedColumn(Modifier.padding(horizontal = 16.dp), content = rows) }
                item { Spacer(Modifier.height(24.dp)) }
            }
        }
    }
    }
}

@Composable
private fun ImagePreference(title: String, summary: String, icon: androidx.compose.ui.graphics.vector.ImageVector,
    enabled: Boolean, onClick: () -> Unit) {
    when (LocalUiMode.current) {
        UiMode.Miuix -> ArrowPreference(title = title, summary = summary, enabled = enabled, onClick = onClick,
            startAction = { Icon(icon, null, Modifier.padding(end = 12.dp), tint = colorScheme.onSurface) })
        UiMode.Material -> SegmentedListItem(onClick = onClick, enabled = enabled,
            headlineContent = { MaterialText(title) }, supportingContent = { MaterialText(summary) },
            leadingContent = { androidx.compose.material3.Icon(icon, null) })
    }
}
