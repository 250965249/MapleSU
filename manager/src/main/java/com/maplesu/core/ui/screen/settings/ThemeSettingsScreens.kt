package com.maplesu.core.ui.screen.settings

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.res.stringResource
import com.maplesu.core.R
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.maplesu.core.theme.*
import com.maplesu.core.ui.navigation3.LocalNavigator
import com.maplesu.core.ui.util.AppearancePreferences
import com.maplesu.core.ui.util.WallpaperPrefs
import com.maplesu.core.theme.ThemeMusic
import kotlinx.coroutines.launch

@Composable
fun WallpaperScreen() {
    val nav = LocalNavigator.current
    val operations = LocalThemeOperations.current
    val state by operations.state.collectAsStateWithLifecycle()
    val json = ThemeRuntime.observe()
    val context = LocalContext.current
    val prefs = AppearancePreferences.prefs(context)
    WallpaperPrefs.observe()
    val layout = json.optString("homeLayoutStyle", "circle")
    val surfaceSlots = activeSurfaceSlots(json)
    var base by rememberSaveable { mutableStateOf("background") }
    var option by rememberSaveable { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()
    val repo = remember { com.maplesu.core.data.repository.SettingsRepositoryImpl() }
    var saving by remember { mutableStateOf(false) }
    var wallSlot by rememberSaveable { mutableStateOf(com.maplesu.core.ui.util.WallpaperStore.Slot.PORTRAIT) }
    fun saveWall(operation: suspend () -> Unit) {
        if (saving || state.busy) return
        saving = true
        scope.launch {
            try { kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) { operation() } }
            catch (e: kotlinx.coroutines.CancellationException) { throw e }
            catch (e: Exception) { operations.error(e) }
            finally { saving = false }
        }
    }
    val wallPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) {
            val selectedSlot = wallSlot
            val video = context.contentResolver.getType(uri)?.startsWith("video/") == true
            if (selectedSlot == com.maplesu.core.ui.util.WallpaperStore.Slot.PORTRAIT) {
                operations.asset(if (video) "video_background" else "background",uri,if (video) "mp4" else "png",
                    mapOf("isBackgroundEnabled" to true,"isMultiBackgroundEnabled" to false,"isVideoBackgroundEnabled" to video))
            } else saveWall {
                com.maplesu.core.ui.util.WallpaperStore.save(context,uri,isVideo=video,slot=selectedSlot)?.let { error(it) }
            }
        }
    }
    val image = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        if (uri != null) operations.asset(base, uri, "png", when {
            base.startsWith("background_") -> mapOf("isMultiBackgroundEnabled" to true, "isBackgroundEnabled" to true)
            base == "background" -> mapOf("isBackgroundEnabled" to true)
            base == "grid_working_card_background" -> mapOf("isGridWorkingCardBackgroundEnabled" to true)
            base == "dashboard_card_bg" -> mapOf("hasDashboardCardBg" to true, "isDashboardCardBackgroundEnabled" to true)
            else -> mapOf("isFocusCardBackgroundEnabled" to true, "hasFocusCard${base.removePrefix("focus_card_").removeSuffix("_bg").replaceFirstChar(Char::uppercase)}Bg" to true)
        })
    }
    CompositionLocalProvider(LocalThemeBusy provides (state.busy || saving)) {
    ThemePage(stringResource(R.string.theme_wallpaper), { nav.pop() }) { padding ->
        LazyColumn(Modifier.fillMaxSize(), contentPadding = padding, verticalArrangement = Arrangement.spacedBy(12.dp)) {
            item { ThemeText(stringResource(R.string.theme_background), Modifier.padding(horizontal = 20.dp, vertical = 8.dp)) }
            item { ThemeCard(Modifier.padding(horizontal = 12.dp)) {
                ThemeSwitch(stringResource(R.string.theme_background_enabled),json.optBoolean("isBackgroundEnabled",
                    com.maplesu.core.ui.util.WallpaperStore.hasWallpaper(com.maplesu.core.ui.util.rememberWallpaperSlot()))) {
                    operations.edit(mapOf("isBackgroundEnabled" to it))
                }
                listOf(com.maplesu.core.ui.util.WallpaperStore.Slot.PORTRAIT,com.maplesu.core.ui.util.WallpaperStore.Slot.LANDSCAPE).forEach { slot ->
                    val portrait = slot == com.maplesu.core.ui.util.WallpaperStore.Slot.PORTRAIT
                    val kind = com.maplesu.core.ui.util.WallpaperStore.kind(slot)
                    ThemeRow(stringResource(if (portrait) R.string.ui_d_wall_portrait else R.string.ui_d_wall_landscape),
                        stringResource(R.string.theme_wallpaper_picker_summary),Icons.Rounded.Wallpaper) {
                        wallSlot=slot; wallPicker.launch(arrayOf("image/*","video/*"))
                    }
                    if (kind != "none") ThemeButton(stringResource(if (portrait) R.string.ui_d_wallpaper_remove else R.string.ui_d_wallpaper_remove_land)) {
                        if (portrait && ThemeRuntime.file(context,if (kind == "video") "video_background" else "background") != null) {
                            operations.clearAsset(if (kind == "video") "video_background" else "background",
                                mapOf("isBackgroundEnabled" to false,"isVideoBackgroundEnabled" to false))
                        } else saveWall { com.maplesu.core.ui.util.WallpaperStore.clear(slot) }
                    }
                }
                ThemeSwitch(stringResource(R.string.ui_d_translucent),repo.uiTranslucent,
                    summary=stringResource(R.string.ui_d_translucent_summary)) { repo.uiTranslucent=it }
                ThemeSwitch(stringResource(R.string.theme_wallpaper_color),prefs.getBoolean("wallpaper_seed",false)) {
                    operations.edit(mapOf("wallpaper_use_color" to it))
                }
                ThemeSwitch(stringResource(R.string.theme_background_per_page),json.optBoolean("isMultiBackgroundEnabled")) {
                    operations.edit(mapOf("isMultiBackgroundEnabled" to it))
                }
                if (json.optBoolean("isMultiBackgroundEnabled")) {
                    listOf("background_home" to stringResource(R.string.theme_page_home),"background_superuser" to stringResource(R.string.theme_page_superuser),
                        "background_system_module" to stringResource(R.string.theme_page_module),"background_settings" to stringResource(R.string.theme_page_settings)).forEach { (slot,title) ->
                        ThemeRow(title,stringResource(R.string.theme_pick_image_gif),Icons.Rounded.Image) { base=slot; image.launch("image/*") }
                        if (ThemeRuntime.file(context,slot) != null) ThemeButton(stringResource(R.string.theme_remove_named_background,title)) {
                            operations.clearAsset(slot)
                        }
                    }
                }
                ThemeSlider(stringResource(R.string.theme_background_blur), prefs.getFloat("wallpaper_blur",0f), 0f..100f, !state.busy) { operations.edit(mapOf("backgroundBlur" to it)) }
                ThemeSlider(stringResource(R.string.theme_background_dim), prefs.getFloat("wallpaper_dim",.35f), enabled = !state.busy) { operations.edit(mapOf("backgroundDim" to it)) }
                ThemeSlider(stringResource(R.string.theme_interface_opacity), prefs.getFloat("ui_translucent_alpha",.5f), enabled = !state.busy) { operations.edit(mapOf("backgroundOpacity" to it)) }
                if (json.optBoolean("isVideoBackgroundEnabled")) ThemeSlider(stringResource(R.string.theme_video_volume),
                    json.optDouble("videoVolume",0.0).toFloat()) { operations.edit(mapOf("videoVolume" to it)) }
                ThemeSwitch(stringResource(R.string.theme_background_dual_dim), json.optBoolean("isDualBackgroundDimEnabled"), !state.busy) { operations.edit(mapOf("isDualBackgroundDimEnabled" to it)) }
                if (json.optBoolean("isDualBackgroundDimEnabled")) {
                    ThemeSlider(stringResource(R.string.theme_background_day_dim), json.optDouble("backgroundDayDim", .2).toFloat()) { operations.edit(mapOf("backgroundDayDim" to it)) }
                    ThemeSlider(stringResource(R.string.theme_background_night_dim), json.optDouble("backgroundNightDim", .2).toFloat()) { operations.edit(mapOf("backgroundNightDim" to it)) }
                }
            } }
            item { ThemeText(stringResource(R.string.theme_layout_background, layoutName(layout)), Modifier.padding(horizontal = 20.dp, vertical = 8.dp)) }
            item { ThemeCard(Modifier.padding(horizontal = 12.dp)) {
                if (layout == "focus") ThemeSwitch(stringResource(R.string.theme_focus_background_enabled), json.optBoolean("isFocusCardBackgroundEnabled")) {
                    operations.edit(mapOf("isFocusCardBackgroundEnabled" to it))
                }
                surfaceSlots.forEach { (slot,title) ->
                    ThemeRow(title, stringResource(R.string.theme_surface_summary), Icons.Rounded.CropOriginal, !state.busy) { base = slot; option = slot }
                }
                if (surfaceSlots.isEmpty()) ThemeText(stringResource(R.string.theme_surface_empty), Modifier.padding(16.dp), true)
            } }
            item { if (state.busy) Row(Modifier.padding(20.dp), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                ThemeProgress(); ThemeText(stringResource(R.string.theme_busy))
            }; Spacer(Modifier.windowInsetsBottomHeight(WindowInsets.safeDrawing).heightIn(min = 24.dp)) }
        }
    }
    option?.let { slot ->
        val grid = slot == "grid_working_card_background"
        val focus = slot.startsWith("focus_")
        val prefix = if (grid) "gridWorkingCardBackground" else if (focus) "focusCardBg" else "dashboardCardBg"
        val toggle = if (grid) "isGridWorkingCardBackgroundEnabled" else if (focus)
            "hasFocusCard${slot.removePrefix("focus_card_").removeSuffix("_bg").replaceFirstChar(Char::uppercase)}Bg" else "isDashboardCardBackgroundEnabled"
        val dual = if (grid) "isGridDualOpacityEnabled" else if (focus) "isFocusCardDualOpacityEnabled" else "isDashboardCardDualOpacityEnabled"
        val dualDim = if (grid) "isGridDualDimEnabled" else if (focus) "isFocusCardDualDimEnabled" else "isDashboardCardDualDimEnabled"
        ThemeDialog(stringResource(R.string.theme_surface_title), { option = null }, onConfirm = { option = null }) {
            if (ThemeRuntime.file(context,slot) != null) ThemeButton(stringResource(R.string.theme_remove_background)) {
                val changes = when {
                    grid -> mapOf("isGridWorkingCardBackgroundEnabled" to false)
                    focus -> mapOf(toggle to false)
                    else -> mapOf("hasDashboardCardBg" to false,"isDashboardCardBackgroundEnabled" to false)
                }
                option = null; operations.clearAsset(slot,changes)
            }
            ThemeButton(stringResource(R.string.theme_pick_image)) { option = null; image.launch("image/*") }
            ThemeSwitch(stringResource(R.string.theme_enabled), ThemeAliases.boolean(json,toggle, if (grid || !focus) false else true)) { operations.edit(mapOf(toggle to it)) }
            ThemeSwitch(stringResource(R.string.theme_dual_opacity), ThemeAliases.boolean(json,dual)) { operations.edit(mapOf(dual to it)) }
            if (json.optBoolean(dual)) listOf("DayOpacity" to stringResource(R.string.theme_day), "NightOpacity" to stringResource(R.string.theme_night)).forEach { (field,label) ->
                ThemeSlider(stringResource(R.string.theme_named_opacity, label), ThemeAliases.number(json,prefix+field,1.0)) { operations.edit(mapOf(prefix+field to it)) }
            } else ThemeSlider(stringResource(R.string.theme_opacity), ThemeAliases.number(json,prefix+"Opacity",1.0)) { operations.edit(mapOf(prefix+"Opacity" to it)) }
            ThemeSwitch(stringResource(R.string.theme_dual_dim), ThemeAliases.boolean(json,dualDim)) { operations.edit(mapOf(dualDim to it)) }
            if (json.optBoolean(dualDim)) listOf("DayDim" to stringResource(R.string.theme_day), "NightDim" to stringResource(R.string.theme_night)).forEach { (field,label) ->
                ThemeSlider(stringResource(R.string.theme_named_dim, label), ThemeAliases.number(json,prefix+field,.3)) { operations.edit(mapOf(prefix+field to it)) }
            } else ThemeSlider(stringResource(R.string.theme_dim), ThemeAliases.number(json,prefix+"Dim",.3)) { operations.edit(mapOf(prefix+"Dim" to it)) }
            if (grid) {
                ThemeSwitch(stringResource(R.string.theme_hide_icon),ThemeAliases.boolean(json,"isGridWorkingCardCheckHidden")) { operations.edit(mapOf("isGridWorkingCardCheckHidden" to it)) }
                ThemeSwitch(stringResource(R.string.theme_hide_text),ThemeAliases.boolean(json,"isGridWorkingCardTextHidden")) { operations.edit(mapOf("isGridWorkingCardTextHidden" to it)) }
                ThemeSwitch(stringResource(R.string.theme_hide_mode),ThemeAliases.boolean(json,"isGridWorkingCardModeHidden")) { operations.edit(mapOf("isGridWorkingCardModeHidden" to it)) }
            }
        }
    }
    }
}

@Composable
private fun layoutName(layout: String) = when (layout) {
    "kernelsu" -> stringResource(R.string.theme_layout_grid)
    "focus" -> stringResource(R.string.theme_layout_focus)
    "dashboard_ui" -> stringResource(R.string.theme_layout_dashboard)
    "stats" -> stringResource(R.string.theme_layout_stats)
    else -> stringResource(R.string.theme_layout_circle)
}

@Composable
private fun activeSurfaceSlots(j: org.json.JSONObject): List<Pair<String,String>> = when (j.optString("homeLayoutStyle","circle")) {
    "kernelsu" -> listOf("grid_working_card_background" to stringResource(R.string.theme_surface_grid))
    "focus" -> listOf("focus_card_kernel_bg" to stringResource(R.string.theme_surface_focus_kernel))
    "dashboard_ui" -> listOf("dashboard_card_bg" to stringResource(R.string.theme_surface_dashboard))
    "stats" -> if (j.optString("statsTopLayout") == "grid") listOf("grid_working_card_background" to stringResource(R.string.theme_surface_stats_grid)) else emptyList()
    else -> emptyList()
}

@Composable
private fun baseLabel(base: String) = when (base) {
    "title_image" -> stringResource(R.string.theme_title_image)
    "video_background" -> stringResource(R.string.theme_video)
    "theme_music" -> stringResource(R.string.theme_music)
    else -> stringResource(R.string.theme_sound)
}

@Composable
internal fun ThemeMetadataDialog(initial: ThemeMetadata, dismiss: () -> Unit, confirm: (ThemeMetadata) -> Unit) {
    var name by rememberSaveable { mutableStateOf(initial.name) }; var type by rememberSaveable { mutableStateOf(initial.type) }
    var version by rememberSaveable { mutableStateOf(initial.version) }; var author by rememberSaveable { mutableStateOf(initial.author) }
    var description by rememberSaveable { mutableStateOf(initial.description) }
    ThemeDialog(stringResource(R.string.theme_package_export), dismiss, stringResource(R.string.theme_export), enabled = name.isNotBlank() && version.isNotBlank() && name.length <= 80 && version.length <= 32, onConfirm = { confirm(ThemeMetadata(name.trim(),type,version.trim(),author.trim().take(80),description.trim().take(2000))) }) {
        ThemeInput(stringResource(R.string.theme_name),name) { name = it }; ThemeInput(stringResource(R.string.theme_version),version) { version = it }
        ThemeInput(stringResource(R.string.theme_author),author) { author = it }; ThemeInput(stringResource(R.string.theme_description),description) { description = it }
        FlowRow { ThemeButton(if (type == "phone") "✓ " + stringResource(R.string.theme_phone) else stringResource(R.string.theme_phone)) { type = "phone" }; ThemeButton(if (type == "tablet") "✓ " + stringResource(R.string.theme_tablet) else stringResource(R.string.theme_tablet)) { type = "tablet" } }
    }
}

@Composable
fun ThemeFontScreen() {
    val nav = LocalNavigator.current; val operations = LocalThemeOperations.current
    val j = ThemeRuntime.observe()
    val context = LocalContext.current
    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) operations.asset("font",uri,"ttf",mapOf("fontMode" to "custom", "isFontEnabled" to true))
    }
    ThemePage(stringResource(R.string.theme_font), { nav.pop() }) { padding ->
        Column(Modifier.fillMaxSize().padding(padding).verticalScroll(rememberScrollState()).padding(12.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            ThemeCard { listOf("app" to stringResource(R.string.theme_font_app), "system" to stringResource(R.string.theme_font_system), "custom" to stringResource(R.string.theme_font_custom)).forEach { (mode,title) ->
                ThemeRow((if (j.optString("fontMode","app") == mode) "✓ " else "")+title, if (mode == "custom") "TTF / OTF" else "", Icons.Rounded.FontDownload) {
                    if (mode == "custom") picker.launch(arrayOf("*/*")) else operations.edit(mapOf("fontMode" to mode,"isFontEnabled" to false))
                }
            } }
            if (ThemeRuntime.file(context,"font") != null) ThemeButton(stringResource(R.string.theme_font_remove)) {
                operations.clearAsset("font",mapOf("fontMode" to "app","isFontEnabled" to false))
            }
            ThemeText(stringResource(R.string.theme_font_preview), Modifier.padding(16.dp))
        }
    }
}

@Composable
fun ThemeLayoutScreen() {
    val nav = LocalNavigator.current; val operations = LocalThemeOperations.current; val j = ThemeRuntime.observe()
    val layout = com.maplesu.core.ui.screen.home.rememberThemeHomeLayout()
    ThemePage(stringResource(R.string.theme_layout_title), { nav.pop() }) { padding ->
        LazyColumn(Modifier.fillMaxSize(), contentPadding = padding, verticalArrangement = Arrangement.spacedBy(12.dp)) {
            item { ThemeCard(Modifier.padding(12.dp)) {
                listOf(ThemeHomeLayout.Large to stringResource(R.string.theme_home_large),
                    ThemeHomeLayout.Small to stringResource(R.string.theme_home_small),
                    ThemeHomeLayout.Three to stringResource(R.string.theme_home_three)).forEach { (value,title) ->
                    ThemeChoice(title,layout == value) { operations.homeLayout(value) }
                }
                ThemeText(stringResource(R.string.theme_home_layout_scope),Modifier.padding(16.dp),secondary=true)
            } }
            item { ThemeCard(Modifier.padding(horizontal=12.dp)) {
                ThemeSwitch(stringResource(R.string.theme_list_hide_mode), j.optBoolean("isListWorkingCardModeHidden")) { operations.edit(mapOf("isListWorkingCardModeHidden" to it)) }
            } }
            item { Spacer(Modifier.windowInsetsBottomHeight(WindowInsets.safeDrawing)) }
        }
    }
}

@Composable
fun ThemeMediaScreen() {
    val nav = LocalNavigator.current; val operations = LocalThemeOperations.current; val j = ThemeRuntime.observe()
    val context = LocalContext.current
    val generation = ThemeRuntime.generation(context)?.name
    var titleMode by rememberSaveable(generation) { mutableStateOf(j.optString("titleTextMode","default")) }
    var titleText by rememberSaveable(generation) { mutableStateOf(j.optString("titleCustomText")) }
    var slot by rememberSaveable { mutableStateOf("title_image") }
    val pick = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri -> if (uri != null) {
        val (ext,changes) = when (slot) {
            "title_image" -> "png" to mapOf("isAdvancedTitleStyleEnabled" to true)
            "theme_music" -> "mp3" to mapOf("isMusicEnabled" to true,"musicFilename" to "theme_music.mp3")
            else -> "wav" to mapOf("isSoundEffectEnabled" to true,"soundEffectFilename" to "theme_sound.wav")
        }; operations.asset(slot,uri,ext,changes)
    } }
    ThemePage(stringResource(R.string.theme_media_title), { nav.pop() }) { padding ->
        LazyColumn(Modifier.fillMaxSize(), contentPadding = padding, verticalArrangement = Arrangement.spacedBy(12.dp)) {
            item { ThemeCard(Modifier.padding(12.dp)) {
                listOf(Triple("title_image",stringResource(R.string.theme_title_image_gif),"image/*"),
                    Triple("theme_music",stringResource(R.string.theme_music),"audio/*"),Triple("theme_sound",stringResource(R.string.theme_sound),"audio/*")).forEach { (base,title,mime) ->
                    ThemeRow(title, stringResource(R.string.theme_pick_file), Icons.Rounded.AttachFile) { slot = base; pick.launch(mime) }
                }
                listOf("isAdvancedTitleStyleEnabled" to stringResource(R.string.theme_title_advanced),
                    "isMusicEnabled" to stringResource(R.string.theme_music), "isAutoPlayEnabled" to stringResource(R.string.theme_music_autoplay), "isLoopingEnabled" to stringResource(R.string.theme_music_loop), "isSoundEffectEnabled" to stringResource(R.string.theme_sound)).forEach { (key,title) ->
                    ThemeSwitch(title,j.optBoolean(key)) { operations.edit(mapOf(key to it)) }
                }
                ThemeRow(stringResource(R.string.theme_title_text), when(titleMode) { "kernelsu" -> "KernelSU"; "custom" -> stringResource(R.string.theme_custom); else -> "MapleSU" }, Icons.Rounded.Title) {
                    titleMode = when(titleMode) { "default" -> "kernelsu"; "kernelsu" -> "custom"; else -> "default" }
                    operations.edit(mapOf("titleTextMode" to titleMode))
                }
                if (titleMode == "custom") {
                    ThemeInput(stringResource(R.string.theme_title_custom),titleText) { titleText = it }
                    ThemeButton(stringResource(R.string.theme_title_save)) { operations.edit(mapOf("titleCustomText" to titleText.take(80))) }
                }
                if (j.optBoolean("isMusicEnabled") && ThemeRuntime.namedFile(com.maplesu.core.ksuApp,j.optString("musicFilename")) != null)
                    ThemeButton(if (ThemeMusic.playing) stringResource(R.string.theme_music_pause) else stringResource(R.string.theme_music_play)) { ThemeMusic.toggle() }
                listOf("title_image" to "isAdvancedTitleStyleEnabled",
                    "theme_music" to "isMusicEnabled", "theme_sound" to "isSoundEffectEnabled").forEach { (base,key) ->
                    if (ThemeRuntime.file(com.maplesu.core.ksuApp,base) != null) ThemeButton(stringResource(R.string.theme_remove_asset, baseLabel(base))) {
                        operations.clearAsset(base,mapOf(key to false))
                    }
                }
                ThemeSwitch(stringResource(R.string.theme_sound_bottom_bar),j.optString("soundEffectScope") == "bottom_bar") { operations.edit(mapOf("soundEffectScope" to if(it) "bottom_bar" else "global")) }
                listOf("musicVolume" to stringResource(R.string.theme_music_volume), "titleImageDayOpacity" to stringResource(R.string.theme_title_day_opacity),
                    "titleImageNightOpacity" to stringResource(R.string.theme_title_night_opacity), "titleImageDim" to stringResource(R.string.theme_title_dim)).forEach { (key,title) ->
                    ThemeSlider(title,j.optDouble(key,if(key.endsWith("Opacity") || key == "musicVolume") 1.0 else 0.0).toFloat()) { operations.edit(mapOf(key to it)) }
                }
                ThemeSlider(stringResource(R.string.theme_title_offset),j.optDouble("titleImageOffsetX",0.0).toFloat(),-2f..2f) { operations.edit(mapOf("titleImageOffsetX" to it)) }
            } }
            item { Spacer(Modifier.windowInsetsBottomHeight(WindowInsets.safeDrawing)) }
        }
    }
}

@Composable
internal fun ThemeColorOptions() {
    val j = ThemeRuntime.observe()
    val operations = LocalThemeOperations.current
    ThemeCard(Modifier.fillMaxWidth().padding(horizontal=12.dp)) {
        ThemeRow(stringResource(R.string.theme_color_generation),j.optString("colorGenerationMode","custom"),Icons.Rounded.Palette) {
            operations.edit(mapOf("colorGenerationMode" to if (j.optString("colorGenerationMode","custom") == "classic") "custom" else "classic"))
        }
        ThemeRow(stringResource(R.string.theme_color_contrast),j.optString("colorContrast","STANDARD"),Icons.Rounded.Contrast) {
            val values = listOf("STANDARD","MEDIUM","HIGH")
            operations.edit(mapOf("colorContrast" to values[(values.indexOf(j.optString("colorContrast","STANDARD"))+1)%values.size]))
        }
    }
}
