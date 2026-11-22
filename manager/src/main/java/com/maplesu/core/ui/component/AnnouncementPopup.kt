package com.maplesu.core.ui.component

import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.maplesu.core.ui.LocalUiMode
import com.maplesu.core.ui.UiMode
import com.maplesu.core.ui.component.maple.hidesModeInfo
import com.maplesu.core.ui.component.maple.homeUltraBrandFacts
import com.maplesu.core.ui.screen.home.ANNOUNCEMENT_TEXT
import com.maplesu.core.ui.screen.home.ANNOUNCEMENT_TITLE
import com.maplesu.core.ui.screen.home.AboutMapleDialogMaterial
import com.maplesu.core.ui.screen.home.AboutMapleDialogMiuix
import com.maplesu.core.ui.util.AnnouncementPrefs
import com.maplesu.core.ui.viewmodel.HomeViewModel

/** 冷启动按公告内容指纹提示一次；确认或取消后记录已读，两套主题共用规则。 */
@Composable
fun AnnouncementPopup(freshStart: Boolean) {
    if (!freshStart) return

    val context = LocalContext.current

    // 指纹只算一次（remember）：重组不重复计算
    val key = remember { AnnouncementPrefs.keyOf(ANNOUNCEMENT_TITLE, ANNOUNCEMENT_TEXT) }
    val shouldShow = remember {
        AnnouncementPrefs.seenKey(context) != key
    }
    if (!shouldShow) return
    var show by rememberSaveable(key) { mutableStateOf(shouldShow) }

    val viewModel = viewModel<HomeViewModel>()
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
    val entryFacts by viewModel.entryFacts.collectAsStateWithLifecycle()
    val hiddenConfirming = uiState.hiddenConfirming || entryFacts.hidden.confirming
    val suppressEntries = entryFacts.hidden.suppressEntries || uiState.hiddenConfirming
    val brandFacts = homeUltraBrandFacts(
        workModeSwitch = entryFacts.workModeSwitch,
        liteHiddenMasking = entryFacts.hidden.masking,
        hiddenConfirming = hiddenConfirming,
    )
    val showModes = !suppressEntries && !hidesModeInfo(brandFacts)
    val onDismiss = {
        AnnouncementPrefs.markSeen(context, key)
        show = false
    }

    when (LocalUiMode.current) {
        UiMode.Miuix -> AboutMapleDialogMiuix(show = show, showModes = showModes, onDismiss = onDismiss)
        UiMode.Material -> if (show) AboutMapleDialogMaterial(showModes = showModes, onDismiss = onDismiss)
    }
}
