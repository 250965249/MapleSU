package com.maplesu.core.ui.screen.settings

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Restore
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.res.stringResource
import com.maplesu.core.R
import com.maplesu.core.ui.LocalUiMode
import com.maplesu.core.ui.UiMode

/** Changes stay local until the native confirmation button is pressed. */
@Composable
internal fun ThemeResetPreference(onReset: (Boolean) -> Unit) {
    var show by rememberSaveable { mutableStateOf(false) }
    var comic by rememberSaveable { mutableStateOf(false) }
    ThemeRow(stringResource(R.string.theme_reset),stringResource(R.string.theme_reset_summary),Icons.Rounded.Restore) {
        comic = false
        show = true
    }
    if (show) ThemeDialog(stringResource(R.string.theme_reset_question), { show = false },
        confirm=stringResource(R.string.theme_reset_confirm),onConfirm={ show=false; onReset(comic) }) {
        ThemeText(stringResource(R.string.theme_reset_message))
        when (LocalUiMode.current) {
            UiMode.Miuix -> top.yukonga.miuix.kmp.preference.CheckboxPreference(
                title=stringResource(R.string.theme_reset_comic),summary=stringResource(R.string.theme_reset_comic_summary),
                checked=comic,onCheckedChange={ comic=it })
            UiMode.Material -> com.maplesu.core.ui.component.material.SegmentedCheckboxItem(
                title=stringResource(R.string.theme_reset_comic),summary=stringResource(R.string.theme_reset_comic_summary),
                checked=comic,onCheckedChange={ comic=it })
        }
    }
}
