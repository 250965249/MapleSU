package com.maplesu.core.ui.component

import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import com.maplesu.core.ui.util.AnnouncementPrefs

/** Remote startup notices are always enabled and acknowledged by content fingerprint. */
@Composable
internal fun T3AnnouncementPopup(content: String?, eligible: Boolean) {
    if (!eligible || content.isNullOrBlank()) return
    val context = LocalContext.current
    val title = "MapleSU 公告"
    val key = remember(content) { AnnouncementPrefs.keyOf(title, content) }
    val shouldShow = remember(key) {
        AnnouncementPrefs.seenKey(context) != key
    }
    var visible by rememberSaveable(key) { mutableStateOf(shouldShow) }
    if (visible) {
        T3NoticeDialog(title = title, content = content, onDismiss = {
            AnnouncementPrefs.markSeen(context, key)
            visible = false
        })
    }
}
