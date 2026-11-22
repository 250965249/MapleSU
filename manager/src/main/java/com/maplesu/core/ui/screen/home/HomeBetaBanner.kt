package com.maplesu.core.ui.screen.home

import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import com.maplesu.core.R
import com.maplesu.core.ui.LocalUiMode
import com.maplesu.core.ui.UiMode
import com.maplesu.core.ui.component.WarningLevel
import com.maplesu.core.ui.component.material.WarningCard as MaterialWarningCard
import com.maplesu.core.ui.component.miuix.WarningCard as MiuixWarningCard

internal const val MAPLESU_FEEDBACK_URL = "https://t.me/MapleSU_Debug_Bot"

@Composable
internal fun HomeBetaBanner(onClick: () -> Unit) {
    val message = stringResource(R.string.home_public_beta_notice)
    val modifier = Modifier.testTag("home_public_beta_banner")
    when (LocalUiMode.current) {
        UiMode.Material -> MaterialWarningCard(message, modifier, WarningLevel.Warning, onClick)
        UiMode.Miuix -> MiuixWarningCard(message, modifier, WarningLevel.Warning, onClick)
    }
}

internal fun openFeedbackInBrowser(context: Context) {
    val intent = Intent(Intent.ACTION_VIEW, Uri.parse(MAPLESU_FEEDBACK_URL)).apply {
        // Resolve the browser category so Telegram's app-link handler does not take over.
        selector = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_APP_BROWSER)
        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    }
    runCatching { context.startActivity(intent) }
}
