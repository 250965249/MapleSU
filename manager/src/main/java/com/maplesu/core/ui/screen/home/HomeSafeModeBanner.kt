package com.maplesu.core.ui.screen.home

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Security
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.maplesu.core.R
import com.maplesu.core.ui.LocalUiMode
import com.maplesu.core.ui.UiMode
import top.yukonga.miuix.kmp.theme.MiuixTheme

/** Persistent recovery status; the module action stays separate from the announcement. */
@Composable
internal fun HomeSafeModeBanner(
    onManageModules: (() -> Unit)? = null,
    modifier: Modifier = Modifier,
) {
    val miuix = LocalUiMode.current == UiMode.Miuix
    val container = if (miuix) MiuixTheme.colorScheme.errorContainer else MaterialTheme.colorScheme.errorContainer
    val content = if (miuix) MiuixTheme.colorScheme.onErrorContainer else MaterialTheme.colorScheme.onErrorContainer
    val accent = if (miuix) MiuixTheme.colorScheme.error else MaterialTheme.colorScheme.error
    Surface(
        modifier = modifier.fillMaxWidth().semantics { liveRegion = LiveRegionMode.Polite },
        color = container,
        contentColor = content,
        shape = RoundedCornerShape(20.dp),
        border = BorderStroke(1.dp, accent.copy(alpha = 0.2f)),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Icon(Icons.Outlined.Security, contentDescription = null, modifier = Modifier.size(24.dp))
                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text(stringResource(R.string.home_safe_mode_banner_title), fontSize = 16.sp,
                        fontWeight = FontWeight.SemiBold, color = content)
                    Text(stringResource(R.string.home_safe_mode_banner_summary), fontSize = 14.sp,
                        lineHeight = 21.sp, color = content)
                }
            }
            if (onManageModules != null) {
                val buttonModifier = Modifier.align(Alignment.End).heightIn(min = 48.dp)
                if (miuix) {
                    top.yukonga.miuix.kmp.basic.TextButton(
                        text = stringResource(R.string.home_safe_mode_manage_modules),
                        onClick = onManageModules,
                        modifier = buttonModifier,
                    )
                } else {
                    androidx.compose.material3.TextButton(onClick = onManageModules, modifier = buttonModifier) {
                        Text(stringResource(R.string.home_safe_mode_manage_modules), color = content)
                    }
                }
            }
        }
    }
}
