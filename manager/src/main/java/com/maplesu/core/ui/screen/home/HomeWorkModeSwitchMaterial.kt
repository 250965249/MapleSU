package com.maplesu.core.ui.screen.home

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.maplesu.core.R
import dev.maplesu.manager.workmode.ui.WorkModeTargetRow
import dev.maplesu.manager.workmode.ui.workModeNameRes

/**
 * 首页工作模式入口 · Material 皮肤（与 [HomeWorkModeSwitchEntryMiuix] 成对）。
 *
 * 判据同一份 [HomeWorkModeSwitchState]，点击打开选择框；不可用时禁用并在行下说明原因。
 */
@Composable
fun HomeWorkModeSwitchEntryMaterial(
    state: HomeWorkModeSwitchState,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val current = state.current
    if (!state.visible || current == null) return
    Column(modifier = modifier) {
        Box {
            WorkModeTargetRow(
                title = stringResource(R.string.work_mode),
                value = stringResource(workModeNameRes(current)),
                enabled = state.enabled,
                onClick = onClick,
                modifier = Modifier.fillMaxWidth(),
            )
            if (state.blocked == HomeWorkModeSwitchBlock.JAILBREAK_ACTIVE) {
                Box(Modifier.matchParentSize().clickable(onClickLabel =
                    stringResource(R.string.work_mode_jailbreak_blocked), onClick = onClick))
            }
        }
        homeWorkModeSwitchBlockedText(state.blocked)?.let { reason ->
            Text(
                text = reason,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(start = 16.dp, top = 6.dp),
            )
        }
    }
}
