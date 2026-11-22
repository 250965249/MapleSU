package com.maplesu.core.ui.screen.settings

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.node.Ref
import androidx.compose.ui.res.stringResource
import com.maplesu.core.R
import com.maplesu.core.ui.component.WarningLevel
import com.maplesu.core.ui.component.dialog.rememberConfirmDialog
import com.maplesu.core.ui.component.miuix.WarningCard
import dev.maplesu.manager.runtime.ultra.UltraEnvUpgrade

/**
 * 首页「发现 Ultra 环境更新」卡 · Miuix。写法与交互照搬 KSU 的管理器更新卡：
 * 一张 Notice 卡，点击 → 确认框 → 执行。紧贴状态卡下方，没有更新时整张不画。
 */
@Composable
fun UltraEnvironmentUpdateCardMiuix(
    panel: UltraEnvironmentUpdatePanel,
    modifier: Modifier = Modifier,
) {
    val upgrade = panel.upgrade
    // 收起动画期间状态已是 None：留住上一次的内容，卡片不会在退场时变空。
    val held = remember { Ref<UltraEnvUpgrade>() }
    if (upgrade !is UltraEnvUpgrade.None) held.value = upgrade
    val shown = held.value
    val confirmTitle = stringResource(R.string.ultra_env_update_confirm_title)
    val confirmText = stringResource(R.string.ultra_env_update_confirm)
    // Available（同版本新构建）与 Unverified（身份读不到 → 重装写身份）都可点；其它状态 null。
    val confirmMessage = shown?.let { ultraUpdateConfirmMessage(it) }

    AnimatedVisibility(
        visible = upgrade !is UltraEnvUpgrade.None,
        enter = fadeIn() + expandVertically(),
        exit = shrinkVertically() + fadeOut(),
    ) {
        // 确认框只在卡片可见时存在：卡片收起时不在首页列里留下任何节点（不多出间距）。
        val dialog = rememberConfirmDialog(onConfirm = { panel.startUpgrade() })
        WarningCard(
            message = ultraUpdateMessage(shown, panel.busy),
            modifier = modifier,
            level = WarningLevel.Notice,
            onClick = if (confirmMessage != null && !panel.busy) {
                { dialog.showConfirm(title = confirmTitle, content = confirmMessage, confirm = confirmText) }
            } else {
                null
            },
        )
    }
}
