package com.maplesu.core.ui.component.uninstalldialog

import androidx.compose.runtime.Composable
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import com.maplesu.core.R
import com.maplesu.core.ui.LocalUiMode
import com.maplesu.core.ui.UiMode
import com.maplesu.core.ui.component.dialog.rememberConfirmDialog
import com.maplesu.core.ui.navigation3.LocalNavigator
import com.maplesu.core.ui.navigation3.Route
import com.maplesu.core.ui.screen.flash.FlashIt
import com.maplesu.core.ui.screen.flash.UninstallType

/**
 * 卸载弹窗里的一项。KSU 三段式的第二段（列表）和第三段（确认窗）都由它描述，
 * Normal 与 Ultra 只是传入不同的项，弹窗的样子与交互完全一致。
 */
@Immutable
data class UninstallChoice(
    val icon: ImageVector,
    val title: String,
    /** 确认窗的正文：写清楚后果。 */
    val message: String,
    /** 不可用的原因；非空时该项禁用。 */
    val disabledReason: String? = null,
    /** 非破坏性的动作（例如「恢复使用」）不需要确认窗。 */
    val needsConfirm: Boolean = true,
    val onRun: () -> Unit,
)

/** Normal：沿用 KSU 的永久卸载 / 恢复原厂镜像，两项都进刷写页。 */
@Composable
fun UninstallDialog(
    show: Boolean,
    onDismissRequest: () -> Unit,
) {
    val navigator = LocalNavigator.current
    UninstallChooser(
        show = show,
        title = stringResource(R.string.uninstall),
        choices = listOf(
            uninstallChoice(UninstallType.PERMANENT) { navigator.push(Route.Flash(FlashIt.FlashUninstall)) },
            uninstallChoice(UninstallType.RESTORE_STOCK_IMAGE) { navigator.push(Route.Flash(FlashIt.FlashRestore)) },
        ),
        onDismissRequest = onDismissRequest,
    )
}

@Composable
private fun uninstallChoice(type: UninstallType, onRun: () -> Unit) = UninstallChoice(
    icon = type.icon,
    title = stringResource(type.title),
    message = stringResource(type.message),
    onRun = onRun,
)

/** 三段式的后两段：列表弹窗 → 确认窗 → 执行（列表在确认后才关闭，取消时回到列表）。 */
@Composable
fun UninstallChooser(
    show: Boolean,
    title: String,
    choices: List<UninstallChoice>,
    onDismissRequest: () -> Unit,
) {
    var pending by remember { mutableStateOf<UninstallChoice?>(null) }
    val confirmDialog = rememberConfirmDialog(
        onConfirm = {
            val choice = choices.firstOrNull { it.title == pending?.title && it.disabledReason == null }
            pending = null
            onDismissRequest()
            choice?.onRun?.invoke()
        },
        onDismiss = { pending = null },
    )
    val onChoose: (UninstallChoice) -> Unit = { choice ->
        if (choice.needsConfirm) {
            pending = choice
            confirmDialog.showConfirm(title = choice.title, content = choice.message)
        } else {
            onDismissRequest()
            choice.onRun()
        }
    }
    when (LocalUiMode.current) {
        UiMode.Miuix -> UninstallChooserMiuix(show, title, choices, onChoose, onDismissRequest)
        UiMode.Material -> UninstallChooserMaterial(show, title, choices, onChoose, onDismissRequest)
    }
}
