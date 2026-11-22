package com.maplesu.core.ui.screen.appprofile

import androidx.annotation.StringRes
import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import com.maplesu.core.R
import dev.maplesu.manager.runtime.State

enum class Mode(@field:StringRes private val res: Int) {
    Default(R.string.profile_default),
    Template(R.string.profile_template),
    Custom(R.string.profile_custom);

    val text: String
        @Composable get() = stringResource(res)
}

/**
 * Normal（KernelSU）下的授权显示状态（纯函数，主机可测）。
 *
 * Ultra 的 `SuDelivery` 模型有"已投递 / 待接线 / 镜像缺失"这些中间态，因为 Lite 需要把
 * `su` 客户端投递到目标应用并注入 PATH。KSU **没有**这个环节：内核在应用发起请求时
 * 直接按 allowlist 判定，所以"在白名单"就是"生效"，"不在"就是"未授权"。
 *
 * 这也修掉审计里 AppProfile 的问题：以前 KSU 模式仍走 `stateFor(...)` +
 * `DirectPolicy.grantedUids(...)`（会起一个 Lite root 进程做投递探测），
 * 在 Normal 下要么失败、要么把状态误报成 `PENDING_WIRING`。
 */
internal fun ksuSuState(granted: Boolean): State =
    if (granted) State.WIRED else State.NOT_AUTHORIZED
