package com.maplesu.core.ui.screen.flash

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.maplesu.core.R
import com.maplesu.core.ui.LocalUiMode
import com.maplesu.core.ui.UiMode
import com.maplesu.core.ui.util.FlashOutcome
import com.maplesu.core.ui.util.InstallStage
import top.yukonga.miuix.kmp.theme.MiuixTheme

/**
 * 步骤 ④ 的全部可见内容（两套皮肤同一份）。
 *
 * 只有四行以内的**结论**：正在修补/写入（阶段）、结果（成功/失败）、失败原因与稳定码、
 * 以及"这次镜像由本机生成"这句必须说的事实。**不渲染**日志、补丁条数、摘要、回读状态、
 * 事务状态串 —— 那些是 host 侧/日志侧的事，不是用户要看的"记录"。
 */
@Composable
internal fun FlashStatusBanner(state: FlashUiState, modifier: Modifier = Modifier) {
    val stageText: String? = if (state.flashingStatus == FlashingStatus.FLASHING) {
        when (state.stage) {
            InstallStage.UPGRADING_ENVIRONMENT -> stringResource(R.string.ultra_env_update_running)
            InstallStage.PATCHING -> stringResource(R.string.install_boot_stage_patching)
            InstallStage.WRITING -> stringResource(R.string.install_boot_stage_writing)
            InstallStage.AWAITING_REBOOT -> stringResource(R.string.install_boot_stage_awaiting_reboot)
            null -> null
        }
    } else null
    val pending = state.flashingStatus == FlashingStatus.PENDING
    val outcomeText: String? = if (pending) stringResource(R.string.module_install_pending_message) else when (state.outcome) {
        FlashOutcome.ENVIRONMENT_UPDATED -> stringResource(R.string.ultra_env_update_complete)
        FlashOutcome.WRITTEN -> stringResource(R.string.install_boot_outcome_written)
        FlashOutcome.SAVED_ONLY -> stringResource(R.string.install_boot_outcome_saved_only)
        FlashOutcome.ALREADY_PATCHED -> stringResource(R.string.install_boot_outcome_already_patched)
        FlashOutcome.RESTORED -> stringResource(R.string.install_boot_outcome_restored)
        FlashOutcome.RECOVERY_REQUIRED -> stringResource(R.string.install_boot_outcome_recovery_required)
        FlashOutcome.IMAGES_REQUIRED -> stringResource(R.string.work_mode_images_title)
        FlashOutcome.FAILED, null -> null
    }
    // 失败原因与结果行可能重复（RESTORED / RECOVERY_REQUIRED 的 err 就是同一句），只说一次。
    val messageText: String? = state.message?.takeIf { it.isNotBlank() && it != outcomeText }
    val codeText: String? = state.errorCode?.takeIf { it.isNotBlank() }
        ?.let { stringResource(R.string.install_boot_error_code, it) }
    val positive = state.outcome == FlashOutcome.WRITTEN || state.outcome == FlashOutcome.ALREADY_PATCHED ||
        state.outcome == FlashOutcome.ENVIRONMENT_UPDATED
    val failure = state.flashingStatus == FlashingStatus.FAILED
    // 出处说明（"由本机生成"）只在**没写进分区**的时候出现：成功页按用户口径只留结论 + 保存/刷入
    // （2026-11-01：「不需要用已验证状态挡人，成功页只留修补成功/刷入/保存」）。
    val generatedText: String? = if (
        state.generatedOnDevice && state.stage != InstallStage.UPGRADING_ENVIRONMENT &&
        state.flashingStatus != FlashingStatus.FLASHING && !positive
    ) {
        stringResource(R.string.install_boot_generated_notice)
    } else {
        null
    }
    if (stageText == null && outcomeText == null && messageText == null && codeText == null && generatedText == null) {
        return
    }

    when (LocalUiMode.current) {
        UiMode.Material -> Column(modifier = modifier.fillMaxWidth()) {
            stageText?.let {
                androidx.compose.material3.Text(
                    text = it,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.primary,
                )
            }
            outcomeText?.let {
                androidx.compose.material3.Text(
                    text = it,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
                    style = MaterialTheme.typography.bodyMedium,
                    color = when {
                        pending -> MaterialTheme.colorScheme.onSurfaceVariant
                        positive -> MaterialTheme.colorScheme.primary
                        else -> MaterialTheme.colorScheme.error
                    },
                )
            }
            messageText?.let {
                androidx.compose.material3.Text(
                    text = it,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
                    style = MaterialTheme.typography.bodySmall,
                    color = if (failure) {
                        MaterialTheme.colorScheme.error
                    } else {
                        MaterialTheme.colorScheme.onSurfaceVariant
                    },
                )
            }
            codeText?.let {
                androidx.compose.material3.Text(
                    text = it,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 2.dp),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            generatedText?.let {
                androidx.compose.material3.Text(
                    text = it,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
            }
        }
        UiMode.Miuix -> Column(modifier = modifier.fillMaxWidth()) {
            stageText?.let {
                top.yukonga.miuix.kmp.basic.Text(
                    text = it,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
                    fontSize = 14.sp,
                    color = MiuixTheme.colorScheme.primary,
                )
            }
            outcomeText?.let {
                top.yukonga.miuix.kmp.basic.Text(
                    text = it,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
                    fontSize = 14.sp,
                    color = when {
                        pending -> MiuixTheme.colorScheme.onSurfaceVariantSummary
                        positive -> MiuixTheme.colorScheme.primary
                        else -> MiuixTheme.colorScheme.error
                    },
                )
            }
            messageText?.let {
                top.yukonga.miuix.kmp.basic.Text(
                    text = it,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
                    fontSize = 12.sp,
                    color = if (failure) MiuixTheme.colorScheme.error else MiuixTheme.colorScheme.onSurfaceVariantSummary,
                )
            }
            codeText?.let {
                top.yukonga.miuix.kmp.basic.Text(
                    text = it,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 2.dp),
                    fontSize = 12.sp,
                    color = MiuixTheme.colorScheme.onSurfaceVariantSummary,
                )
            }
            generatedText?.let {
                top.yukonga.miuix.kmp.basic.Text(
                    text = it,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
                    fontSize = 12.sp,
                    color = MiuixTheme.colorScheme.error,
                )
            }
        }
    }
}
