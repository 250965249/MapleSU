package dev.maplesu.manager.workmode.ui

import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import com.maplesu.core.R

internal data class ModeSwitchCopy(val title: String, val hint: String)

@Composable
internal fun modeSwitchCopy(state: ModeSwitchUiState): ModeSwitchCopy {
    val target = state.to?.let { stringResource(WorkModeStrings.modeNameRes(it)) }
    val headline = modeSwitchHeadline(state.phase, state.stateWire, state.rebootRequired)
    val title = when (headline) {
        ModeSwitchHeadline.ATTACHING -> stringResource(R.string.work_mode_switch_attaching)
        ModeSwitchHeadline.RUNNING -> target?.let {
            stringResource(R.string.work_mode_headline_running_to, it)
        } ?: stringResource(R.string.work_mode_switch_running)
        ModeSwitchHeadline.ROLLING_BACK -> stringResource(R.string.work_mode_headline_rolling_back)
        ModeSwitchHeadline.VERIFYING -> stringResource(R.string.work_mode_headline_verifying)
        ModeSwitchHeadline.AWAITING_REBOOT -> stringResource(R.string.work_mode_ready_reboot)
        ModeSwitchHeadline.DONE -> stringResource(R.string.work_mode_headline_done)
        ModeSwitchHeadline.ROLLED_BACK -> stringResource(R.string.work_mode_headline_rolled_back)
        ModeSwitchHeadline.FAILED -> stringResource(R.string.work_mode_switch_failed_short)
        ModeSwitchHeadline.NEEDS_RECOVERY -> stringResource(R.string.work_mode_switch_recovery_required)
        ModeSwitchHeadline.MISSING -> stringResource(R.string.work_mode_journal_missing)
    }
    val hint = when (headline) {
        ModeSwitchHeadline.ATTACHING, ModeSwitchHeadline.RUNNING, ModeSwitchHeadline.ROLLING_BACK,
        ModeSwitchHeadline.VERIFYING -> stringResource(R.string.work_mode_headline_running_hint)
        ModeSwitchHeadline.AWAITING_REBOOT -> target?.let {
            stringResource(R.string.work_mode_headline_reboot_hint, it)
        } ?: stringResource(R.string.work_mode_headline_reboot_hint_generic)
        ModeSwitchHeadline.DONE -> target?.let {
            stringResource(R.string.work_mode_headline_done_hint, it)
        } ?: stringResource(R.string.work_mode_headline_done)
        ModeSwitchHeadline.ROLLED_BACK -> stringResource(R.string.work_mode_headline_rolled_back_hint)
        ModeSwitchHeadline.FAILED, ModeSwitchHeadline.NEEDS_RECOVERY ->
            stringResource(R.string.work_mode_headline_failed_hint)
        ModeSwitchHeadline.MISSING -> stringResource(R.string.work_mode_headline_missing_hint)
    }
    return ModeSwitchCopy(title, hint)
}
