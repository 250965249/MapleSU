package com.maplesu.core.ui.component.rebootlistpopup

import android.content.Context
import android.os.PowerManager
import android.widget.Toast
import androidx.annotation.StringRes
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import com.maplesu.core.R
import com.maplesu.core.ui.LocalUiMode
import com.maplesu.core.ui.UiMode
import com.maplesu.core.ui.component.dialog.rememberConfirmDialog
import com.maplesu.core.ui.util.reboot
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

data class RebootListOption(
    @param:StringRes val labelRes: Int,
    val reason: String,
)

@Composable
fun getRebootListOption(): List<RebootListOption> {
    val pm = LocalContext.current.getSystemService(Context.POWER_SERVICE) as PowerManager?

    @Suppress("DEPRECATION")
    val isRebootingUserspaceSupported = runCatching { pm?.isRebootingUserspaceSupported == true }
        .getOrDefault(false)

    return buildList {
        add(RebootListOption(R.string.reboot, ""))
        if (isRebootingUserspaceSupported) {
            add(RebootListOption(R.string.reboot_userspace, "userspace"))
        }
        add(RebootListOption(R.string.reboot_soft, "soft_reboot"))
        add(RebootListOption(R.string.reboot_recovery, "recovery"))
        add(RebootListOption(R.string.reboot_bootloader, "bootloader"))
        add(RebootListOption(R.string.reboot_download, "download"))
        add(RebootListOption(R.string.reboot_edl, "edl"))
    }
}

/** Dispatch off-main; confirm a device reboot when the temporary root session would be lost. */
@Composable
fun rememberRebootAction(lateLoad: Boolean = false): (String) -> Unit {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val inFlight = remember { AtomicBoolean(false) }
    val failed = stringResource(R.string.reboot_request_failed)
    val title = stringResource(R.string.reboot)
    val message = stringResource(R.string.jailbreak_reboot_warning)
    val submit: (String) -> Unit = remember(context, scope, failed) {
        { reason ->
            if (inFlight.compareAndSet(false, true)) {
                scope.launch {
                    try {
                        val accepted = withContext(Dispatchers.IO) {
                            runCatching { reboot(reason) }.getOrDefault(false)
                        }
                        if (!accepted) Toast.makeText(context, failed, Toast.LENGTH_LONG).show()
                    } finally {
                        inFlight.set(false)
                    }
                }
            }
        }
    }
    var pendingReason by remember { mutableStateOf("") }
    val confirmDialog = rememberConfirmDialog(onConfirm = { submit(pendingReason) })

    return remember(title, message, confirmDialog, lateLoad, submit) {
        { reason ->
            if (lateLoad && reason != "soft_reboot") {
                pendingReason = reason
                confirmDialog.showConfirm(title = title, content = message)
            } else {
                submit(reason)
            }
        }
    }
}

@Composable
fun RebootListPopup(lateLoad: Boolean = false) {
    when (LocalUiMode.current) {
        UiMode.Miuix -> RebootListPopupMiuix(lateLoad = lateLoad)
        UiMode.Material -> RebootListPopupMaterial(lateLoad = lateLoad)
    }
}
