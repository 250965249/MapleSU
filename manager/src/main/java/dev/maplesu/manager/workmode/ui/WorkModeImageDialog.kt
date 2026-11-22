package dev.maplesu.manager.workmode.ui

import android.net.Uri
import android.provider.OpenableColumns
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import com.maplesu.core.R
import com.maplesu.core.ui.screen.host.HiddenFlowButton
import com.maplesu.core.ui.screen.host.HiddenFlowDialog
import com.maplesu.core.ui.screen.host.HiddenFlowText
import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.service.SwitchOutcome

/** Shown only after switch confirmation discovers that no automatic backup is available. */
@Composable
internal fun WorkModeImageDialog(
    request: SwitchOutcome.ImagesRequired,
    busy: Boolean,
    readError: String?,
    onConfirm: (Uri?, Uri?) -> Unit,
    onDismiss: () -> Unit,
) {
    val context = LocalContext.current
    var boot by rememberSaveable(request) { mutableStateOf<String?>(null) }
    var initBoot by rememberSaveable(request) { mutableStateOf<String?>(null) }
    var bootName by rememberSaveable(request) { mutableStateOf("") }
    var initBootName by rememberSaveable(request) { mutableStateOf("") }
    fun name(uri: Uri): String = runCatching {
        context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use {
            if (it.moveToFirst()) it.getString(0) else null
        }
    }.getOrNull() ?: uri.lastPathSegment.orEmpty()
    val bootPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) { boot = uri.toString(); bootName = name(uri) }
    }
    val initBootPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) { initBoot = uri.toString(); initBootName = name(uri) }
    }
    HiddenFlowDialog(
        title = stringResource(R.string.work_mode_images_title),
        onDismiss = onDismiss,
        confirmLabel = stringResource(R.string.confirm),
        onConfirm = { onConfirm(boot?.let(Uri::parse), initBoot?.let(Uri::parse)) },
        dismissLabel = stringResource(R.string.download_cancel),
        confirmEnabled = !busy && (!request.requiresBoot || boot != null) &&
            (!request.restoreInitBoot || initBoot != null),
        dismissEnabled = !busy,
    ) {
        HiddenFlowText(stringResource(when {
            request.target == WorkMode.KSU -> R.string.work_mode_images_normal
            request.restoreInitBoot -> R.string.work_mode_images_ultra
            else -> R.string.work_mode_images_ultra_boot
        }), secondary = true)
        if (request.restoreInitBoot) HiddenFlowButton(
            text = initBootName.ifBlank { stringResource(R.string.work_mode_images_restore_init_boot) },
            onClick = { initBootPicker.launch(arrayOf("*/*")) },
            modifier = Modifier.fillMaxWidth(), enabled = !busy,
        )
        HiddenFlowButton(
            text = bootName.ifBlank { stringResource(if (request.requiresBoot)
                R.string.work_mode_images_boot else R.string.work_mode_images_boot_optional) },
            onClick = { bootPicker.launch(arrayOf("*/*")) },
            modifier = Modifier.fillMaxWidth(), enabled = !busy,
        )
        if (request.target == WorkMode.LITE && !request.requiresBoot && boot != null) HiddenFlowButton(
            text = stringResource(R.string.work_mode_images_use_current),
            onClick = { boot = null; bootName = "" }, enabled = !busy,
        )
        if (readError != null) HiddenFlowText(stringResource(R.string.work_mode_images_read_failed), secondary = true)
    }
}
