package dev.maplesu.manager.jailbreak

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.SheetValue
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.core.content.FileProvider
import com.maplesu.core.BuildConfig
import com.maplesu.core.R
import com.maplesu.core.ui.LocalUiMode
import com.maplesu.core.ui.UiMode
import com.maplesu.core.ui.theme.materialDialogColor
import com.maplesu.core.ui.theme.miuixDialogColor
import com.maplesu.core.ui.util.getBugreportFile
import com.maplesu.core.ui.util.saveBugreport
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import top.yukonga.miuix.kmp.window.WindowBottomSheet

/** Progress and failure diagnostics remain available without a working SU channel. */
@Composable
@OptIn(ExperimentalMaterial3Api::class)
internal fun JailbreakLogSheet(ui: JailbreakSelectionState, onDismiss: () -> Unit, onCancel: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var busy by remember { mutableStateOf(false) }
    val reader = remember(ui.runId, ui.method, ui.rootTarget, ui.logAttemptId, ui.logStartedAtMillis) {
        JailbreakLogReader(context.createDeviceProtectedStorageContext().dataDir, context.filesDir,
            ui.method.wireName, ui.rootTarget, ui.logAttemptId, ui.logStartedAtMillis)
    }
    var snapshot by remember(reader) { mutableStateOf(JailbreakLogReader.Snapshot()) }
    var pendingScreenLog by remember { mutableStateOf<JailbreakScreenLog?>(null) }
    LaunchedEffect(reader) {
        while (true) {
            snapshot = withContext(Dispatchers.IO) { reader.poll() }
            delay(350)
        }
    }
    val saved = stringResource(R.string.log_saved)
    val failed = stringResource(R.string.log_export_failed)
    val share = stringResource(R.string.maplesu_jailbreak_share_logs)
    val copied = stringResource(R.string.maplesu_jailbreak_logs_copied)
    val copiedTail = stringResource(R.string.maplesu_jailbreak_logs_copied_tail)
    val copyFailed = stringResource(R.string.maplesu_jailbreak_logs_copy_failed)
    val launcher = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/gzip")) { uri ->
        val screenLog = pendingScreenLog
        pendingScreenLog = null
        if (uri != null) scope.launch {
            busy = true
            try {
                withContext(Dispatchers.IO) { saveBugreport(context, uri, includePrivileged = false,
                    screenLog = screenLog) }
                Toast.makeText(context, saved, Toast.LENGTH_SHORT).show()
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                android.util.Log.w("JailbreakLogs", "Export failed", error)
                Toast.makeText(context, failed, Toast.LENGTH_LONG).show()
            } finally { busy = false }
        }
    }
    val content: @Composable () -> Unit = {
        JailbreakLogPanel(ui, snapshot, busy, onCopy = {
            try {
                val text = snapshot.text()
                // Stay below Binder's clipboard transaction limit; the archive always keeps the full log.
                context.getSystemService(ClipboardManager::class.java)
                    .setPrimaryClip(ClipData.newPlainText("MapleSU logs", text.takeLast(160_000)))
                Toast.makeText(context, if (text.length > 160_000) copiedTail else copied, Toast.LENGTH_SHORT).show()
            } catch (error: Exception) {
                android.util.Log.w("JailbreakLogs", "Copy failed", error)
                Toast.makeText(context, copyFailed, Toast.LENGTH_LONG).show()
            }
        }, onExport = {
            pendingScreenLog = JailbreakScreenLog(snapshot, ui.method.wireName, ui.rootTarget)
            launcher.launch("MapleSU_jailbreak_${System.currentTimeMillis()}.tar.gz")
        },
            onShare = {
                val screenLog = JailbreakScreenLog(snapshot, ui.method.wireName, ui.rootTarget)
                scope.launch {
                    busy = true
                    try {
                        val report = withContext(Dispatchers.IO) { getBugreportFile(context, includePrivileged = false,
                            screenLog = screenLog) }
                        val uri = FileProvider.getUriForFile(context, "${BuildConfig.APPLICATION_ID}.fileprovider", report)
                        val intent = Intent(Intent.ACTION_SEND).apply {
                            type = "application/gzip"
                            putExtra(Intent.EXTRA_STREAM, uri)
                            clipData = ClipData.newRawUri("MapleSU logs", uri)
                            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                        }
                        context.startActivity(Intent.createChooser(intent, share))
                    } catch (error: CancellationException) {
                        throw error
                    } catch (error: Exception) {
                        android.util.Log.w("JailbreakLogs", "Share failed", error)
                        Toast.makeText(context, failed, Toast.LENGTH_LONG).show()
                    } finally { busy = false }
                }
            }, onDismiss = onDismiss, onCancel = onCancel)
    }
    val title = stringResource(R.string.maplesu_jailbreak_logs_title)
    when (LocalUiMode.current) {
        UiMode.Miuix -> WindowBottomSheet(show = true, title = title,
            backgroundColor = miuixDialogColor(), allowDismiss = !busy,
            onDismissRequest = { if (!busy) onDismiss() }) { content() }
        UiMode.Material -> ModalBottomSheet(
            onDismissRequest = { if (!busy) onDismiss() },
            sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true,
                confirmValueChange = { it != SheetValue.Hidden || !busy }),
            containerColor = materialDialogColor(),
        ) {
            com.maplesu.core.ui.screen.host.HiddenFlowText(title,
                modifier = Modifier.padding(horizontal = 18.dp, vertical = 4.dp), title = true)
            content()
        }
    }
}
