package dev.maplesu.manager.workmode.ui

import android.content.Intent
import android.widget.Toast
import androidx.core.content.FileProvider
import androidx.compose.runtime.Composable
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.maplesu.core.ui.LocalUiMode
import com.maplesu.core.ui.UiMode
import com.maplesu.core.ui.navigation3.LocalNavigator
import dev.maplesu.manager.workmode.control.ControlPaths
import dev.maplesu.manager.workmode.recovery.DiagnosticsExporter
import com.maplesu.core.R
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlin.coroutines.cancellation.CancellationException
import java.io.File

/** 诊断页动作（双皮肤共用）。 */
@Immutable
data class DiagnosisActions(
    val onBack: () -> Unit,
    val onRefresh: () -> Unit,
    val onExport: () -> Unit,
    val onShare: () -> Unit = {},
)

/**
 * 诊断页宿主（W16；主文档 §5.7）。
 *
 * 导出写 `filesDir/diagnostics/diagnostics-*.json`（脱敏合并 evidence/journal/baseline）；
 * 路径与 sha256 显示在页面上供用户复制。**不存在任何分享明文/凭据的入口**。
 *
 * `switchId` 只来自 `Route.Diagnosis`（内部 push），不接受 Intent 注入。
 */
@Composable
fun DiagnosisScreen(
    switchId: String = "",
    onBack: (() -> Unit)? = null,
) {
    val navigator = LocalNavigator.current
    val context = LocalContext.current
    val viewModel = viewModel<DiagnosisViewModel>()
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val scope = rememberCoroutineScope()

    val exporter = remember(context) {
        DiagnosticsExporter(
            root = ControlPaths.ROOT_FILE,
            diagnosticsDir = File(context.filesDir, "diagnostics"),
        )
    }
    LaunchedEffect(switchId) { viewModel.attach(switchId) }

    val actions = DiagnosisActions(
        onBack = { onBack?.invoke() ?: navigator.pop() },
        onRefresh = viewModel::refresh,
        onExport = { viewModel.export(exporter) },
        onShare = {
            state.exportedPath?.let { path ->
                scope.launch {
                    try {
                        val uri = withContext(Dispatchers.IO) {
                            val directory = File(context.cacheDir, "diagnostics").apply { mkdirs() }
                            val shared = File(directory, File(path).name)
                            File(path).copyTo(shared, overwrite = true)
                            FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", shared)
                        }
                        context.startActivity(Intent.createChooser(
                            Intent(Intent.ACTION_SEND).apply {
                                type = "application/json"
                                putExtra(Intent.EXTRA_STREAM, uri)
                                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                            }, context.getString(R.string.diagnosis_share),
                        ))
                    } catch (cancelled: CancellationException) {
                        throw cancelled
                    } catch (_: Exception) {
                        Toast.makeText(context, R.string.diagnosis_share_failed, Toast.LENGTH_SHORT).show()
                    }
                }
            }
        },
    )

    when (LocalUiMode.current) {
        UiMode.Miuix -> DiagnosisScreenMiuix(state, actions)
        UiMode.Material -> DiagnosisScreenMaterial(state, actions)
    }
}
