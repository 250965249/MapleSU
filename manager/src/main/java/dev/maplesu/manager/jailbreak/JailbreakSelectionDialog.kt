package dev.maplesu.manager.jailbreak

import android.net.Uri
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.selection.toggleable
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import com.maplesu.core.R
import com.maplesu.core.ui.LocalUiMode
import com.maplesu.core.ui.UiMode
import com.maplesu.core.ui.component.rebootlistpopup.rememberRebootAction
import com.maplesu.core.ui.util.requestSystemReboot
import com.maplesu.core.ui.screen.host.HiddenFlowButton
import com.maplesu.core.ui.screen.host.HiddenFlowDialog
import com.maplesu.core.ui.screen.host.HiddenFlowText
import com.maplesu.core.ui.screen.host.hiddenFlowColors
import dev.maplesu.ghostlock.extract.ExtractInput
import dev.maplesu.ghostlock.extract.ExtractionOutcome
import dev.maplesu.ghostlock.extract.GeneratedProfile
import dev.maplesu.ghostlock.extract.GhostlockExtractionPipeline
import dev.maplesu.ghostlock.extract.GhostlockNativeExtractor
import dev.maplesu.ghostlock.extract.GhostlockOtaFlow
import dev.maplesu.ghostlock.extract.GhostlockProfileGate
import dev.maplesu.ghostlock.extract.GhostlockProfileStore
import dev.maplesu.ghostlock.extract.OtaCopy
import dev.maplesu.ghostlock.extract.OtaParseState
import java.io.File
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.CardDefaults
import top.yukonga.miuix.kmp.theme.MiuixTheme

/**
 * Jailbreak entry. Method setup is disclosed only for the selected method,
 * and an attempt starts only after the current admission checks pass.
 * A run only reports stages the privileged side actually reached; the dialog
 * never writes a "rooted" or "installed" preference.
 *
 * Ghostlock availability is one decision (`GhostlockProfileGate`): the packaged
 * upstream list carries this exact `uname -r`, **or** a confirmed imported
 * profile carries it. When neither holds, the dialog shows the one place the
 * user can fix it: paste a full OTA link (or pick a local `boot.img`), parse it
 * and use the result immediately. A failed parse never enables the option.
 */
@Composable
fun JailbreakSelectionDialog(onDismiss: () -> Unit, onActivated: () -> Unit = {}) {
    var selected by rememberSaveable { mutableStateOf(JailbreakMethod.DIRTYFRAG.name) }
    var target by remember { mutableStateOf<JailbreakTarget?>(null) }
    var probeFailed by remember { mutableStateOf(false) }
    var artifactBlocker by remember { mutableStateOf<JailbreakBlocker?>(null) }
    var assessment by remember { mutableStateOf<JailbreakAssessment?>(null) }
    var checkedMethod by remember { mutableStateOf<JailbreakMethod?>(null) }
    var checkedStoreVersion by remember { mutableStateOf(-1) }
    var task by remember { mutableStateOf(JailbreakTaskUiState()) }
    val running = task.running
    val outcome = task.outcome
    var observed by remember { mutableStateOf<JailbreakStatus?>(null) }
    /*
     * The upstream GhostLock-App support list (SUPPORTED_DEVICES_ZH.md), packaged
     * as `assets/ghostlock/supported-devices.json`. Null while it is being read;
     * a read that fails still yields a fail-closed list, never an exception.
     */
    var ghostlockList by remember { mutableStateOf<GhostlockSupport?>(null) }
    var ghostlockGate by remember { mutableStateOf<GhostlockProfileGate.Decision?>(null) }
    var checkedGhostlockStoreVersion by remember { mutableStateOf(-1) }
    var storeVersion by remember { mutableStateOf(0) }
    // Preserve the existing success-time reboot preference.
    var softReboot by rememberSaveable { mutableStateOf(true) }
    /*
     * Which mode the user wants root for. This is a real choice, not a
     * derivation from the current work mode: the jailbreak is the same exploit
     * either way, and the kernel payload is what differs (our own module for
     * Ultra, KernelSU for Normal). It defaults to Ultra.
     */
    var rootTarget by rememberSaveable {
        mutableStateOf(JailbreakRequest.BACKEND_HOOK)
    }
    // OTA/local-image parse state for the "no matching profile" case only.
    var otaUrl by rememberSaveable { mutableStateOf("") }
    var otaState by remember { mutableStateOf<OtaParseState>(OtaParseState.Idle) }
    var pendingOverwrite by remember { mutableStateOf<List<GeneratedProfile>?>(null) }
    val method = JailbreakMethod.valueOf(selected)
    val context = LocalContext.current.applicationContext
    var shizuku by remember { mutableStateOf(ShizukuAccess.State()) }
    val scope = rememberCoroutineScope()
    val onReboot = rememberRebootAction(lateLoad = true)
    val rebootFailed = stringResource(R.string.reboot_request_failed)
    val automaticReboot = remember(context) {
        val preferences = context.getSharedPreferences("jailbreak_reboot", android.content.Context.MODE_PRIVATE)
        JailbreakAutomaticReboot(
            lastAttempt = { preferences.getString("last_attempt", null) },
            recordAttempt = { preferences.edit().putString("last_attempt", it).commit() },
        )
    }

    val managerRestartMessage = stringResource(R.string.maplesu_jailbreak_manager_restart)
    val managerRestartFailed = stringResource(R.string.maplesu_jailbreak_manager_restart_failed)
    val automaticManagerRestart = remember(context) {
        val preferences = context.getSharedPreferences("jailbreak_manager_restart", android.content.Context.MODE_PRIVATE)
        JailbreakAutomaticReboot(
            lastAttempt = { preferences.getString("last_attempt", null) },
            recordAttempt = { preferences.edit().putString("last_attempt", it).commit() },
        )
    }

    LaunchedEffect(Unit) {
        try {
            target = withContext(Dispatchers.IO) { JailbreakDeviceProbe.collect() }
        } catch (error: CancellationException) {
            throw error
        } catch (error: Exception) {
            probeFailed = true
        }
    }
    // S14: poll the trusted process so the UI shows real stages and expires the
    // record when the attempt/lease is gone.
    LaunchedEffect(running) {
        while (running) {
            observed = withContext(Dispatchers.IO) { JailbreakController.status(context) }
            delay(400)
        }
    }
    LaunchedEffect(method, rootTarget) {
        task = task.copy(outcome = null, cancellationFailed = false, startedAtMillis = 0)
        observed = withContext(Dispatchers.IO) { JailbreakController.status(context) }
    }
    LaunchedEffect(Unit) {
        ghostlockList = withContext(Dispatchers.IO) { GhostlockSupport.from(context) }
    }
    LaunchedEffect(method) {
        while (method == JailbreakMethod.MAPLESU_93260) {
            shizuku = withContext(Dispatchers.IO) { ShizukuAccess.state() }
            delay(600)
        }
    }


    // Profile and artifact reads stay off the composition thread. A previous
    // method's result must never enable Start while a new selection is checked.
    LaunchedEffect(method, target, storeVersion) {
        checkedMethod = null
        assessment = null
        artifactBlocker = null
        val current = target ?: return@LaunchedEffect
        val checked = withContext(Dispatchers.IO) {
            JailbreakAdmission.assess(context, method, current) to
                JailbreakAdmission.verifyArtifacts(context, method)
        }
        assessment = checked.first
        artifactBlocker = checked.second
        checkedStoreVersion = storeVersion
        checkedMethod = method
    }
    val checksReady = target != null && checkedMethod == method && checkedStoreVersion == storeVersion
    val blockers = if (checksReady) buildList {
        assessment?.blockers?.let { addAll(it) }
        artifactBlocker?.let { add(it) }
    } else emptyList()
    val warnings = if (checksReady) assessment?.warnings.orEmpty() else emptyList()

    val release = target?.kernelRelease.orEmpty()
    // Store.openIn returns a handle; decide() reads its confirmed documents.
    // Keep that read off the UI thread as well as the admission/artifact checks.
    LaunchedEffect(target, ghostlockList, storeVersion) {
        ghostlockGate = null
        val packaged = ghostlockList ?: return@LaunchedEffect
        if (target == null) return@LaunchedEffect
        ghostlockGate = withContext(Dispatchers.IO) {
            GhostlockProfileGate.decide(
                release = release,
                packagedSupported = packaged.isSupported(release) is GhostlockSupport.Support.SUPPORTED,
                store = GhostlockProfileStore.openIn(context.filesDir),
                packagedListUsable = packaged.isUsable,
            )
        }
        checkedGhostlockStoreVersion = storeVersion
    }
    val ghostlockDecided = ghostlockGate != null && checkedGhostlockStoreVersion == storeVersion
    val ghostlockEnabled = ghostlockDecided && ghostlockGate?.let(GhostlockProfileGate::isOffered) == true

    /** Persist one successful parse/import and make it usable immediately. */
    suspend fun persistAndConfirm(profiles: List<GeneratedProfile>): Boolean =
        withContext(Dispatchers.IO) {
            val store = GhostlockProfileStore.openIn(context.filesDir)
            val profile = profiles.firstOrNull { it.release == release } ?: return@withContext false
            if (!profile.complete) return@withContext false
            if (!store.save(store.entryFor(profile))) return@withContext false
            store.confirm(profile.release)
        }

    /** Run the OTA/local-image parse off the main thread and apply the outcome. */
    suspend fun runParse(input: ExtractInput) {
        otaState = OtaParseState.Parsing
        val outcomeResult = withContext(Dispatchers.IO) {
            try {
                val entry = "libmaplesu_ghostlock_extract.so"
                JailbreakArtifacts.require(context, entry)
                GhostlockExtractionPipeline.parse(
                    input = input,
                    workDir = File(context.cacheDir, "ghostlock-parse").apply { mkdirs() },
                    imageExtractor = GhostlockNativeExtractor(File(context.applicationInfo.nativeLibraryDir, entry)),
                    onLog = { android.util.Log.i("MapleSU-Ghostlock", "extract: $it") },
                )
            } catch (error: java.io.IOException) {
                android.util.Log.e("MapleSU-Ghostlock", "extractor startup failed", error)
                ExtractionOutcome.Failure(dev.maplesu.ghostlock.extract.FailureKind.GENERIC,
                    error.message ?: "extractor startup failed")
            }
        }
        val flow = GhostlockOtaFlow(release)
        val evaluated = flow.finish(outcomeResult)
        when {
            outcomeResult is ExtractionOutcome.Generated && evaluated is OtaParseState.Succeeded -> {
                val store = withContext(Dispatchers.IO) {
                    GhostlockProfileStore.openIn(context.filesDir)
                }
                if (withContext(Dispatchers.IO) { store.has(release) }) {
                    // The reference asks before replacing an existing document.
                    pendingOverwrite = outcomeResult.profiles
                    otaState = OtaParseState.Idle
                } else if (persistAndConfirm(outcomeResult.profiles)) {
                    pendingOverwrite = null
                    otaState = evaluated
                    storeVersion++
                } else {
                    otaState = OtaParseState.Failed(dev.maplesu.ghostlock.extract.OtaFailure.INTERNAL)
                }
            }

            else -> {
                pendingOverwrite = null
                otaState = evaluated
            }
        }
    }

    /** Copy a user-picked document into cache, then parse it as a boot image. */
    suspend fun parseLocalBoot(uris: List<Uri>) {
        otaState = OtaParseState.Parsing
        val copied = withContext(Dispatchers.IO) {
            var directory: File? = null
            try {
                val selectedDirectory = java.nio.file.Files.createTempDirectory(context.cacheDir.toPath(),
                    "ghostlock-local-").toFile()
                directory = selectedDirectory
                val images = linkedMapOf<String, File>()
                for (uri in uris) {
                    val name = context.contentResolver.query(uri,
                        arrayOf(android.provider.OpenableColumns.DISPLAY_NAME), null, null, null)?.use {
                        if (it.moveToFirst()) it.getString(0) else null
                    }?.lowercase(java.util.Locale.ROOT)
                    val key = when (name) {
                        "xbl_config.img", "uefi.img", "vendor_boot.img" -> name
                        else -> "boot.img"
                    }
                    require(key !in images) { "select one boot image and optional auxiliary images" }
                    val target = File(selectedDirectory, key)
                    context.contentResolver.openInputStream(uri)?.use { input ->
                        target.outputStream().use { output ->
                            val buffer = ByteArray(65536)
                            var remaining = GhostlockExtractionPipeline.MAX_LOCAL_IMAGE_BYTES
                            while (true) {
                                val count = input.read(buffer)
                                if (count < 0) break
                                if (count > remaining) throw java.io.IOException("image exceeds size bound")
                                output.write(buffer, 0, count)
                                remaining -= count
                            }
                        }
                    } ?: throw java.io.IOException("image stream unavailable")
                    require(target.length() in 1..GhostlockExtractionPipeline.MAX_LOCAL_IMAGE_BYTES) {
                        "image size outside supported bound"
                    }
                    images[key] = target
                }
                val boot = images["boot.img"] ?: throw java.io.IOException("boot image missing")
                ExtractInput.BootImageFile(boot, images["xbl_config.img"], images["uefi.img"],
                    images["vendor_boot.img"])
            } catch (error: CancellationException) {
                directory?.deleteRecursively()
                throw error
            } catch (error: Exception) {
                directory?.deleteRecursively()
                null
            }
        }
        if (copied == null) {
            otaState = OtaParseState.Failed(dev.maplesu.ghostlock.extract.OtaFailure.INTERNAL)
            return
        }
        try { runParse(copied) } finally { copied.boot.parentFile?.deleteRecursively() }
    }

    val localPicker = rememberLauncherForActivityResult(ActivityResultContracts.GetMultipleContents()) { uris ->
        if (uris.isNotEmpty()) scope.launch { parseLocalBoot(uris) }
    }

    fun cancelAttempt() {
        if (!task.running || task.cancellationPending) return
        val runId = task.runId
        task = task.cancellationRequested()
        scope.launch {
            val accepted = withContext(Dispatchers.IO) {
                jailbreakCancellationAccepted { JailbreakController.cancel(context) }
            }
            task = task.cancellationFinished(runId, accepted)
        }
    }
    /*
     * T4 fix: the gate is per boot. `read()` is pure (C2), so a record from an older
     * boot still says READY; showing it as "this boot already has a session" made
     * every reboot look blocked.
     */
    val observedStageNow = observed?.takeIf {
        it.bootId != null && it.bootId == DirtyfragAttempt.readBootId() &&
            it.method == method.wireName && it.rootBackend == rootTarget &&
            (!running || it.startedAtMillis >= task.startedAtMillis)
    }?.stage
    val ui = JailbreakSelectionState(
        runId = task.runId,
        logStartedAtMillis = task.startedAtMillis,
        logAttemptId = outcome?.attemptId ?: observed?.takeIf {
            it.method == method.wireName && it.rootBackend == rootTarget &&
                it.startedAtMillis >= task.startedAtMillis
        }?.attemptId,
        method = method,
        shizuku = shizuku,
        ghostlockReady = ghostlockEnabled,
        ghostlockDecided = ghostlockDecided,
        setupReason = (ghostlockGate as? GhostlockProfileGate.Decision.Unsupported)?.reason,
        otaUrl = otaUrl,
        otaState = otaState,
        awaitingOverwrite = pendingOverwrite != null,
        rootTarget = rootTarget,
        softReboot = softReboot && method != JailbreakMethod.MAPLESU_93260,
        running = running,
        checksReady = checksReady,
        probeFailed = probeFailed,
        blockers = blockers,
        warnings = warnings,
        detectedModel = target?.model.orEmpty(),
        detectedKernel = target?.kernelRelease.orEmpty(),
        methodLabel = if (method == JailbreakMethod.MAPLESU_93260) assessment?.methodLabel else null,
        observedStage = observedStageNow,
        outcome = outcome,
        cancellationPending = task.cancellationPending,
        cancellationFailed = task.cancellationFailed,
    )
    JailbreakSelectionDialogContent(
        ui = ui,
        onDismiss = onDismiss,
        onConfirm = {
            if (task.running) {
                cancelAttempt()
            } else if (ui.succeeded) {
                if (ui.softRebootAvailable) onReboot("soft_reboot") else onDismiss()
            } else if (ui.canStart) {
                task = task.started()
                val runId = task.runId
                val rebootRequested = ui.softReboot && ui.softRebootAvailable
                val requestedTarget = rootTarget
                scope.launch {
                    try {
                        val completed = withContext(Dispatchers.IO) {
                            JailbreakController.run(context, method, rebootRequested, rootTarget)
                        }
                        // The completed result is authoritative for this UI task. A
                        // diagnostic status read must not keep its progress active.
                        val restartManager = JailbreakManagerRestart.required(method, requestedTarget, completed)
                        task = task.completed(runId, if (restartManager)
                            completed.copy(message = managerRestartMessage) else completed)
                        if (task.runId == runId && completed.stage == JailbreakStatus.STAGE_DAEMON_READY &&
                            completed.failure == null && !completed.attemptId.isNullOrBlank()) {
                            onActivated()
                        }
                        if (restartManager)
                            Toast.makeText(context, managerRestartMessage, Toast.LENGTH_LONG).show()
                        val restarted = withContext(Dispatchers.IO) {
                            if (restartManager) {
                                automaticManagerRestart.onSuccess(true, requestedTarget, completed) {
                                    JailbreakManagerRestart.restart(context, completed)
                                }
                            } else automaticReboot.onSuccess(rebootRequested, requestedTarget, completed) {
                                requestSystemReboot(context, "soft_reboot")
                            }
                        }
                        if (restarted == false) {
                            Toast.makeText(context, if (restartManager) managerRestartFailed else rebootFailed,
                                Toast.LENGTH_LONG).show()
                        }
                    } catch (error: CancellationException) {
                        throw error
                    } catch (error: Exception) {
                        task = task.completed(runId, JailbreakController.Outcome(
                            JailbreakStatus.STAGE_FAILED, "task failed", "JAILBREAK_ATTEMPT_FAILED"))
                    } finally {
                        task = task.finished(runId)
                    }
                }
            }
        },
        onMethodSelected = { selected = it.name },
        onTargetSelected = { rootTarget = it },
        onSoftRebootChanged = { softReboot = it },
        onOtaUrlChanged = { otaUrl = it },
        onParse = {
            val started = GhostlockOtaFlow(release).start(otaUrl)
            otaState = started
            if (started is OtaParseState.Parsing) {
                scope.launch { runParse(ExtractInput.OtaUrl(otaUrl.trim())) }
            }
        },
        onLocalBoot = { localPicker.launch("application/octet-stream") },
        onOverwrite = confirmOverwrite@{
            val profiles = pendingOverwrite ?: return@confirmOverwrite
            otaState = OtaParseState.Parsing
            scope.launch {
                if (persistAndConfirm(profiles)) {
                    pendingOverwrite = null
                    otaState = OtaParseState.Succeeded(release)
                    storeVersion++
                } else {
                    otaState = OtaParseState.Failed(dev.maplesu.ghostlock.extract.OtaFailure.INTERNAL)
                }
            }
        },
        onCancelOverwrite = {
            pendingOverwrite = null
            otaState = OtaParseState.Idle
        },
        onCancel = ::cancelAttempt,
        onShizukuPermission = { runCatching { ShizukuAccess.requestPermission() } },
    )
}

internal data class JailbreakSelectionState(
    val runId: Long = 0,
    val logStartedAtMillis: Long = 0,
    val logAttemptId: String? = null,
    val method: JailbreakMethod = JailbreakMethod.DIRTYFRAG,
    val shizuku: ShizukuAccess.State = ShizukuAccess.State(),
    val ghostlockReady: Boolean = false,
    val ghostlockDecided: Boolean = false,
    val setupReason: GhostlockProfileGate.Reason? = null,
    val otaUrl: String = "",
    val otaState: OtaParseState = OtaParseState.Idle,
    val awaitingOverwrite: Boolean = false,
    val rootTarget: String = JailbreakRequest.BACKEND_HOOK,
    val softReboot: Boolean = true,
    val running: Boolean = false,
    val checksReady: Boolean = false,
    val probeFailed: Boolean = false,
    val blockers: List<JailbreakBlocker> = emptyList(),
    val warnings: List<JailbreakBlocker> = emptyList(),
    /** Observed model name; display only, never part of a profile match. */
    val detectedModel: String = "",
    /** Observed `uname -r`; the 98260 profile match is exact on this value. */
    val detectedKernel: String = "",
    /** Escalation variant the 98260 catalog recognised, packaged or not. */
    val methodLabel: String? = null,
    val observedStage: String? = null,
    val outcome: JailbreakController.Outcome? = null,
    val cancellationPending: Boolean = false,
    val cancellationFailed: Boolean = false,
) {
    val succeeded: Boolean
        get() = outcome?.let { it.failure == null && it.stage == JailbreakStatus.STAGE_DAEMON_READY } == true

    val selection: JailbreakSelectionUi get() = JailbreakSelectionUi(method, ghostlockReady, shizuku.ready)
    val parsing: Boolean get() = otaState is OtaParseState.Parsing
    /** C5/T4 gate removed by user directive 2026-11-02: Start is never blocked. */
    val sessionActive: Boolean get() = false
    /** T11: a soft reboot is only meaningful for a kernel carrier (Ultra/Normal). */
    val softRebootAvailable: Boolean
        get() = method != JailbreakMethod.MAPLESU_93260 &&
            (rootTarget == JailbreakRequest.BACKEND_HOOK || rootTarget == JailbreakRequest.BACKEND_KSU)
    val canStart: Boolean get() = selection.canStart(
        running, checksReady, blockers.isNotEmpty(), parsing, awaitingOverwrite)
}

/** The production presentation is also rendered by fixtures without a provider or executor. */
@Composable
internal fun JailbreakSelectionDialogContent(
    ui: JailbreakSelectionState,
    onDismiss: () -> Unit,
    onConfirm: () -> Unit,
    onMethodSelected: (JailbreakMethod) -> Unit,
    onTargetSelected: (String) -> Unit,
    onSoftRebootChanged: (Boolean) -> Unit,
    onOtaUrlChanged: (String) -> Unit,
    onParse: () -> Unit,
    onLocalBoot: () -> Unit,
    onOverwrite: () -> Unit,
    onCancelOverwrite: () -> Unit,
    onCancel: () -> Unit = onConfirm,
    onShizukuPermission: () -> Unit = {},
) {
    val colors = hiddenFlowColors()
    val failed = ui.outcome?.failure != null && ui.outcome.stage != JailbreakStatus.STAGE_CANCELLED && !ui.running
    var showLogs by rememberSaveable(ui.runId) { mutableStateOf(ui.running || failed) }
    LaunchedEffect(ui.runId, ui.running, failed) {
        if (ui.running || failed) showLogs = true
    }
    val selectionUi = ui.selection
    val parsing = ui.parsing
    HiddenFlowDialog(
        title = stringResource(R.string.maplesu_jailbreak_precheck_title),
        onDismiss = onDismiss,
        confirmLabel = when {
            ui.cancellationPending -> stringResource(R.string.maplesu_jailbreak_cancel_pending)
            ui.running -> stringResource(R.string.maplesu_jailbreak_cancel)
            ui.succeeded -> stringResource(if (ui.softRebootAvailable)
                R.string.reboot_soft else R.string.maplesu_jailbreak_close)
            parsing -> OtaCopy.PARSING
            else -> stringResource(R.string.maplesu_jailbreak_start)
        },
        dismissLabel = stringResource(R.string.maplesu_jailbreak_close),
        confirmEnabled = (ui.running || ui.canStart || ui.succeeded) && !ui.cancellationPending,
        dismissEnabled = !ui.running,
        onConfirm = onConfirm,
    ) {
        HiddenFlowText(stringResource(R.string.maplesu_jailbreak_precheck_description), secondary = true)
        HiddenFlowButton(stringResource(R.string.maplesu_jailbreak_open_logs),
            modifier = Modifier.fillMaxWidth(), onClick = { showLogs = true })
        JailbreakSection(stringResource(R.string.maplesu_jailbreak_method_title)) {
            Column(Modifier.selectableGroup()) {
                listOf(JailbreakMethod.DIRTYFRAG, JailbreakMethod.GHOSTLOCK, JailbreakMethod.MAPLESU_93260, JailbreakMethod.GHOSTSAM).forEach { option ->
                    JailbreakChoice(
                        title = stringResource(when (option) {
                            JailbreakMethod.GHOSTLOCK -> R.string.maplesu_jailbreak_ghostlock
                            JailbreakMethod.DIRTYFRAG -> R.string.maplesu_jailbreak_dirtyfrag
                            JailbreakMethod.MAPLESU_93260 -> R.string.maplesu_jailbreak_93260
                            JailbreakMethod.GHOSTSAM -> R.string.maplesu_jailbreak_ghostlock
                        }),
                        summary = stringResource(when (option) {
                            JailbreakMethod.GHOSTLOCK -> R.string.maplesu_jailbreak_ghostlock_summary
                            JailbreakMethod.DIRTYFRAG -> R.string.maplesu_jailbreak_dirtyfrag_summary
                            JailbreakMethod.MAPLESU_93260 -> R.string.maplesu_jailbreak_93260_summary
                            JailbreakMethod.GHOSTSAM -> R.string.maplesu_jailbreak_ghostlock_summary
                        }),
                        selected = ui.method == option,
                        enabled = !ui.running,
                        onClick = { onMethodSelected(option) },
                    )
                }
            }
        }
        if (ui.method == JailbreakMethod.MAPLESU_93260) {
            if (ui.detectedKernel.isNotBlank()) {
                JailbreakSection(stringResource(R.string.maplesu_jailbreak_93260_detect_title)) {
                    Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        HiddenFlowText(stringResource(R.string.maplesu_jailbreak_93260_detected,
                            ui.detectedModel.ifBlank { stringResource(R.string.maplesu_jailbreak_unknown) },
                            ui.detectedKernel))
                        val label = ui.methodLabel
                        if (!label.isNullOrBlank()) {
                            val missing = ui.blockers.contains(
                                JailbreakBlocker.MAPLESU_93260_PROFILE_NOT_PACKAGED)
                            HiddenFlowText(stringResource(
                                if (missing) R.string.maplesu_jailbreak_93260_variant_missing
                                else R.string.maplesu_jailbreak_93260_variant, label),
                                secondary = true)
                        }
                    }
                }
            }
            JailbreakSection("Shizuku") {
                Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    HiddenFlowText(stringResource(when {
                        !ui.shizuku.running -> R.string.maplesu_jailbreak_shizuku_stopped
                        !ui.shizuku.granted -> R.string.maplesu_jailbreak_shizuku_permission
                        else -> R.string.maplesu_jailbreak_shizuku_ready
                    }), secondary = true)
                    if (ui.shizuku.running && !ui.shizuku.granted)
                        HiddenFlowButton(stringResource(R.string.maplesu_jailbreak_shizuku_authorize),
                            enabled = !ui.running, onClick = onShizukuPermission)
                    HiddenFlowText(stringResource(R.string.maplesu_jailbreak_93260_lifetime), secondary = true)
                    JailbreakSpecialThanks()
                }
            }
        }
        // Selecting Ghostlock opens setup even without a profile. Only Start is
        // gated; DirtyFrag never displays Ghostlock-specific image requirements.
        if (selectionUi.showGhostlockConfiguration && ui.ghostlockDecided) {
            JailbreakSection(stringResource(R.string.maplesu_jailbreak_ghostlock_setup_title)) {
                Column(
                    Modifier.padding(14.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    HiddenFlowText(
                        text = when (ui.setupReason) {
                            GhostlockProfileGate.Reason.LIST_MISSING ->
                                stringResource(R.string.maplesu_jailbreak_ghostlock_list_unavailable)
                            GhostlockProfileGate.Reason.KERNEL_UNKNOWN ->
                                stringResource(R.string.maplesu_jailbreak_block_target_identity)
                            else -> stringResource(R.string.maplesu_jailbreak_ghostlock_setup_description)
                        },
                        secondary = true,
                    )
                    if (ui.awaitingOverwrite) {
                        HiddenFlowText(OtaCopy.OVERWRITE_QUESTION)
                        HiddenFlowButton(
                            text = OtaCopy.OVERWRITE_CONFIRM,
                            modifier = Modifier.fillMaxWidth(),
                            enabled = !ui.running && !parsing,
                            primary = true,
                            onClick = onOverwrite,
                        )
                        HiddenFlowButton(
                            text = OtaCopy.OVERWRITE_CANCEL,
                            modifier = Modifier.fillMaxWidth(),
                            enabled = !ui.running && !parsing,
                            onClick = onCancelOverwrite,
                        )
                    } else {
                        when (LocalUiMode.current) {
                            UiMode.Miuix -> top.yukonga.miuix.kmp.basic.TextField(
                                value = ui.otaUrl,
                                onValueChange = onOtaUrlChanged,
                                enabled = !ui.running && !parsing,
                                maxLines = 1,
                                label = OtaCopy.FIELD_HINT,
                                modifier = Modifier.fillMaxWidth(),
                            )
                            UiMode.Material -> OutlinedTextField(
                                value = ui.otaUrl,
                                onValueChange = onOtaUrlChanged,
                                enabled = !ui.running && !parsing,
                                singleLine = true,
                                label = { HiddenFlowText(OtaCopy.FIELD_HINT) },
                                modifier = Modifier.fillMaxWidth(),
                            )
                        }
                        HiddenFlowButton(
                            text = if (parsing) OtaCopy.PARSING else OtaCopy.ACTION,
                            modifier = Modifier.fillMaxWidth(),
                            enabled = !ui.running && !parsing && ui.otaUrl.isNotBlank(),
                            primary = true,
                            onClick = onParse,
                        )
                        HiddenFlowButton(
                            text = OtaCopy.PICK_LOCAL,
                            modifier = Modifier.fillMaxWidth(),
                            enabled = !ui.running && !parsing,
                            onClick = onLocalBoot,
                        )
                        OtaCopy.lineFor(ui.otaState)?.let { line ->
                            HiddenFlowText(
                                text = line,
                                secondary = true,
                                color = if (ui.otaState is OtaParseState.Failed) colors.error else colors.primary,
                            )
                        }
                    }
                }
            }
        }
        if (ui.method == JailbreakMethod.GHOSTLOCK && !ui.ghostlockDecided) {
            HiddenFlowText(stringResource(R.string.maplesu_jailbreak_probe_loading), secondary = true)
        }
        JailbreakSection(stringResource(R.string.maplesu_jailbreak_target_title)) {
            Column(Modifier.selectableGroup()) {
                listOf(
                    JailbreakRequest.BACKEND_HOOK to R.string.maplesu_jailbreak_target_ultra,
                    JailbreakRequest.BACKEND_KSU to R.string.maplesu_jailbreak_target_normal,
                ).forEach { (backend, label) ->
                    JailbreakChoice(
                        title = stringResource(label),
                        selected = ui.rootTarget == backend,
                        enabled = !ui.running,
                        onClick = { onTargetSelected(backend) },
                    )
                }
            }
        }
        // T11: only a kernel carrier survives a soft reboot. The lease route has no
        // such carrier, so the switch is not offered there at all.
        if (ui.softRebootAvailable) JailbreakSection(stringResource(R.string.maplesu_jailbreak_after_success_title)) {
            when (LocalUiMode.current) {
                UiMode.Miuix -> top.yukonga.miuix.kmp.preference.SwitchPreference(
                    title = stringResource(R.string.maplesu_jailbreak_soft_reboot),
                    checked = ui.softReboot,
                    onCheckedChange = onSoftRebootChanged,
                    enabled = !ui.running,
                )
                UiMode.Material -> Row(
                    Modifier.fillMaxWidth().heightIn(min = 56.dp)
                        .toggleable(
                            value = ui.softReboot,
                            enabled = !ui.running,
                            role = Role.Switch,
                            onValueChange = onSoftRebootChanged,
                        ).padding(horizontal = 14.dp, vertical = 8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    HiddenFlowText(
                        stringResource(R.string.maplesu_jailbreak_soft_reboot),
                        modifier = Modifier.weight(1f),
                    )
                    Switch(checked = ui.softReboot, onCheckedChange = null, enabled = !ui.running)
                }
            }
        }
        if (!ui.running && ui.outcome == null) {
            when {
                ui.probeFailed -> HiddenFlowText(
                    stringResource(R.string.maplesu_jailbreak_probe_failed), secondary = true, color = colors.error)
                !ui.checksReady -> HiddenFlowText(
                    stringResource(R.string.maplesu_jailbreak_probe_loading), secondary = true)
                ui.blockers.isNotEmpty() -> ui.blockers.forEach { blocker ->
                    HiddenFlowText(stringResource(blockerDescription(blocker)), secondary = true, color = colors.error)
                }
                else -> ui.warnings.filterNot {
                    ui.method == JailbreakMethod.GHOSTLOCK && it == JailbreakBlocker.GHOSTLOCK_EXACT_PROFILE_MISSING
                }.forEach { warning ->
                    HiddenFlowText(stringResource(blockerDescription(warning)), secondary = true)
                }
            }
        }
        if (ui.running) {
            HiddenFlowText(
                stringResource(jailbreakStageDescription(ui.observedStage)),
                color = colors.primary,
            )
        }
        if (ui.cancellationFailed) {
            HiddenFlowText(stringResource(R.string.maplesu_jailbreak_cancel_unconfirmed),
                secondary = true, color = colors.error)
        }
        ui.outcome?.let { result ->
            HiddenFlowText(
                text = if (result.stage == JailbreakStatus.STAGE_CANCELLED || result.failure == null)
                    stringResource(jailbreakStageDescription(result.stage))
                    else stringResource(R.string.maplesu_jailbreak_failure, jailbreakFailureText(result.failure)),
                color = if (result.failure == null) colors.primary else colors.error,
            )
            result.failure?.let { code ->
                HiddenFlowText(jailbreakFailureCode(code), secondary = true, color = colors.error)
            }
        }
        HiddenFlowText(stringResource(R.string.maplesu_jailbreak_ephemeral_notice), secondary = true)
    }
    if (showLogs) JailbreakLogSheet(ui = ui, onDismiss = { showLogs = false }, onCancel = onCancel)
}

@Composable
private fun JailbreakSection(title: String, content: @Composable ColumnScope.() -> Unit) {
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        HiddenFlowText(title, Modifier.padding(horizontal = 4.dp), secondary = true)
        when (LocalUiMode.current) {
            UiMode.Miuix -> Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.defaultColors(color = MiuixTheme.colorScheme.surfaceContainer),
                insideMargin = PaddingValues(0.dp),
            ) { Column(content = content) }
            UiMode.Material -> Surface(
                modifier = Modifier.fillMaxWidth(),
                color = MaterialTheme.colorScheme.surfaceContainerHigh,
                shape = MaterialTheme.shapes.large,
            ) { Column(content = content) }
        }
    }
}

@Composable
private fun JailbreakChoice(
    title: String,
    selected: Boolean,
    enabled: Boolean,
    onClick: () -> Unit,
    summary: String? = null,
) {
    val colors = hiddenFlowColors()
    val selectionColor by animateColorAsState(
        targetValue = if (selected) colors.primary.copy(alpha = 0.12f) else Color.Transparent,
        animationSpec = tween(160),
        label = "jailbreakSelection",
    )
    Row(
        modifier = Modifier.fillMaxWidth().heightIn(min = 56.dp)
            .background(selectionColor)
            .selectable(selected = selected, enabled = enabled, role = Role.RadioButton, onClick = onClick)
            .padding(horizontal = 14.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        when (LocalUiMode.current) {
            UiMode.Miuix -> top.yukonga.miuix.kmp.basic.RadioButton(
                selected = selected, onClick = null, enabled = enabled)
            UiMode.Material -> RadioButton(selected = selected, onClick = null, enabled = enabled)
        }
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
            HiddenFlowText(title, color = if (enabled) colors.text else colors.secondary)
            if (summary != null) HiddenFlowText(summary, secondary = true)
        }
    }
}

internal fun jailbreakStageDescription(stage: String?): Int = when (stage) {
    JailbreakStatus.STAGE_TARGET_CHECKED -> R.string.maplesu_jailbreak_progress_preparing
    JailbreakStatus.STAGE_HANDOFF_AUTHENTICATED,
    JailbreakStatus.STAGE_ROOT_WORKER_OBSERVED -> R.string.maplesu_jailbreak_progress_connecting
    JailbreakStatus.STAGE_DAEMON_READY -> R.string.maplesu_jailbreak_progress_complete
    JailbreakStatus.STAGE_CANCELLED -> R.string.maplesu_jailbreak_progress_cancelled
    JailbreakStatus.STAGE_EXPIRED -> R.string.maplesu_jailbreak_progress_expired
    JailbreakStatus.STAGE_FAILED -> R.string.maplesu_jailbreak_progress_failed
    else -> R.string.maplesu_jailbreak_running
}

@Composable
private fun blockerDescription(blocker: JailbreakBlocker): Int = when (blocker) {
    JailbreakBlocker.MAPLESU_93260_KERNEL_UNSUPPORTED -> R.string.maplesu_jailbreak_93260_kernel
    JailbreakBlocker.MAPLESU_93260_PROFILE_NOT_PACKAGED ->
        R.string.maplesu_jailbreak_93260_profile_missing
    JailbreakBlocker.TARGET_IDENTITY_MISSING -> R.string.maplesu_jailbreak_block_target_identity
    JailbreakBlocker.ABI_UNSUPPORTED -> R.string.maplesu_jailbreak_block_abi
    JailbreakBlocker.EXACT_KMI_UNSUPPORTED -> R.string.maplesu_jailbreak_block_kmi
    JailbreakBlocker.GHOSTLOCK_EXACT_PROFILE_MISSING -> R.string.maplesu_jailbreak_block_profile
    JailbreakBlocker.ARTIFACT_UNVERIFIED -> R.string.maplesu_jailbreak_block_artifact
    JailbreakBlocker.TARGET_NOT_VERIFIED -> R.string.maplesu_jailbreak_block_not_verified
    JailbreakBlocker.SECONDARY_USER_UNSUPPORTED -> R.string.maplesu_jailbreak_block_user
}

