package dev.maplesu.manager.workmode.service

import android.content.Context
import android.os.Bundle
import android.os.ParcelFileDescriptor
import dev.maplesu.manager.installer.InstallerServiceClient
import dev.maplesu.manager.workmode.switch.ModeSwitchHashes
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

/**
 * [ModeSwitchClient] 的真实实现：`InstallerServiceClient` 的 12 个 AIDL 方法 + Bundle 解码。
 *
 * 结果回执以 [ClientResult] 返回；连接/代理异常仍由调用方处理。
 */
internal class ServiceClientModeSwitchClient(
    context: Context,
) : ModeSwitchClient {

    private val appContext = context.applicationContext

    override suspend fun preflight(switchId: String, planFields: Map<String, String>): ClientResult =
        io {
            decodeResult(
                InstallerServiceClient.preflightModeSwitch(appContext, switchId,
                    ModeSwitchAidlCodec.planBundle(switchId, planFields)),
                switchId,
            )
        }

    override suspend fun begin(switchId: String, planFields: Map<String, String>,
                               superuserJson: File, settingsMirrorJson: File): ClientResult = io {
        decodeResult(
            InstallerServiceClient.beginModeSwitch(
                appContext, switchId, ModeSwitchAidlCodec.planBundle(switchId, planFields),
                superuserJson, settingsMirrorJson,
            ),
            switchId,
        )
    }

    override suspend fun snapshot(switchId: String): ClientResult = io {
        decodeResult(InstallerServiceClient.snapshotModeSwitch(appContext, switchId), switchId)
    }

    override suspend fun exportImage(switchId: String, kind: String, partition: String,
                                     destination: File): Boolean = io {
        runCatching {
            destination.parentFile?.mkdirs()
            val (meta, pfd) = InstallerServiceClient.openSwitchImage(appContext, switchId, kind, partition)
            ParcelFileDescriptor.AutoCloseInputStream(pfd).use { input ->
                val size = meta.getLong("size")
                val sha = meta.getString("sha256").orEmpty()
                if (size <= 0 || !ModeSwitchHashes.isHash(sha)) return@runCatching false
                val copied = destination.outputStream().use { output ->
                    val count = input.copyTo(output)
                    output.fd.sync()
                    count
                }
                copied == size && destination.isFile && destination.length() == size &&
                    ModeSwitchHashes.sha256(destination).equals(sha, ignoreCase = true)
            }
        }.getOrDefault(false)
    }

    override suspend fun submitCandidate(switchId: String, partition: String,
                                         candidate: File, candidateSha256: String): ClientResult = io {
        decodeResult(
            InstallerServiceClient.submitSwitchCandidate(
                appContext, switchId, partition, candidate, candidateSha256,
            ),
            switchId,
        )
    }

    override suspend fun commit(switchId: String): ClientResult = io {
        decodeResult(InstallerServiceClient.commitModeSwitch(appContext, switchId), switchId)
    }

    override suspend fun rollback(switchId: String): ClientResult = io {
        decodeResult(InstallerServiceClient.rollbackModeSwitch(appContext, switchId), switchId)
    }

    override suspend fun abort(switchId: String): ClientResult = io {
        decodeResult(InstallerServiceClient.abortModeSwitch(appContext, switchId), switchId)
    }

    override fun status(switchId: String): ClientStatus? = runCatching {
        require(!Thread.currentThread().name.contains("main"))
        decodeStatus(InstallerServiceClient.getModeSwitch(appContext, switchId))
    }.getOrNull()

    override fun statusExact(switchId: String): ClientStatus? {
        require(!Thread.currentThread().name.contains("main"))
        val bundle = InstallerServiceClient.getModeSwitch(appContext, switchId)
        check(bundle.containsKey("state") &&
            (switchId.isEmpty() || bundle.getString("switchId") == switchId)) {
            "INSTALLER_SERVICE_RESPONSE_INVALID"
        }
        if (bundle.getString("state").isNullOrBlank()) {
            val error = bundle.getString("error").orEmpty()
            check(error.isEmpty()) { error }
            return null
        }
        check(!bundle.getString("switchId").isNullOrBlank()) { "INSTALLER_SERVICE_RESPONSE_INVALID" }
        return decodeStatus(bundle)
    }

    override suspend fun verify(switchId: String): ClientResult = io {
        decodeResult(InstallerServiceClient.verifyModeSwitch(appContext, switchId), switchId)
    }

    override suspend fun markRebootRequested(switchId: String): Boolean = io {
        runCatching { InstallerServiceClient.rebootAfterModeSwitch(appContext, switchId) }.getOrDefault(false)
    }

    override suspend fun exportLog(switchId: String, destination: File): File? = io {
        runCatching { InstallerServiceClient.exportSwitchLog(appContext, switchId, destination) }.getOrNull()
    }

    // ------------------------------------------------------------------ codec

    private fun decodeResult(bundle: Bundle, switchId: String): ClientResult {
        if (!bundle.containsKey("ok") || bundle.getString("switchId") != switchId) {
            return ClientResult(false, "INSTALLER_SERVICE_RESPONSE_INVALID")
        }
        val error = bundle.getString("error").orEmpty()
        val ok = bundle.getBoolean("ok", false) && error.isEmpty()
        return ClientResult(
            ok = ok,
            code = if (ok) "" else error.ifEmpty { "SWITCH_SERVICE_FAILED" },
            detail = bundle.getString("errorDetail").orEmpty(),
            status = decodeStatus(bundle),
        )
    }

    private fun decodeStatus(bundle: Bundle): ClientStatus? {
        val switchId = bundle.getString("switchId").orEmpty()
        if (switchId.isEmpty() && bundle.getString("state").orEmpty().isEmpty()) return null
        val names = bundle.getStringArrayList("partitions").orEmpty()
        val partitions = names.mapNotNull { name ->
            val row = bundle.getBundle(name) ?: return@mapNotNull null
            ClientPartition(
                name = name,
                role = row.getString("role").orEmpty(),
                size = row.getLong("size"),
                preSha256 = row.getString("preSha256").orEmpty(),
                targetSha256 = row.getString("targetSha256").orEmpty(),
                observedSha256 = row.getString("observedSha256").orEmpty(),
                state = row.getString("state").orEmpty(),
            )
        }
        return ClientStatus(
            switchId = switchId,
            state = bundle.getString("state").orEmpty(),
            stage = bundle.getString("stage").orEmpty(),
            step = bundle.getString("step").orEmpty(),
            fromMode = bundle.getString("fromMode").orEmpty(),
            toMode = bundle.getString("toMode").orEmpty(),
            error = bundle.getString("error").orEmpty(),
            errorDetail = bundle.getString("errorDetail").orEmpty(),
            planSha256 = bundle.getString("planSha256").orEmpty(),
            rebootRequired = bundle.getBoolean("rebootRequired"),
            bootObserved = bundle.getBoolean("bootObserved"),
            canRollback = bundle.getBoolean("canRollback"),
            canResumeReboot = bundle.getBoolean("canResumeReboot"),
            verifyFailures = bundle.getInt("verifyFailures"),
            partitions = partitions,
            slotSuffix = bundle.getString(dev.maplesu.installer.SwitchPlan.DEVICE_SLOT),
            targetPartition = bundle.getString("targetPartition"),
            signingMode = bundle.getString("signingMode") ?: "",
        )
    }

    private suspend fun <T> io(block: () -> T): T = withContext(Dispatchers.IO) { block() }
}
