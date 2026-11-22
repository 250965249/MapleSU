package dev.maplesu.manager.parasite

import android.content.Context
import dev.maplesu.manager.runtime.MapleSuCredentialStore
import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.superuser.LiteImplantQuiesceGate
import java.io.File
import java.util.concurrent.TimeUnit

/** runtime CLI 一次调用的结果（退出码 + stdout/stderr）。 */
data class RuntimeCliInvocation(val code: Int, val out: String, val err: String)

/** 运行 `libmaplesu_runtime.so` 子命令的调用器（可注入，主机测试不启动进程）。 */
interface RuntimeCliInvoker {
    fun invoke(executable: File, credential: ByteArray, vararg arguments: String): RuntimeCliInvocation
}

/** 生产调用器：与 `SuPathWiring.invoke` 相同的 4+48 凭证帧 + 双流读取 + 60s 上限。 */
class ProcessRuntimeCliInvoker : RuntimeCliInvoker {
    override fun invoke(
        executable: File,
        credential: ByteArray,
        vararg arguments: String,
    ): RuntimeCliInvocation {
        val process = runCatching {
            ProcessBuilder(listOf(executable.absolutePath) + arguments)
                .redirectErrorStream(false)
                .start()
        }.getOrElse { return RuntimeCliInvocation(-1, "", "runtime start failed") }
        try {
            runCatching {
                process.outputStream.use { input ->
                    input.write(byteArrayOf(0, 0, 0, 48))
                    input.write(credential)
                    input.flush()
                }
            }.getOrElse {
                process.destroyForcibly()
                return RuntimeCliInvocation(-1, "", "credential frame write failed")
            }
        } finally {
            credential.fill(0)
        }
        val out = StringBuilder()
        val err = StringBuilder()
        val outThread = Thread {
            runCatching { process.inputStream.bufferedReader().use { out.append(it.readText()) } }
        }.apply { isDaemon = true; start() }
        val errThread = Thread {
            runCatching { process.errorStream.bufferedReader().use { err.append(it.readText()) } }
        }.apply { isDaemon = true; start() }
        val finished = runCatching { process.waitFor(60, TimeUnit.SECONDS) }.getOrDefault(false)
        if (!finished) process.destroyForcibly()
        outThread.join(2_000)
        errThread.join(2_000)
        return RuntimeCliInvocation(if (finished) process.exitValue() else -1, out.toString(), err.toString())
    }
}

/**
 * 寄生端口的生产实现（**Lite / 模式 A 专用**）：调用 Lite runtime kit 的 CLI。
 *
 * 三调用与 runtime 子命令的对应：
 * - [precheck]  → `--wire-su-precheck <cmdline>`（stdout 每行 `状态 <so 绝对路径>`）；
 * - [implantApp]→ `--implant-app <cmdline> <so>`（stdout `IMPLANTED:<so>`）；
 * - [implantSuEnv] → `--wire-su-env <cmdline> <so> <su_dir>`（stdout `WIRED:<so>`）。
 *
 * 退出码映射（与 `runtime/src/exec_main.cpp` 一致）：
 * 65 → CREDENTIAL_UNAVAILABLE，66 → PRECHECK_FAILED，67 → SU_ENV_FAILED，68 → IMPLANT_FAILED；
 * 其它非 0 按所在子命令归入对应失败码（不伪造成功）。
 * 模式切换静默期（[LiteImplantQuiesceGate]）拒绝新动作 → QUIESCING。
 */
class LiteParasiteSdkPort(
    private val executable: File,
    private val credentialProvider: () -> ByteArray?,
    private val invoker: RuntimeCliInvoker = ProcessRuntimeCliInvoker(),
    private val quiescing: () -> Boolean = { LiteImplantQuiesceGate.isBlocked() },
) : ParasiteSdkPort {

    override fun precheck(targetPidCmdline: String): ParasiteSdkResult {
        validate(targetPidCmdline)?.let { return it }
        blocked()?.let { return it }
        runtimeUnavailable()?.let { return it }
        val credential = credential() ?: return credentialFailure()
        val invocation = invoker.invoke(executable, credential, "--wire-su-precheck", targetPidCmdline)
        return when (invocation.code) {
            0 -> {
                val dynlibs = parseDynlibs(invocation.out)
                    ?: return ParasiteSdkResult.Failed(ParasiteCodes.STATUS_UNKNOWN, firstLine(invocation))
                if (dynlibs.isEmpty()) {
                    ParasiteSdkResult.Failed(ParasiteCodes.NO_ELIGIBLE_DYNLIB, "no eligible dynlib")
                } else {
                    ParasiteSdkResult.Ok(dynlibs)
                }
            }
            EXIT_CREDENTIAL -> credentialFailure(invocation)
            else -> ParasiteSdkResult.Failed(ParasiteCodes.PRECHECK_FAILED, describe(invocation))
        }
    }

    override fun implantApp(targetPidCmdline: String, soPath: String): ParasiteSdkResult {
        validate(targetPidCmdline)?.let { return it }
        validate(soPath, "soPath")?.let { return it }
        blocked()?.let { return it }
        runtimeUnavailable()?.let { return it }
        val credential = credential() ?: return credentialFailure()
        val invocation = invoker.invoke(executable, credential, "--implant-app", targetPidCmdline, soPath)
        return when (invocation.code) {
            0 -> ParasiteSdkResult.Ok()
            EXIT_CREDENTIAL -> credentialFailure(invocation)
            else -> ParasiteSdkResult.Failed(ParasiteCodes.IMPLANT_FAILED, describe(invocation))
        }
    }

    override fun implantSuEnv(targetPidCmdline: String, soPath: String, suDir: String): ParasiteSdkResult {
        validate(targetPidCmdline)?.let { return it }
        validate(soPath, "soPath")?.let { return it }
        validate(suDir, "suDir")?.let { return it }
        blocked()?.let { return it }
        runtimeUnavailable()?.let { return it }
        val credential = credential() ?: return credentialFailure()
        val invocation = invoker.invoke(
            executable, credential, "--wire-su-env", targetPidCmdline, soPath, suDir,
        )
        return when (invocation.code) {
            0 -> ParasiteSdkResult.Ok()
            EXIT_CREDENTIAL -> credentialFailure(invocation)
            EXIT_SU_ENV -> ParasiteSdkResult.Failed(ParasiteCodes.SU_ENV_FAILED, describe(invocation))
            else -> ParasiteSdkResult.Failed(ParasiteCodes.SU_ENV_FAILED, describe(invocation))
        }
    }

    private fun validate(value: String, field: String = "targetPidCmdline"): ParasiteSdkResult.Failed? =
        if (value.isBlank()) {
            ParasiteSdkResult.Failed(ParasiteCodes.INVALID_ARGUMENT, "$field blank")
        } else {
            null
        }

    private fun blocked(): ParasiteSdkResult.Failed? =
        if (quiescing()) ParasiteSdkResult.Failed(ParasiteCodes.QUIESCING, "writes quiesced") else null

    private fun runtimeUnavailable(): ParasiteSdkResult.Failed? =
        if (executable.isFile) {
            null
        } else {
            ParasiteSdkResult.Failed(ParasiteCodes.ULTRA_UNAVAILABLE, "runtime image unavailable: ${executable.name}")
        }

    private fun credential(): ByteArray? =
        runCatching { credentialProvider() }.getOrNull()?.takeIf { it.size == CREDENTIAL_SIZE }

    private fun credentialFailure(invocation: RuntimeCliInvocation? = null): ParasiteSdkResult.Failed {
        val why = invocation?.let { describe(it) } ?: "no paired credential"
        return ParasiteSdkResult.Failed(ParasiteCodes.CREDENTIAL_UNAVAILABLE, why)
    }

    /** 解析 `状态 <path>` 行；状态整数未知 → null（调用方报 STATUS_UNKNOWN，不默认状态）。 */
    private fun parseDynlibs(out: String): List<AppDynlibInfo>? {
        val lines = out.lineSequence().map { it.trim() }.filter { it.isNotEmpty() }.toList()
        if (lines.isEmpty()) return emptyList()
        val result = mutableListOf<AppDynlibInfo>()
        for (line in lines) {
            val separator = line.indexOf(' ')
            if (separator <= 0) return null
            val statusCode = line.substring(0, separator).toIntOrNull() ?: return null
            val path = line.substring(separator + 1).trim()
            if (path.isEmpty()) return null
            val status = when (statusCode) {
                STATUS_UNKNOWN -> AppDynlibStatus.UNKNOWN
                STATUS_RUNNING -> AppDynlibStatus.RUNNING
                STATUS_NOT_RUNNING -> AppDynlibStatus.NOT_RUNNING
                else -> return null
            }
            result += AppDynlibInfo(path, status)
        }
        return result
    }

    private fun describe(invocation: RuntimeCliInvocation): String {
        val detail = firstLine(invocation)
        return "exit=${invocation.code}: ${detail.take(160)}"
    }

    private fun firstLine(invocation: RuntimeCliInvocation): String =
        invocation.err.lineSequence().firstOrNull { it.isNotBlank() }
            ?: invocation.out.lineSequence().firstOrNull { it.isNotBlank() }
            ?: "no diagnostic"

    companion object {
        const val CREDENTIAL_SIZE = 48

        /** runtime CLI 退出码（与 exec_main.cpp 一致）。 */
        const val EXIT_CREDENTIAL = 65
        const val EXIT_PRECHECK = 66
        const val EXIT_SU_ENV = 67
        const val EXIT_IMPLANT_APP = 68

        /** `kernel_root::AppDynlibStatus`（Unknown=0/Running=1/NotRunning=2）。 */
        const val STATUS_UNKNOWN = 0
        const val STATUS_RUNNING = 1
        const val STATUS_NOT_RUNNING = 2

        /** 从 Context 构造：runtime 镜像来自 nativeLibraryDir，凭证来自既有 Keystore 存储。 */
        fun forContext(context: Context): LiteParasiteSdkPort {
            val application = context.applicationContext
            return LiteParasiteSdkPort(
                executable = File(application.applicationInfo.nativeLibraryDir, "libmaplesu_runtime.so"),
                credentialProvider = {
                    runCatching { MapleSuCredentialStore(application).load() }.getOrNull()
                },
            )
        }
    }
}

/**
 * 模式端口选择：只有 A（LITE）调用其端口工厂（生产为 Ultra SDK）；KSU/未判定一律
 * `ULTRA_UNAVAILABLE`（不默认 LITE，不假装能力）。纯函数便于主机测试。
 */
fun selectProductionParasitePort(
    mode: WorkMode?,
    litePort: () -> ParasiteSdkPort,
    unavailablePort: () -> ParasiteSdkPort = { UnavailableParasiteSdkPort(UltraAvailability.RUNNING) },
): ParasiteSdkPort = if (mode == WorkMode.LITE) litePort() else unavailablePort()
