package dev.maplesu.manager.litehidden

import com.maplesu.core.ksuApp
import dev.maplesu.manager.runtime.RootExec
import dev.maplesu.manager.runtime.ultra.UltraAuthorization
import dev.maplesu.manager.workmode.ModeRuntime
import dev.maplesu.manager.workmode.WorkMode
import kotlinx.coroutines.runBlocking

/**
 * **debug-only** 设备验证入口（`manager/src/debug`，不进 release APK）。
 *
 * 用 instrumentation 在管理器自己的进程里调用，跑真实的后端事务并把分步结果、root 侧事实
 * 原样打印出来（`am instrument -w` 直接可见）。这不是产品 API：没有 UI、没有注入面，
 * 只用于「隐藏后端激活/解除」的真机取证（见 `.analysis/hidden-backend-verify-<date>/`）。
 *
 * 输出里**不含** token / rootKey / 凭据：恢复链接只报是否存在。
 */
object HiddenBackendDiagnostics {

    @JvmStatic
    fun activate(host: String, port: Int): String = runBlocking {
        val waited = ModeRuntime.awaitActivated(15_000)
        val installed = runCatching { HiddenModeWiring.installNow(ksuApp) }.getOrDefault(false)
        val mode = ModeRuntime.active
        if (HiddenModeBackends.current == null) {
            return@runBlocking "activate ok=false code=BACKEND_UNAVAILABLE mode=${mode?.suffix ?: "unresolved"} installed=$installed"
        }
        val result = runCatching { HiddenModeBackends.activate(host, port) }.getOrNull()
            ?: return@runBlocking "activate ok=false code=BACKEND_EXCEPTION mode=${mode?.suffix}"
        buildString {
            appendLine("activate ok=${result.success} code=${result.code} host=${result.hostPackage}")
            appendLine("mode=${mode?.suffix ?: "unresolved"} installed=$installed awaited=${waited?.suffix ?: "timeout"}")
            appendLine("recovery_url_present=${result.recoveryUrl.isNotBlank()}")
            result.steps.forEach { step ->
                appendLine("step ${step.step} ok=${step.ok} code=${step.code} detail=${step.detail}")
            }
        }
    }

    @JvmStatic
    fun deactivate(host: String): String = runBlocking {
        ModeRuntime.awaitActivated(10_000)
        runCatching { HiddenModeWiring.installNow(ksuApp) }
        val result = runCatching { HiddenModeBackends.deactivate(host) }.getOrNull()
            ?: return@runBlocking "deactivate ok=false code=BACKEND_EXCEPTION"
        buildString {
            appendLine("deactivate ok=${result.success} code=${result.code} host=${result.hostPackage}")
            appendLine(
                "flags host_so_restored=${result.hostSoRestored} " +
                    "su_auth_revoked=${result.suAuthRevoked} daemon_stopped=${result.daemonStopped}",
            )
            result.steps.forEach { step ->
                appendLine("step ${step.step} ok=${step.ok} code=${step.code} detail=${step.detail}")
            }
        }
    }

    /** root 侧事实快照：隐藏位、宿主 lib 的 sha、备份清单、daemon pid/端口、su_auth 成员。 */
    @JvmStatic
    fun snapshot(host: String, port: Int): String {
        fun root(script: String): String =
            runCatching { RootExec.execute(script) }.getOrNull()?.output.orEmpty().trim()

        val hidden = root("cat /data/adb/maplesu/lite_hidden 2>/dev/null")
        val libDir = root("cat /data/adb/maplesu/recovery/host/$host/libdir.txt 2>/dev/null")
        val label = root("cat /data/adb/maplesu/recovery/host/$host/label.txt 2>/dev/null")
        val shas = if (libDir.startsWith("/")) root("sha256sum '$libDir'/*.so 2>/dev/null") else ""
        val manifest = root("cat /data/adb/maplesu/recovery/host/$host/host.manifest 2>/dev/null")
        val pid = root("cat /data/adb/maplesu/recovery/liteweb.pid 2>/dev/null")
        val pidState = if (pid.isNotEmpty()) {
            root("kill -0 '$pid' 2>/dev/null && echo ALIVE || echo DEAD")
        } else {
            "none"
        }
        val portHex = port.toString(16).uppercase().padStart(4, '0')
        val listen = root("cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | grep -c ':$portHex '")
        val suAuth = runCatching {
            UltraAuthorization.refresh(ksuApp)
            "${UltraAuthorization.isGranted(host)} count=${UltraAuthorization.grantedPackages().size}"
        }.getOrDefault("unavailable")
        val stealth = runCatching { com.maplesu.core.ui.security.Stealth.state().name }.getOrDefault("unavailable")
        return buildString {
            appendLine("Snapshot host=$host port=$port")
            appendLine("mode=${ModeRuntime.active?.suffix ?: "unresolved"} api=${WorkMode.LITE.suffix}")
            appendLine("hidden=$hidden")
            appendLine("libdir=$libDir")
            appendLine("label=$label")
            appendLine("listen_count=$listen")
            appendLine("daemon_pid=$pid state=$pidState")
            appendLine("su_auth=$suAuth")
            appendLine("stealth=$stealth")
            appendLine("--- lib shas ---")
            appendLine(shas)
            appendLine("--- host.manifest ---")
            appendLine(manifest)
        }
    }
}
