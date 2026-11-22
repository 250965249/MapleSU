package dev.maplesu.manager.recovery

import java.io.ByteArrayOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * 开机自启恢复模块（Ultra 模块 / KSU 模块共用脚本内容；主机可测）。
 *
 * 内容（**不写密令/rootKey/token**）：
 * - `module.prop`：标准模块元数据（KSU/Magisk 使用；Ultra SDK 若要求 `libmodule_*.so` 描述符，
 *   安装器会显式拒绝——见 [UltraModuleFormat] 审计，不假装可安装）；
 * - `service.sh`：开机后从 `/data/adb/maplesu/recovery/manager.apk` 副本启动自包含 daemon，
 *   写 `/data/adb/maplesu/boot-hook.log`（时间/pid/端口），并写一份到
 *   `/sdcard/Download/maplesu_boot_probe.log` 供 adb 读取（/data/adb 对 adb shell 不可读）；
 * - `post-fs-data.sh`：仅记录启动阶段；`uninstall.sh`：清理 daemon/pid。
 */
object BootHookModule {
    const val MODULE_ID = "maplesu_boot_hook"
    const val RECOVERY_APK = "/data/adb/maplesu/recovery/manager.apk"
    const val RECOVERY_CONFIG = "/data/adb/maplesu/recovery/webui.conf"
    const val BOOT_LOG = "/data/adb/maplesu/boot-hook.log"
    const val PROBE_LOG = "/sdcard/Download/maplesu_boot_probe.log"
    const val DAEMON_CLASS = "dev.maplesu.manager.liteweb.daemon.LiteWebDaemonMain"

    val SERVICE_SCRIPT: String = buildString {
        appendLine("#!/system/bin/sh")
        appendLine("MODDIR=\${0%/*}")
        appendLine("LOG=$BOOT_LOG")
        appendLine("PROBE=$PROBE_LOG")
        appendLine("mkdir -p /data/adb/maplesu 2>/dev/null")
        appendLine("TS=\$(date '+%Y-%m-%d %H:%M:%S')")
        appendLine("if [ ! -f '$RECOVERY_APK' ]; then")
        appendLine("  echo \"\$TS recovery apk missing\" >> \"\$LOG\" 2>/dev/null")
        appendLine("  echo \"\$TS recovery apk missing\" >> \"\$PROBE\" 2>/dev/null")
        appendLine("  exit 0")
        appendLine("fi")
        appendLine("DAEMON_PID=\$(pidof maplesu-liteweb 2>/dev/null)")
        appendLine("if [ -z \"\$DAEMON_PID\" ]; then")
        // classpath 必须走 CLASSPATH 环境变量：app_process 只把 `--nice-name=` 之类当开关，
        // `-Djava.class.path=` 会被当成主类名（真机表现为 Unable to find class）。
        appendLine("  CLASSPATH='$RECOVERY_APK' nohup /system/bin/app_process /system/bin \\")
        appendLine("    --nice-name=maplesu-liteweb $DAEMON_CLASS \\")
        appendLine("    </dev/null >>/data/adb/maplesu/boot-hook-daemon.log 2>&1 &")
        appendLine("  DAEMON_PID=\$!")
        appendLine("fi")
        appendLine("sleep 1")
        appendLine("echo \"\$TS pid=\$DAEMON_PID config=$RECOVERY_CONFIG\" >> \"\$LOG\" 2>/dev/null")
        appendLine("echo \"\$TS pid=\$DAEMON_PID\" >> \"\$PROBE\" 2>/dev/null")
        appendLine("chmod 600 \"\$LOG\" 2>/dev/null")
    }

    val POST_FS_DATA_SCRIPT: String = buildString {
        appendLine("#!/system/bin/sh")
        appendLine("echo \"post-fs-data \$(date '+%Y-%m-%d %H:%M:%S')\" >> '$BOOT_LOG' 2>/dev/null")
    }

    val UNINSTALL_SCRIPT: String = buildString {
        appendLine("#!/system/bin/sh")
        appendLine("pidof maplesu-liteweb 2>/dev/null | xargs -r kill 2>/dev/null")
    }

    val MODULE_PROP: String = buildString {
        appendLine("id=$MODULE_ID")
        appendLine("name=MapleSU boot recovery hook")
        appendLine("version=1.0.0")
        appendLine("versionCode=1")
        appendLine("author=MapleSU")
        appendLine("description=Starts the self-contained WebUI recovery daemon after boot.")
    }

    /** 生成模块 zip（KSU/Magisk 标准结构；Ultra 安装需先通过描述符审计）。 */
    fun buildZip(): ByteArray {
        val out = ByteArrayOutputStream()
        ZipOutputStream(out).use { zip ->
            fun put(name: String, content: String) {
                zip.putNextEntry(ZipEntry(name))
                zip.write(content.toByteArray(Charsets.UTF_8))
                zip.closeEntry()
            }
            put("module.prop", MODULE_PROP)
            put("service.sh", SERVICE_SCRIPT)
            put("post-fs-data.sh", POST_FS_DATA_SCRIPT)
            put("uninstall.sh", UNINSTALL_SCRIPT)
        }
        return out.toByteArray()
    }

    fun entries(zipBytes: ByteArray): List<String> = runCatching {
        java.util.zip.ZipInputStream(java.io.ByteArrayInputStream(zipBytes)).use { input ->
            val names = mutableListOf<String>()
            while (true) {
                val entry = input.nextEntry ?: break
                names += entry.name
            }
            names
        }
    }.getOrDefault(emptyList())
}

/** Ultra 模块格式要求：模块包需要 `libmodule_*.so` 描述符。 */
object UltraModuleFormat {
    /** 参考 zip 根级存在 `libmodule_*.so` 与配套目录；纯脚本 zip 不能作为 Ultra 模块安装。 */
    const val REQUIRES_DESCRIPTOR_ELF = true
}

sealed interface BootHookInstallResult {
    data class Ok(val moduleId: String) : BootHookInstallResult
    data class Failed(val code: String, val detail: String = "") : BootHookInstallResult
}

sealed interface BootHookVerifyResult {
    data class Installed(val moduleId: String, val detail: String = "") : BootHookVerifyResult
    data class Missing(val code: String, val detail: String = "") : BootHookVerifyResult
}

/** 模块安装后端（Ultra SDK install_module / KSU 模块目录）；生产实现见 Backend。 */
interface BootHookInstaller {
    fun install(moduleZip: ByteArray, moduleId: String): BootHookInstallResult

    fun verify(moduleId: String): BootHookVerifyResult

    fun uninstall(moduleId: String): BootHookInstallResult
}

/** 证据：daemon 在重启后确实在监听（才允许 proven）。 */
data class BootHookEvidence(
    val bootId: String,
    val recordedAt: Long,
    val daemonPid: Int?,
    val port: Int?,
    val moduleLog: String,
    val serviceScriptRan: Boolean,
    val daemonListening: Boolean,
) {
    fun evidenceJson(): String = buildString {
        append('{')
        append("\"bootId\":\"").append(escape(bootId)).append("\",")
        append("\"recordedAt\":").append(recordedAt).append(',')
        append("\"daemonPid\":").append(daemonPid ?: 0).append(',')
        append("\"port\":").append(port ?: 0).append(',')
        append("\"serviceScriptRan\":").append(serviceScriptRan).append(',')
        append("\"daemonListening\":").append(daemonListening).append(',')
        append("\"moduleLog\":\"").append(escape(moduleLog)).append("\"")
        append('}')
    }

    private fun escape(value: String): String =
        value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n")

    companion object {
        /** 只有 service.sh 真执行 + daemon 真监听 + pid 存在 → proven。 */
        fun proven(evidence: BootHookEvidence?): Boolean =
            evidence != null && evidence.serviceScriptRan && evidence.daemonListening && evidence.daemonPid != null
    }
}
