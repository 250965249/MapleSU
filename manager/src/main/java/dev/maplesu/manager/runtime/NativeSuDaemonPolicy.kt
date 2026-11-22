package dev.maplesu.manager.runtime

import android.content.Context
import android.os.Looper
import android.system.Os
import android.util.AtomicFile
import org.json.JSONObject
import java.io.File
import java.security.MessageDigest
import java.util.concurrent.TimeUnit

/** Installs only the fixed socket transport rules, preserving global Enforcing. */
internal object NativeSuDaemonPolicy {
    private var applied: String? = null

    @Synchronized
    fun check(context: Context): String = execute(context, apply = false)

    @Synchronized
    fun ensure(context: Context): String = applied ?: execute(context, apply = true).also { applied = it }

    private fun execute(context: Context, apply: Boolean): String {
        kotlin.check(Looper.myLooper() != Looper.getMainLooper()) { "SU_POLICY_BACKGROUND_THREAD_REQUIRED" }
        val executable = File(context.applicationInfo.nativeLibraryDir, "libmaplesu_policy.so")
        kotlin.check(executable.isFile && executable.canExecute()) { "SU_POLICY_TOOL_UNAVAILABLE" }
        val bytes = context.assets.open("maplesu-su-socket.rule").use { it.readBytes() }
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
        val source = File(context.noBackupFilesDir, "su-daemon-policy.rule")
        val atomic = AtomicFile(source)
        val stream = atomic.startWrite()
        try {
            Os.fchmod(stream.fd, 0x180) // 0600
            stream.write(bytes)
            atomic.finishWrite(stream)
        } catch (error: Exception) {
            atomic.failWrite(stream)
            throw error
        }
        // Freeze the asset in a root-owned directory before the loader reads it.
        // Neither this entry point nor its CLI accepts external module rules.
        val applyCommand = if (apply) "${quote(executable.absolutePath)} apply --rules \"${'$'}rules\"" else ""
        val script = """
            (
            set -eu
            stage=enforcing
            trap 'code=${'$'}?; if [ "${'$'}code" -ne 0 ]; then /system/bin/printf "SU_POLICY_STAGE:%s exit=%s\n" "${'$'}stage" "${'$'}code" >&2; fi' EXIT
            test "${'$'}(/system/bin/getenforce)" = Enforcing
            stage=parent_directory
            test ! -L /data/adb
            if [ ! -d /data/adb ]; then
                /system/bin/mkdir /data/adb
                /system/bin/chown 0:0 /data/adb
                /system/bin/chmod 0700 /data/adb
            fi
            test "${'$'}(/system/bin/stat -c %u /data/adb)" = 0
            test "${'$'}((8#${'$'}(/system/bin/stat -c %a /data/adb) & 8#22))" -eq 0
            base=/data/adb/maplesu-su-policy
            stage=private_directory
            test ! -L "${'$'}base"
            /system/bin/mkdir -p "${'$'}base"
            test "${'$'}(/system/bin/stat -c %u "${'$'}base")" = 0
            /system/bin/chmod 0700 "${'$'}base"
            rules=${'$'}(/system/bin/mktemp "${'$'}base/rules.XXXXXX")
            trap 'code=${'$'}?; /system/bin/rm -f "${'$'}rules"; if [ "${'$'}code" -ne 0 ]; then /system/bin/printf "SU_POLICY_STAGE:%s exit=%s\n" "${'$'}stage" "${'$'}code" >&2; fi' EXIT
            stage=freeze_asset
            test ! -L ${quote(source.absolutePath)}
            /system/bin/cat ${quote(source.absolutePath)} > "${'$'}rules"
            /system/bin/chmod 0400 "${'$'}rules"
            test "${'$'}(/system/bin/sha256sum "${'$'}rules" | /system/bin/cut -d ' ' -f 1)" = '$digest'
            stage=check
            ${quote(executable.absolutePath)} check --rules "${'$'}rules"
            stage=apply
            $applyCommand
            test "${'$'}(/system/bin/getenforce)" = Enforcing
            )
        """.trimIndent()
        val result = MapleSuRuntime.openShell(context).use { shell ->
            shell.newJob().add(script).to(ArrayList<String>(), ArrayList<String>())
                .enqueue().get(30, TimeUnit.SECONDS)
        }
        val output = result.out.joinToString("\n")
        kotlin.check(result.isSuccess) {
            "SU_POLICY_${if (apply) "APPLY" else "CHECK"}_FAILED exit=${result.code}: $output\n${result.err.joinToString("\n")}"
        }
        val report = result.out.lastOrNull { line ->
            runCatching { JSONObject(line).optString("event") == "result" }.getOrDefault(false)
        }?.let(::JSONObject) ?: error("SU_POLICY_RESULT_MISSING")
        kotlin.check(report.getString("status") == if (apply) "applied" else "checked") { "SU_POLICY_RESULT_INVALID: $report" }
        kotlin.check(report.getBoolean("committed") == apply) { "SU_POLICY_COMMIT_STATE_INVALID: $report" }
        return output
    }

    private fun quote(value: String): String = "'" + value.replace("'", "'\\''") + "'"
}
