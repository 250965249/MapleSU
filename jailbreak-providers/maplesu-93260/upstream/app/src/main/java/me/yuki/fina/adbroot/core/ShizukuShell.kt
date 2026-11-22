package me.yuki.fina.adbroot.core

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import rikka.shizuku.Shizuku
import rikka.shizuku.ShizukuRemoteProcess
import java.io.File
import java.lang.reflect.Method
import java.util.concurrent.TimeUnit

/**
 * Shizuku 通道。
 *
 * Shizuku 13.x 把 `Shizuku.newProcess` 改成了 private（官方 API 只剩 binder 检查与权限申请），
 * 所以这里用反射拿它；返回的 ShizukuRemoteProcess 是 public 的、继承 java.lang.Process。
 */
class ShizukuShell : Shell {

    private val newProcess: Method? by lazy {
        runCatching {
            val c = Class.forName("rikka.shizuku.Shizuku")
            val byName = c.declaredMethods.firstOrNull { it.name == "newProcess" && it.parameterCount == 3 }
            (byName ?: c.getDeclaredMethod(
                "newProcess",
                Array<String>::class.java,
                Array<String>::class.java,
                String::class.java,
            )).apply { isAccessible = true }
        }.getOrNull()
    }

    override fun isAvailable(): Boolean = runCatching {
        Shizuku.pingBinder() && Shizuku.checkSelfPermission() == android.content.pm.PackageManager.PERMISSION_GRANTED
    }.getOrDefault(false)

    private fun spawn(cmd: Array<String>, dir: String?): ShizukuRemoteProcess? {
        val m = newProcess ?: return null
        val proc = runCatching {
            m.invoke(null, cmd, null, dir ?: "/data/local/tmp") as ShizukuRemoteProcess
        }.getOrNull()
        return proc
    }

    override suspend fun exec(cmd: String, timeoutMs: Long): ExecResult = withContext(Dispatchers.IO) {
        val proc = spawn(arrayOf("sh", "-c", cmd), "/data/local/tmp")
            ?: return@withContext ExecResult(-1, "", "shell 通道打不开：binder=${runCatching { Shizuku.pingBinder() }.getOrDefault(false)}，授权=${runCatching { Shizuku.checkSelfPermission() == android.content.pm.PackageManager.PERMISSION_GRANTED }.getOrDefault(false)}，入口=${if (newProcess == null) "没找到" else "在"}，类=${runCatching { Class.forName("rikka.shizuku.Shizuku").name }.getOrDefault("加载失败")}，方法数=${runCatching { Class.forName("rikka.shizuku.Shizuku").declaredMethods.size }.getOrDefault(-1)}，带Process=${runCatching { Class.forName("rikka.shizuku.Shizuku").declaredMethods.count { it.name.contains("Process", true) } }.getOrDefault(-1)}")
        val out = StringBuilder()
        val err = StringBuilder()
        val tOut = Thread { runCatching { proc.inputStream.bufferedReader().useLines { ls -> ls.forEach { out.appendLine(it) } } } }
        val tErr = Thread { runCatching { proc.errorStream.bufferedReader().useLines { ls -> ls.forEach { err.appendLine(it) } } } }
        tOut.isDaemon = true
        tErr.isDaemon = true
        tOut.start()
        tErr.start()
        val finished = runCatching { proc.waitForTimeout(timeoutMs, TimeUnit.MILLISECONDS) }.getOrDefault(false)
        if (!finished) {
            runCatching { proc.destroy() }
            return@withContext ExecResult(-1, out.toString(), err.toString() + "\n超时 ${timeoutMs}ms")
        }
        tOut.join(3_000)
        tErr.join(3_000)
        ExecResult(runCatching { proc.exitValue() }.getOrDefault(0), out.toString(), err.toString())
    }

    override suspend fun push(local: File, remote: String): Boolean = withContext(Dispatchers.IO) {
        val target = remote.substringBeforeLast('/').ifEmpty { "/data/local/tmp" }
        val proc = spawn(arrayOf("sh", "-c", "cat > '$remote'"), target) ?: return@withContext false
        val ok = runCatching {
            proc.outputStream.use { out -> local.inputStream().use { it.copyTo(out) } }
            proc.waitForTimeout(60_000, TimeUnit.MILLISECONDS) && proc.exitValue() == 0
        }.getOrDefault(false)
        if (!ok) runCatching { proc.destroy() }
        ok
    }
}
