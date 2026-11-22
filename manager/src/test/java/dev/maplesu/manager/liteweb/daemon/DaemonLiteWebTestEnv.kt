package dev.maplesu.manager.liteweb.daemon

import dev.maplesu.manager.liteweb.LiteWebUnhidePort
import dev.maplesu.manager.liteweb.UnavailableUnhidePort
import java.io.File
import java.io.FileOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * 纯 JVM 假设备树：临时 `/data/adb` 结构 + 含 `assets/liteweb/...` 的假 APK。
 *
 * 所有路径都落在临时目录里，绝不碰真机 `/data/adb`；`selfUid` 注入成固定值，
 * 因此 `rootAvailable` 的可判定性也能在主机上测。
 */
internal class DaemonLiteWebTestEnv(val root: File) {
    val normalRuntime = object : DaemonRuntimeSource {
        override fun snapshot() = DaemonRuntimeSnapshot(
            mode = "KSU", rootBackend = "KSU", probe = "NotInstalled", source = "test_committed_mode",
        )
        override fun ultraModules(): DaemonModulesSnapshot = error("Normal test must not read Ultra modules")
    }
    val adbRoot: File = File(root, "adb")
    val modulesRoot: File = File(adbRoot, "modules")
    val maplesuDir: File = File(adbRoot, "maplesu")
    val recoveryDir: File = File(maplesuDir, "recovery")
    val apk: File = File(recoveryDir, "manager.apk")
    val hiddenFile: File = File(maplesuDir, "lite_hidden")
    val suLog: File = File(File(maplesuDir, "logs"), "su.log")

    fun createApk(entries: Map<String, ByteArray>): File {
        recoveryDir.mkdirs()
        ZipOutputStream(FileOutputStream(apk)).use { zip ->
            for ((name, bytes) in entries) {
                zip.putNextEntry(ZipEntry(name))
                zip.write(bytes)
                zip.closeEntry()
            }
        }
        return apk
    }

    fun createTextApk(entries: Map<String, String>): File =
        createApk(entries.mapValues { (_, value) -> value.toByteArray(Charsets.UTF_8) })

    fun addModule(
        id: String,
        prop: String? = "id=$id\nname=$id\n",
        disable: Boolean = false,
        remove: Boolean = false,
    ): File {
        val directory = File(modulesRoot, id)
        directory.mkdirs()
        if (prop != null) File(directory, "module.prop").writeText(prop, Charsets.UTF_8)
        if (disable) File(directory, "disable").writeBytes(ByteArray(0))
        if (remove) File(directory, "remove").writeBytes(ByteArray(0))
        return directory
    }

    fun backend(
        uid: Int? = 0,
        port: Int = 18427,
        unhidePort: LiteWebUnhidePort = UnavailableUnhidePort,
        runtime: DaemonRuntimeSource = normalRuntime,
    ): DaemonLiteWebBackend = DaemonLiteWebBackend(
        adbRoot = adbRoot.absolutePath,
        managerApkPath = apk.absolutePath,
        hiddenStatePath = hiddenFile.absolutePath,
        modulesRoot = modulesRoot.absolutePath,
        suLogPath = suLog.absolutePath,
        configuredPortValue = port,
        selfUid = { uid },
        unhidePortValue = unhidePort,
        runtimeSource = runtime,
    )
}
