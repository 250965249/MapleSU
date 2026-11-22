package dev.maplesu.manager.installer

import android.content.Context
import android.os.Bundle
import android.system.Os
import android.util.Log
import dev.maplesu.manager.ModuleArchiveInspector.ModuleType
import dev.maplesu.manager.modules.ModuleCatalog
import dev.maplesu.manager.modules.ModuleToolDeployment
import dev.maplesu.manager.runtime.ModuleTaskEnvironment
import dev.maplesu.manager.workmode.service.ModeSwitchRootCommandRunner
import java.io.File

/** Runs in the authenticated root installer while holding its existing device lock. */
internal object UltraModuleCleanup {
    fun remove(context: Context, managerUid: Int): Bundle {
        require(managerUid >= 10_000)
        val userId = managerUid / 100_000
        val appFiles = File("/data/user/$userId/${context.packageName}/files").canonicalFile
        val namespaces = listOf(appFiles, File(appFiles, "ksu"))
        namespaces.forEach { checkPrivateParents(File(it, "module-catalog")) }
        val source = context.assets.open("maplesu/modules/cleanup.sh").bufferedReader().use { it.readText() }
        val busybox = ModuleToolDeployment.busyboxSource(context).absolutePath
        // This installer already owns Root; its source supplies no SDK installation mode.
        val moduleEnvironment by lazy { ModuleTaskEnvironment.captureNonSdk(hook = false) }
        val runner = ModeSwitchRootCommandRunner(start = {
            ProcessBuilder("/system/bin/sh").redirectErrorStream(true).apply {
                ModuleTaskEnvironment.replace(environment(), moduleEnvironment)
            }.start()
        })
        fun execute(script: String): String {
            val result = runner.execute(script)
            check(result.code == 0 && result.detail.isEmpty()) { "MODULE_CLEANUP_FAILED" }
            result.output.lineSequence().filter { it.startsWith("MODULE_UNINSTALL_WARNING\t") }
                .forEach { Log.w("MapleSUModules", it) }
            return result.output
        }
        fun phase(vararg args: String): String {
            val command = "MAPLESU_CLEANUP_BUSYBOX=${quote(busybox)}\nset -- ${args.joinToString(" ", transform = ::quote)}\n$source"
            return execute("""
                if [ "${'$'}(readlink /proc/self/ns/mnt)" != "${'$'}(readlink /proc/1/ns/mnt)" ]; then
                  exec ${quote(busybox)} nsenter -t 1 -m -- /system/bin/sh -c ${quote(command)}
                fi
                $command
            """.trimIndent())
        }
        val modules = phase("list").lineSequence().filter { it.startsWith("MODULE\t") }.map { line ->
            val fields = line.split('\t')
            check(fields.size == 3 && fields[1] in setOf("0", "1") &&
                fields[2].matches(Regex("/data/adb/modules(?:_update)?/[a-zA-Z0-9._-]+"))) {
                "MODULE_CLEANUP_INVENTORY_INVALID"
            }
            fields[1] to fields[2]
        }.sortedWith(compareBy({ it.first }, { it.second })).toList()
        modules.forEach { (_, path) -> phase("uninstall", path) }
        check(phase("finish").lineSequence().any { it == "MODULE_CLEANUP_OK" }) { "MODULE_CLEANUP_INCOMPLETE" }

        // Purge both namespaces. Native Ultra catalog entries are unrelated to the shared KSU tree.
        for (files in namespaces) {
            val catalogRoot = File(files, "module-catalog")
            if (catalogRoot.isDirectory) {
                check(catalogRoot.canonicalFile.parentFile == files.canonicalFile) { "MODULE_CLEANUP_PATH_CONFLICT" }
                try {
                    val catalog = ModuleCatalog(catalogRoot)
                    catalog.list().filter { it.report.type == ModuleType.KERNEL_SU }
                        .forEach { catalog.uninstall(it.report.type, it.report.id) }
                    check(catalog.list().none { it.report.type == ModuleType.KERNEL_SU }) { "MODULE_CLEANUP_INCOMPLETE" }
                } finally {
                    // Restore app ownership even when a corrupt catalog interrupts cleanup.
                    for (name in listOf("", "staged", "revisions", "installed", "catalog.lock")) {
                        val file = if (name.isEmpty()) catalogRoot else File(catalogRoot, name)
                        check(!java.nio.file.Files.isSymbolicLink(file.toPath())) { "MODULE_CLEANUP_PATH_CONFLICT" }
                        if (file.exists()) Os.chown(file.path, managerUid, managerUid)
                    }
                }
            }
            for (name in listOf("revisions", "staging", "receipts")) {
                removePrivateTree(File(files, "module-runtime/$name"), execute = ::execute)
            }
        }
        removePrivateTree(File("/data/user_de/$userId/${context.packageName}/files/module-zygisk"), execute = ::execute)
        return Bundle().apply {
            putBoolean("complete", true)
            putInt("removedModules", modules.size)
        }
    }

    private fun removePrivateTree(file: File, execute: (String) -> String) {
        checkPrivateParents(file)
        execute("rm -rf -- ${quote(file.path)}\ntest ! -e ${quote(file.path)} && test ! -L ${quote(file.path)}")
    }

    private fun checkPrivateParents(file: File) {
        // The caller constructs only fixed package-private cache paths. Check every tail parent.
        var parent = file.parentFile
        val packageRoot = file.path.substringBefore("/files/")
        while (parent != null && parent.path.length >= packageRoot.length) {
            check(!java.nio.file.Files.isSymbolicLink(parent.toPath())) { "MODULE_CLEANUP_PATH_CONFLICT" }
            parent = parent.parentFile
        }
    }

    private fun quote(value: String) = "'" + value.replace("'", "'\\''") + "'"
}
