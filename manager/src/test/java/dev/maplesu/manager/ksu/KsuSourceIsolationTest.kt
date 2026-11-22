// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.ksu

import java.io.File
import org.junit.Assert.assertFalse
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * source set 边界。
 *
 * D5 要求「KSU 后端进独立 source set」，本仓库的实现是
 * `manager/src/ksu/java` + `sourceSets["main"].kotlin.srcDir(...)`（单 sourceSet 多目录）。
 * 这带来一个可机器校验的替代：**目录与 import 白名单**。
 */
class KsuSourceIsolationTest {

    private fun managerDir(): File = KsuTestPaths.managerDir()

    private fun unexpectedNonFacadeImports(relativePath: String, text: String): List<String> {
        // The reboot transport may consume this existing main/glue channel, not JNI or commands.
        val allowed = if (relativePath == "com/maplesu/core/ui/util/SystemReboot.kt") {
            setOf("dev.maplesu.manager.ksu.KsuRootChannel")
        } else if (relativePath == "dev/maplesu/manager/installer/InstallerPartitionService.kt") {
            // The root installer deploys verified boot userland before publishing success.
            setOf("dev.maplesu.manager.ksu.KsuFileCommandRunner", "dev.maplesu.manager.ksu.ensureNormalBootUserland")
        } else if (relativePath == "dev/maplesu/manager/workmode/service/ServiceModeSwitchWiring.kt") {
            setOf("dev.maplesu.manager.ksu.KsuFileCommandRunner")
        } else if (relativePath == "dev/maplesu/manager/installer/VivoCompatibility.kt") {
            setOf("KsuFileCommandRunner", "KsuLog", "KsuTimeouts")
                .map { "dev.maplesu.manager.ksu.$it" }.toSet()
        } else if (relativePath == "dev/maplesu/manager/workmode/service/ModeSwitchSourceRecovery.kt") {
            // Only file inspection/copy recovery is wired here; partition writes remain with its caller.
            setOf("KsuBootInfoSubcommand", "KsuCommands", "KsuInstallProducer", "KsuRootCommandRunner",
                "KsuShellResult", "KsuTimeouts", "RamdiskState").map { "dev.maplesu.manager.ksu.$it" }.toSet()
        } else emptySet()
        return Regex("""(?m)^\s*import\s+(dev\.maplesu\.manager\.ksu\.[\w.*]+)""")
            .findAll(text).map { it.groupValues[1] }.filter { it !in allowed }.toList()
    }

    @Test
    fun ksuBackendLivesOutsideMainJavaTree() {
        val manager = managerDir()
        // R1：KSU JNI 后端只放 src/ksu/java。src/main/java/dev/maplesu/manager/ksu/ 只允许
        // 集成轮（W11b/W12）的 **glue** 文件——它们依赖后端，但不是后端本体；
        // 白名单外的任何文件都视为"把 JNI 后端放进了 main"。见
        // task-16 的写作用域（wm-ksu 持有 src/ksu，集成轮只能新增 glue）。
        val glueDir = File(manager, "src/main/java/dev/maplesu/manager/ksu")
        val allowedGlue = setOf(
            "NativesFacadeDispatch.kt",
            "KsuInstallProducer.kt",
            "KsuInstallPolicy.kt",
            "KsuInstallGlue.kt",
            "KsuBootstrap.kt",
            "KsuFileCommandRunner.kt",
            // Mode B 根通道（`ksud debug su` 的 libsu 适配 + 注册）；不是 JNI 后端本体。
            "KsuRootChannel.kt",
        )
        if (glueDir.isDirectory) {
            val unexpected = glueDir.listFiles().orEmpty()
                .filter { it.isFile && it.name !in allowedGlue }
                .map { it.name }
            assertTrue(
                "src/main/java glue dir may only contain $allowedGlue; found $unexpected",
                unexpected.isEmpty(),
            )
        }
        // 后端本体的标志文件不得出现在 main：
        assertFalse(
            "KSU JNI backend must not live under src/main/java",
            File(glueDir, "KsuNatives.kt").exists(),
        )
        assertTrue(
            "KSU backend dir missing",
            File(manager, "src/ksu/java/dev/maplesu/manager/ksu/KsuNatives.kt").isFile,
        )
    }

    @Test
    fun onlyFacadesMayImportKsuBackend() {
        val manager = managerDir()
        val whitelist = setOf(
            "com/maplesu/core/Natives.kt",
            "com/maplesu/core/ui/util/KsuCli.kt",
            "dev/maplesu/manager/workmode/backend/BackendRouter.kt",
            "dev/maplesu/manager/workmode/backend/KsuBackendRegistry.kt",
            "dev/maplesu/manager/workmode/superuser/KsuSuperuserBackend.kt",
            // W12b 集成层：切换事务运行时需要调用 KSU 用户态 bootstrap / 后端装配
            // （S4 阶段部署 ksud、读取 KSU 后端状态）。它是门面层的合法消费者，
            // 不是 JNI 后端本体（本体仍在 src/ksu）。
            "dev/maplesu/manager/workmode/service/ModeSwitchRuntime.kt",
        )
        // 集成 glue 目录整体允许 import（它就是门面↔后端的接线层）。
        val gluePrefix = "dev/maplesu/manager/ksu/"
        // 探针门面适配层：workmode/detect/probes/Ksu*ProbeAdapter 是「模式探针 → KSU 后端」
        // 的适配器（wm-core W02/W05 的探测链），属于门面层的合法消费者；
        // 只放行这一条命名规则，其他 detect/ 文件仍按非门面禁止。
        val probeAdapterPrefix = "dev/maplesu/manager/workmode/detect/probes/Ksu"
        fun isProbeAdapter(rel: String, name: String): Boolean =
            rel.startsWith(probeAdapterPrefix) && name.contains("ProbeAdapter")
        val mainJava = File(manager, "src/main/java")
        assertTrue("src/main/java missing: ${mainJava.path}", mainJava.isDirectory)
        val offenders = mutableListOf<String>()
        mainJava.walkTopDown()
            .filter { it.isFile && (it.extension == "kt" || it.extension == "java") }
            .forEach { file ->
                val rel = file.relativeTo(mainJava).invariantSeparatorsPath
                if (rel in whitelist || rel.startsWith(gluePrefix) ||
                    isProbeAdapter(rel, file.name)
                ) {
                    return@forEach
                }
                val text = runCatching { file.readText() }.getOrNull() ?: return@forEach
                val imports = unexpectedNonFacadeImports(rel, text)
                if (imports.isNotEmpty()) offenders += "$rel: $imports"
            }
        assertTrue("non-facade imports KSU backend: $offenders", offenders.isEmpty())
    }

    @Test
    fun rebootTransportExceptionAllowsOnlyTheExactGlueSymbol() {
        val reboot = "com/maplesu/core/ui/util/SystemReboot.kt"
        val channel = "dev.maplesu.manager.ksu.KsuRootChannel"
        assertTrue(unexpectedNonFacadeImports(reboot, "import $channel").isEmpty())
        for (backend in listOf("KsuNatives", "KsuCommands", "*")) {
            val imported = "dev.maplesu.manager.ksu.$backend"
            assertEquals(listOf(imported), unexpectedNonFacadeImports(reboot, "import $channel\nimport $imported"))
        }
        assertEquals(listOf(channel), unexpectedNonFacadeImports("com/maplesu/core/ui/util/Other.kt", "import $channel"))
    }

    @Test
    fun bootInstallerExceptionAllowsOnlyTheTwoDeploymentSymbols() {
        val installer = "dev/maplesu/manager/installer/InstallerPartitionService.kt"
        for (symbol in listOf("KsuFileCommandRunner", "ensureNormalBootUserland")) {
            val imported = "dev.maplesu.manager.ksu.$symbol"
            assertTrue(unexpectedNonFacadeImports(installer, "import $imported").isEmpty())
            assertEquals(listOf(imported), unexpectedNonFacadeImports("Other.kt", "import $imported"))
        }
        for (symbol in listOf("KsuNatives", "KsuCommands", "*")) {
            val imported = "dev.maplesu.manager.ksu.$symbol"
            assertEquals(listOf(imported), unexpectedNonFacadeImports(installer, "import $imported"))
        }
        val fileConsumers = mapOf(
            "dev/maplesu/manager/workmode/service/ServiceModeSwitchWiring.kt" to listOf("KsuFileCommandRunner"),
            "dev/maplesu/manager/installer/VivoCompatibility.kt" to listOf("KsuFileCommandRunner", "KsuLog", "KsuTimeouts"),
            "dev/maplesu/manager/workmode/service/ModeSwitchSourceRecovery.kt" to listOf(
                "KsuBootInfoSubcommand", "KsuCommands", "KsuInstallProducer", "KsuRootCommandRunner",
                "KsuShellResult", "KsuTimeouts", "RamdiskState"),
        )
        for ((path, symbols) in fileConsumers) {
            for (symbol in symbols) {
                val imported = "dev.maplesu.manager.ksu.$symbol"
                assertTrue(unexpectedNonFacadeImports(path, "import $imported").isEmpty())
                assertEquals(listOf(imported), unexpectedNonFacadeImports("Other.kt", "import $imported"))
            }
            for (symbol in listOf("KsuNatives", "KsuNativeCalls", "KsuNativesBackend", "KsuBackends", "*")) {
                val imported = "dev.maplesu.manager.ksu.$symbol"
                assertEquals(listOf(imported), unexpectedNonFacadeImports(path, "import $imported"))
            }
        }
    }

    @Test
    fun ksuBackendNeverImportsUi() {
        val manager = managerDir()
        val ksuRoot = File(manager, "src/ksu/java")
        assertTrue("src/ksu/java missing: ${ksuRoot.path}", ksuRoot.isDirectory)
        val offenders = mutableListOf<String>()
        ksuRoot.walkTopDown().filter { it.isFile && it.extension == "kt" }.forEach { file ->
            val text = file.readText()
            if (text.contains("import com.maplesu.core.ui.")) {
                offenders += file.name
            }
        }
        assertTrue("KSU backend must not depend on UI: $offenders", offenders.isEmpty())
    }

    @Test
    fun ksuBackendFilesArePresent() {
        val manager = managerDir()
        val expected = listOf(
            "KsuNatives.kt",
            "KsuNativesBackend.kt",
            "KsuCommandBackend.kt",
            "KsuBootInfo.kt",
            "KsuModuleOps.kt",
            "KsuSuperuserAdapter.kt",
            "KsuSettingsFeature.kt",
            "KsuBackends.kt",
            "LibsuShellRunner.kt",
        )
        expected.forEach { name ->
            assertTrue(
                "missing KSU backend file: $name",
                File(manager, "src/ksu/java/dev/maplesu/manager/ksu/$name").isFile,
            )
        }
    }

    @Test
    fun gradleWiresKsuSourceRootMinimally() {
        val manager = managerDir()
        val gradle = File(manager, "build.gradle.kts")
        assertTrue("build.gradle.kts missing: ${gradle.path}", gradle.isFile)
        val text = gradle.readText()
        assertTrue(
            "manager/build.gradle.kts must wire src/ksu/java into the main source set",
            text.contains("sourceSets[\"main\"].kotlin.srcDir(\"src/ksu/java\")"),
        )
        // Scope this invariant to KSU wiring; independent environment-backed release signing is valid.
        assertEquals("KSU must have one main source-root wiring", 1,
            Regex("""(?m)^\s*sourceSets\["main"\]\.kotlin\.srcDir\("src/ksu/java"\)\s*$""")
                .findAll(text).count())
        assertFalse("no new flavors may be introduced by the KSU wiring", text.contains("flavorDimensions"))
    }
}
