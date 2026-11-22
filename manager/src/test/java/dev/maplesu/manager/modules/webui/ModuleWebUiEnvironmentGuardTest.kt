package dev.maplesu.manager.modules.webui

import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.util.concurrent.atomic.AtomicReference

/**
 * 「打开 WebUI 不改进程环境」的守卫。
 *
 * ## 为什么需要这个文件
 *
 * W3-P1 的 `ModuleWebUiOrchestrationTest` 里曾有三处 `System.getenv("PATH")` 比较
 * （取 `pathBefore`、在 fake SDK 里取 `pathDuring`、结束时再取一次）。三处读的是**同一个 JVM
 * 环境**，测试代码和 `WebUiOpenCoordinator` 都不碰 PATH —— 即使把 `Os.setenv` 加回
 * `ModuleWebUiLauncher`，那些断言也**不会红**。W5 复核（S1-3）据此判定 H4 的 PATH 分项
 * 当时只有 grep 证据。本文件把那条空转断言换成两条腿，并写清各自的能力边界。
 *
 * ## 腿 1：源文本守卫（能红）
 *
 * 读 `ModuleWebUiLauncher.kt` 的源码文本，剥离注释与字符串常量后，断言其中**不含**执行型的
 * 环境修改：`android.system.Os`、`Os.setenv/unsetenv/getenv`、`setenv(`/`unsetenv(`、
 * `suppressSdkBrowserOpen`、`SDK_CALL_PATH_GUARD`。
 *
 * - **能抓住**：有人把旧的 `suppressSdkBrowserOpen()`（连同 `Os.setenv`/`Os.unsetenv`）、
 *   常量 `SDK_CALL_PATH_GUARD`、或任何直接 `getenv/setenv` 调用/import 以**源码文本**加回
 *   launcher —— 包括注释掉旧代码后又取消注释、以及改成 `android.system.Os.setenv(...)`
 *   全限定写法。剥离注释保证解释性文字（如文件头 KDoc 里就写着 `Os.setenv`）不误伤；
 *   剥离字符串常量保证字符串里的同名字样也不误伤。
 * - **抓不住**：反射/运行时拼出来的方法名（这些名字在我们的匹配前已被当作字符串抹掉，反而
 *   更抓不到）；JNI/native 侧改环境；把改环境的 helper 放到**别的文件**再由 launcher 调用；
 *   `ProcessBuilder.environment()` 这类非 `Os.*` 的间接写法；以及任何运行期行为本身。它是
 *   文本守卫，不是行为证明 —— 因此下面的运行时腿也不能替它宣称行为已证明。
 *
 * ## 腿 2：运行时 tripwire（只能作 tripwire，**不能**抓住 `Os.setenv`）
 *
 * 在注入的 [SdkOpenRunner] 前后与其中记录 `System.getenv("PATH")`，断言三次相等。这是一个
 * tripwire，不是「PATH 没被改」的证明：
 *
 * - JVM（非 Android）里 `android.system.Os` 根本不存在；本测试也**不构造** `ModuleWebUiLauncher`
 *   （它是 Android 类，仓库没有 Robolectric，按约束也不引入）。所以即使 launcher 里加回
 *   `Os.setenv`，这条运行时断言照样绿。
 * - Java 没有可移植的「改进程环境」API：`System.setProperty` 改的是 properties，不是 env；
 *   因此也**不**制造「注入一个会改 PATH 的假实现」的假演示（那只会演一个和产品代码无关的
 *   假象）。能红的那条腿是上面的源文本守卫；对「把 `Os.setenv` 加回」的对照失败实测见
 *   `.analysis/ultra-module-crash-remediation-20261031/w6-f3/EVIDENCE.md`（临时副本，不动仓库）。
 * - 它今天**有意义**的部分是：驱动真实编排路径时确认没有在本进程内看到环境漂移；并且
 *   [coordinatorSourceDoesNotAccessProcessEnvironment] 会独立地拦住「编排层自己读/写环境」
 *   这种未来改动 —— 两条合起来才是「这条 tripwire 不是纯摆设」的诚实说法。
 */
class ModuleWebUiEnvironmentGuardTest {

    // ------------------------------------------------------------------ 源文本守卫

    @Test
    fun launcherSourceIsTheRealFileNotEmptyOrMissing() {
        val file = locateRepositorySource(LAUNCHER_SOURCE)
        val raw = file.readText(Charsets.UTF_8)

        // 先证明「真的读到了正确文件」：路径写错/文件被清空/内容被换成别的东西时，下面的
        // 「不包含」断言会恒绿（空文件永远不包含任何 token），所以这里必须先把身份钉住。
        assertTrue(
            "必须真的读到 ModuleWebUiLauncher.kt：$file 只有 ${raw.length} 字符（>3000 才算真实内容）",
            raw.length > 3_000,
        )
        assertTrue("读到的文件必须包含 ModuleWebUiLauncher 标识：$file", raw.contains("ModuleWebUiLauncher"))
        assertTrue("读到的文件必须是 `object ModuleWebUiLauncher`：$file", raw.contains("object ModuleWebUiLauncher"))
        assertTrue(
            "读到的文件必须声明预期包名：$file",
            raw.contains("package dev.maplesu.manager.modules"),
        )
    }

    @Test
    fun launcherHasNoExecutableEnvironmentMutation() {
        val file = locateRepositorySource(LAUNCHER_SOURCE)
        val raw = file.readText(Charsets.UTF_8)
        val code = stripCommentsAndStringLiterals(raw)

        // 剥离器自检：注释/字符串里的名字必须消失，真正的代码必须留下。否则「命中列表为空」
        // 可能只是剥离器把整个文件都抹掉了。这两条针对合成片段，不依赖 launcher 的内容。
        assertTrue(
            "剥离器必须保留代码：`fun f() { g() }` 不能整段消失",
            stripCommentsAndStringLiterals("fun f() { g() }").contains("g()"),
        )
        assertTrue(
            "剥离器必须抹掉注释里的 Os.setenv（否则解释性文字会误伤）",
            !stripCommentsAndStringLiterals("// see Os.setenv(\"PATH\", x)\nfun f() {}").contains("setenv("),
        )
        assertTrue(
            "剥离器必须抹掉字符串常量里的 Os.setenv（否则示意字符串会误伤）",
            !stripCommentsAndStringLiterals("val s = \"Os.setenv(PATH)\"").contains("setenv("),
        )
        assertTrue(
            "剥离器必须支持 Kotlin 嵌套块注释（外层块注释里再写一个块注释）",
            !stripCommentsAndStringLiterals("/* 外层 /* 内层 Os.setenv( */ 仍在注释 */\nfun f() {}")
                .contains("setenv("),
        )
        // 真实文件剥离后仍必须是「代码」，否则下面的断言没有意义。
        assertTrue("剥离后 launcher 仍需保留函数体（openDetailed）", code.contains("openDetailed"))
        assertTrue("剥离后 launcher 仍需保留注入点（SdkOpenRunner）", code.contains("SdkOpenRunner"))
        assertTrue(
            "剥离后应保留大部分源码（阈值取 1/3，避免注释增删造成假红）：raw=${raw.length} code=${code.length}",
            code.length > raw.length / 3,
        )

        val forbidden = listOf(
            "android.system.Os",
            "Os.setenv",
            "Os.unsetenv",
            "Os.getenv",
            "setenv(",
            "unsetenv(",
            "suppressSdkBrowserOpen",
            "SDK_CALL_PATH_GUARD",
        )
        val hits = forbidden.mapNotNull { token ->
            val index = code.indexOf(token)
            if (index < 0) null else "$token（第 ${lineOf(code, index)} 行）"
        }
        assertTrue(
            "ModuleWebUiLauncher 不得包含执行型的环境修改（§5.1）：把 Os.setenv 加回时本断言必须变红。" +
                "命中：$hits；文件：$file",
            hits.isEmpty(),
        )
    }

    // ------------------------------------------------------------------ 运行时 tripwire

    @Test
    fun coordinatorSourceDoesNotAccessProcessEnvironment() {
        // 编排层是运行时腿真正驱动的代码；它若开始 getenv/setenv，运行时 tripwire 也可能被
        // 绕过（例如先缓存再恢复）。这条是能红的静态补充。
        val file = locateRepositorySource(COORDINATOR_SOURCE)
        val code = stripCommentsAndStringLiterals(file.readText(Charsets.UTF_8))
        for (token in listOf("getenv(", "setenv(", "unsetenv(")) {
            assertEquals(
                "WebUiOpenCoordinator（ModuleWebUiPlan.kt）不得访问进程环境：命中 $token；文件：$file",
                -1,
                code.indexOf(token),
            )
        }
    }

    @Test
    fun sdkOpenRunDoesNotChangeTheProcessPath() = runBlocking {
        // 说明：这是 tripwire（见类注释）。它能红的前提是「本进程可见的环境真的变了」；JVM 上
        // 产品代码（尤其是 Android-only 的 launcher）无法造成这种变化，因此它不证明 launcher
        // 没调用 Os.setenv —— 那条由 launcherHasNoExecutableEnvironmentMutation 负责。
        val pathBefore = System.getenv("PATH")
        val pathInsideRunner = AtomicReference<String?>(null)

        val runner = SdkOpenRunner {
            pathInsideRunner.set(System.getenv("PATH"))
            delay(100)
            SdkOpenOutcome(ok = true, port = 32431, sdkError = "OK")
        }
        val coordinator = WebUiOpenCoordinator(
            runner,
            HttpReadyProbe { port -> HttpReadyResult.readyAt(port) },
            WebUiCompatibilityCheck {
                WebUiGateVerdict.permit(
                    decision = "UNVERIFIED",
                    reasonCodes = listOf("UNKNOWN_PACKAGE"),
                    detail = "gate=UNVERIFIED record=none codes=UNKNOWN_PACKAGE",
                )
            },
        )

        val result = coordinator.open(WebUiOpenSpec("aaaa1111", WebUiRoute.ULTRA_SDK))

        // 先证明 runner 真的跑了，否则「PATH 没变」可能只是流程没走到。
        assertTrue("注入的 SDK 启动器必须被调用并成功", result.succeeded)
        assertEquals(32431, result.port)
        assertEquals("SDK 调用期间 PATH 不得变化", pathBefore, pathInsideRunner.get())
        assertEquals("SDK 调用结束后 PATH 不得变化", pathBefore, System.getenv("PATH"))
    }

    // ------------------------------------------------------------------ 工具

    private companion object {
        private const val LAUNCHER_SOURCE =
            "manager/src/main/java/dev/maplesu/manager/modules/ModuleWebUiLauncher.kt"
        private const val COORDINATOR_SOURCE =
            "manager/src/main/java/dev/maplesu/manager/modules/webui/ModuleWebUiPlan.kt"

        /** 1-based 行号；剥离器用空格覆盖被移除的字符但保留换行，所以行号与原文件一致。 */
        private fun lineOf(text: String, index: Int): Int {
            var line = 1
            for (i in 0 until index) if (text[i] == '\n') line++
            return line
        }

        /**
         * 把行注释、块注释与字符串/字符常量的**内容**替换成空格（保留换行与长度）。
         *
         * 只保留代码 token，这样「注释里解释旧实现用了 `Os.setenv`」不会让守卫误红，而真正
         * 的 `import android.system.Os` / `Os.setenv(...)` 会留下。字符串常量内容也一并抹掉
         * ，代价是「反射/字符串拼名」抓不到 —— 已在类注释写明。
         */
        internal fun stripCommentsAndStringLiterals(source: String): String {
            val out = StringBuilder(source.length)
            var i = 0
            var state = 0 // 0=code 1=line comment 2=block comment 3=string 4=raw string 5=char
            var blockDepth = 0 // Kotlin 的块注释可嵌套：/* /* */ */
            while (i < source.length) {
                val c = source[i]
                when (state) {
                    0 -> when {
                        c == '/' && i + 1 < source.length && source[i + 1] == '/' -> {
                            out.append("  "); state = 1; i += 2
                        }
                        c == '/' && i + 1 < source.length && source[i + 1] == '*' -> {
                            out.append("  "); state = 2; blockDepth = 1; i += 2
                        }
                        c == '"' && source.startsWith("\"\"\"", i) -> {
                            out.append("   "); state = 4; i += 3
                        }
                        c == '"' -> {
                            out.append(' '); state = 3; i += 1
                        }
                        c == '\'' -> {
                            out.append(' '); state = 5; i += 1
                        }
                        else -> {
                            out.append(c); i += 1
                        }
                    }
                    1 -> {
                        if (c == '\n') { out.append('\n'); state = 0 } else out.append(' ')
                        i += 1
                    }
                    2 -> when {
                        c == '/' && i + 1 < source.length && source[i + 1] == '*' -> {
                            out.append("  "); blockDepth++; i += 2
                        }
                        c == '*' && i + 1 < source.length && source[i + 1] == '/' -> {
                            out.append("  "); blockDepth--; i += 2
                            if (blockDepth == 0) state = 0
                        }
                        else -> {
                            if (c == '\n') out.append('\n') else out.append(' ')
                            i += 1
                        }
                    }
                    3 -> when {
                        c == '\\' && i + 1 < source.length -> {
                            out.append("  "); i += 2
                        }
                        c == '"' -> {
                            out.append(' '); state = 0; i += 1
                        }
                        // 未闭合字符串：防御性复位，绝不因此吞掉后面的代码。
                        c == '\n' -> {
                            out.append('\n'); state = 0; i += 1
                        }
                        else -> {
                            out.append(' '); i += 1
                        }
                    }
                    4 -> {
                        if (source.startsWith("\"\"\"", i)) {
                            out.append("   "); state = 0; i += 3
                        } else {
                            if (c == '\n') out.append('\n') else out.append(' ')
                            i += 1
                        }
                    }
                    else -> when {
                        c == '\\' && i + 1 < source.length -> {
                            out.append("  "); i += 2
                        }
                        c == '\'' -> {
                            out.append(' '); state = 0; i += 1
                        }
                        c == '\n' -> {
                            out.append('\n'); state = 0; i += 1
                        }
                        else -> {
                            out.append(' '); i += 1
                        }
                    }
                }
            }
            return out.toString()
        }

        /**
         * 从测试工作目录向上找仓库内文件。
         *
         * Gradle 单测的 cwd 可能是仓库根，也可能是 `manager/` 模块根，离线跑时还可能是临时
         * 对照目录，所以两种相对路径都试、并向上遍历。找不到时**抛错**（而不是 return 空
         * 字符串），否则「文件不存在」会退化成恒绿。
         */
        private fun locateRepositorySource(relative: String): File {
            val variants = listOf(relative, relative.removePrefix("manager/"))
            val tried = mutableListOf<File>()
            var dir: File? = File(System.getProperty("user.dir")).absoluteFile
            while (dir != null) {
                for (variant in variants) {
                    val candidate = File(dir, variant)
                    tried += candidate
                    if (candidate.isFile) return candidate
                }
                dir = dir.parentFile
            }
            throw AssertionError(
                "找不到仓库源码 $relative（cwd=${System.getProperty("user.dir")}）。" +
                    "尝试过：\n" + tried.joinToString("\n"),
            )
        }
    }
}
