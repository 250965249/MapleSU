// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.ksu

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * T7：`ksud module action` 的**命令形态**与**输出透传**（开发文档 §6 T7 / §10.3 D3-D4）。
 *
 * 四条判据：
 * 1. argv 不含 `-g`（`-g` 只属于 `debug su`，clap 会拒绝 `module action ... -g`）；
 * 2. 命令跑在**全局挂载命名空间**的 runner 上（上游 `withNewRootShell(true)`）；
 * 3. stdout/stderr/退出码原样返回（不再压成布尔、不再回吐伪造串）；
 * 4. 后端不可用/命令被拒时返回**具名错误码**（C3：禁止静默成功）。
 */
class KsuModuleActionTest {

    private val daemon = "/data/adb/ksud"

    private class RecordingRunner(
        private val result: KsuShellResult = KsuShellResult(0, emptyList(), emptyList()),
    ) : KsuShellRunner {
        val calls = mutableListOf<List<String>>()

        override fun run(command: List<String>, timeoutMs: Long): KsuShellResult {
            calls += command
            return result
        }
    }

    private fun backend(
        plain: KsuShellRunner,
        global: KsuShellRunner,
        daemonExists: Boolean = true,
    ): KsuCommandBackend = KsuCommandBackend(
        daemonPathProvider = { daemon },
        runner = plain,
        globalMountRunner = global,
        probe = object : KsuPathProbe {
            override fun exists(path: String): Boolean = daemonExists

            override fun canExecute(path: String): Boolean = daemonExists
        },
    )

    @Test
    fun actionHasNoDashGAndRunsInGlobalMountShell() {
        val plain = RecordingRunner(KsuShellResult(99, emptyList(), listOf("plain shell must not run")))
        val global = RecordingRunner()
        val ops = KsuModuleOps(backend(plain, global))

        val result = ops.action("m1")

        assertTrue("action 必须在 global-mnt runner 上执行", plain.calls.isEmpty())
        assertEquals(
            listOf(listOf(daemon, "module", "action", "m1")),
            global.calls,
        )
        assertFalse("argv 不得包含 -g", global.calls.single().contains("-g"))
        assertTrue(result.ok)
    }

    @Test
    fun actionPassesThroughStdoutStderrAndExitCode() {
        val plain = RecordingRunner()
        val global = RecordingRunner(
            KsuShellResult(7, listOf("script: hello", "script: line2"), listOf("script: boom")),
        )
        val result = KsuModuleOps(backend(plain, global)).action("m1")

        assertEquals(7, result.code)
        assertFalse(result.ok)
        assertEquals("script: hello\nscript: line2", result.out)
        assertEquals("script: boom", result.err)
    }

    @Test
    fun actionStreamsThroughTheGlobalRunnerWithoutACompletionReplay() {
        val events = mutableListOf<String>()
        val plain = RecordingRunner()
        val global = object : KsuShellRunner {
            override fun run(command: List<String>, timeoutMs: Long): KsuShellResult =
                error("action must use streaming")

            override fun runStreaming(
                command: List<String>, timeoutMs: Long,
                onStdout: (String) -> Unit, onStderr: (String) -> Unit,
            ): KsuShellResult {
                assertEquals(listOf(daemon, "module", "action", "m1"), command)
                onStdout("running")
                onStderr("")
                events += "completed"
                return KsuShellResult(7, listOf("running"), listOf(""))
            }
        }
        val result = KsuModuleOps(backend(plain, global)).action("m1",
            { events += "out:$it" }, { events += "err:$it" })

        assertEquals(7, result.code)
        assertEquals(listOf("out:running", "err:", "completed"), events)
        assertTrue(plain.calls.isEmpty())
    }

    @Test
    fun actionReturnsNamedErrorWhenKsudMissing() {
        val plain = RecordingRunner()
        val global = RecordingRunner()
        val result = KsuModuleOps(backend(plain, global, daemonExists = false)).action("m1")

        // C3：不可用必须是具名错误码，不得返回 code=0 + 空输出冒充成功。
        assertEquals(-1, result.code)
        assertTrue(result.err.contains(KsuCommandBackend.CODE_KSUD_UNAVAILABLE))
        assertTrue("daemon 不可用时不得起进程", global.calls.isEmpty())
    }

    @Test
    fun actionRejectsIllegalModuleIdBeforeAnyProcess() {
        val plain = RecordingRunner()
        val global = RecordingRunner()
        val result = KsuModuleOps(backend(plain, global)).action("bad id; rm -rf /")

        assertEquals(-1, result.code)
        assertTrue(result.err.contains("KSU_MODULE_ID_REJECTED"))
        assertTrue("非法 id 不得起进程", global.calls.isEmpty() && plain.calls.isEmpty())
    }

    @Test
    fun globalMountRunnerDefaultsToPlainRunnerWhenNotInjected() {
        // 主机测试/未装配时的安全默认：global-mnt 缺省复用普通 root shell，
        // 绝不静默降级成 app uid 执行。
        val plain = RecordingRunner()
        val backend = KsuCommandBackend(
            daemonPathProvider = { daemon },
            runner = plain,
            probe = object : KsuPathProbe {
                override fun exists(path: String): Boolean = true

                override fun canExecute(path: String): Boolean = true
            },
        )
        val result = KsuModuleOps(backend).action("m1")

        assertEquals(1, plain.calls.size)
        assertTrue(result.ok)
    }
}
