// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.ksu

import java.io.File
import java.util.concurrent.CancellationException
import java.util.concurrent.TimeoutException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * Normal（KSU）的 ksud 命令面：**root shell 提权**（2026-11-01 收尾）。
 *
 * 覆盖审计 §8「KSU 命令后端不提权」与 §1「ksud 部署」：
 * - `KsuCommandBackend.forDeployedDaemon` 的模块/feature 命令走**已认证 root shell**，
 *   不再以 app uid 起进程；
 * - 部署路径（`/data/adb/ksud`）的存在性由 root shell 探针回答
 *   （`/data/adb` 是 0700 root，app uid 连 stat 都不行）；
 * - 未装配 root shell 时**显式失败**，绝不静默降级成 app uid；
 * - `KsuModuleListMapper` 补齐 `updateJson` / `props` / `stages`；
 * - `KsuBootstrap.ensureDeployed` 的显式状态（含"已部署就跳过重装"）。
 */
class KsuRootWiringTest {

    @get:Rule
    val tmp = TemporaryFolder()

    @Before
    fun setUp() {
        // 后端接缝是进程级的：每个用例从"未装配"开始，避免跨类顺序影响结论。
        KsuRootShell.resetForTest()
        KsuLog.clear()
    }

    // ── root shell runner ───────────────────────────────────────────────

    @Test
    fun rootShellRunnerJoinsTokensAndExecutesInRootShell() {
        val lines = mutableListOf<String>()
        val runner = RootShellKsuRunner(
            KsuRootShellExecutor { line ->
                lines += line
                KsuShellResult(0, listOf("ok"), emptyList())
            },
        )
        val result = runner.run(
            listOf("/data/adb/ksud", "module", "install", "/sdcard/my module.zip"),
            1_000L,
        )
        assertEquals(0, result.code)
        // 一行命令交给 root shell；含空格的参数被引号包住（不会拆成两个话题）。
        assertEquals(listOf("/data/adb/ksud module install '/sdcard/my module.zip'"), lines)
    }

    private data class Invocation(val method: String, val command: String, val timeoutMs: Long?)

    private fun recordingExecutor(calls: MutableList<Invocation>): KsuRootShellExecutor =
        java.lang.reflect.Proxy.newProxyInstance(
            KsuRootShellExecutor::class.java.classLoader,
            arrayOf(KsuRootShellExecutor::class.java),
        ) { _, method, arguments ->
            calls += Invocation(method.name, arguments!![0] as String, arguments.getOrNull(1) as? Long)
            KsuShellResult(7, listOf("out", ""), listOf("err", ""))
        } as KsuRootShellExecutor

    @Test
    fun ordinaryRunnerForwardsRequestedTimeoutAndReceipt() {
        val calls = mutableListOf<Invocation>()
        val result = RootShellKsuRunner(recordingExecutor(calls)).run(listOf("ksud", "module", "list"), 30_000L)
        assertEquals(listOf(Invocation("exec", "ksud module list", 30_000L)), calls)
        assertEquals(KsuShellResult(7, listOf("out", ""), listOf("err", "")), result)
    }

    @Test
    fun globalRunnerForwardsRequestedTimeoutAndNamespace() {
        val calls = mutableListOf<Invocation>()
        RootShellKsuRunner(recordingExecutor(calls), globalMnt = true)
            .run(listOf("ksud", "module", "action", "module.id"), 300_000L)
        assertEquals(listOf(Invocation("execInGlobalMount", "ksud module action module.id", 300_000L)), calls)
    }

    @Test
    fun installedExecutorReceivesEachRequestedTimeout() {
        val calls = mutableListOf<Invocation>()
        KsuRootShell.install(recordingExecutor(calls))
        try {
            KsuRootShell.runner().run(listOf("ksud", "module", "list"), 12_345L)
            KsuRootShell.runner(globalMnt = true).run(listOf("ksud", "module", "action", "module.id"), 54_321L)
            assertEquals(listOf(
                Invocation("exec", "ksud module list", 12_345L),
                Invocation("execInGlobalMount", "ksud module action module.id", 54_321L),
            ), calls)
        } finally {
            KsuRootShell.resetForTest()
        }
    }

    @Test
    fun normalModuleOperationsForwardLiveCallbacksThroughTheInstalledRootExecutor() {
        val calls = mutableListOf<Pair<Boolean, Long>>()
        val events = mutableListOf<String>()
        KsuRootShell.install(object : KsuRootShellExecutor {
            override fun exec(commandLine: String): KsuShellResult = error("use streaming")

            override fun execStreaming(
                commandLine: String, timeoutMs: Long, globalMnt: Boolean,
                onStdout: (String) -> Unit, onStderr: (String) -> Unit,
            ): KsuShellResult {
                calls += globalMnt to timeoutMs
                onStdout("working")
                onStderr("warning")
                events += "completed"
                return KsuShellResult(0, listOf("working"), listOf("warning"))
            }
        })
        try {
            val ops = KsuModuleOps(KsuCommandBackend.forDeployedDaemon(probe = object : KsuPathProbe {
                override fun exists(path: String): Boolean = true
            }))
            ops.installResult(tmp.newFile("streaming.zip"),
                { events += "out:$it" }, { events += "err:$it" })
            ops.action("fixture", { events += "out:$it" }, { events += "err:$it" })

            assertEquals(listOf(false to KsuTimeouts.MODULE_INSTALL_MS, true to KsuTimeouts.COMMAND_MS), calls)
            assertEquals(List(2) { listOf("out:working", "err:warning", "completed") }.flatten(), events)
        } finally {
            KsuRootShell.resetForTest()
        }
    }

    @Test
    fun oldSamAdapterStillExecutesOnce() {
        val lines = mutableListOf<String>()
        val executor = KsuRootShellExecutor { command ->
            lines += command
            KsuShellResult(0, listOf("legacy"), emptyList())
        }
        assertEquals(0, RootShellKsuRunner(executor).run(listOf("ksud", "module", "list"), 12_345L).code)
        assertEquals(listOf("ksud module list"), lines)
    }

    @Test
    fun oldGlobalOverrideStaysInGlobalNamespace() {
        val lines = mutableListOf<String>()
        val executor = object : KsuRootShellExecutor {
            override fun exec(commandLine: String): KsuShellResult = error("ordinary namespace must not be used")
            override fun execInGlobalMount(commandLine: String): KsuShellResult {
                lines += commandLine
                return KsuShellResult(0, listOf("legacy-global"), emptyList())
            }
        }
        assertEquals(0, RootShellKsuRunner(executor, globalMnt = true)
            .run(listOf("ksud", "module", "action", "module.id"), 12_345L).code)
        assertEquals(listOf("ksud module action module.id"), lines)
    }

    @Test
    fun unwiredRootShellFailsExplicitlyNeverAppUid() {
        KsuRootShell.resetForTest()
        val result = KsuRootShell.runner().run(listOf("/data/adb/ksud", "module", "list"), 1_000L)
        assertEquals(-1, result.code)
        assertTrue(result.errText.contains(KsuRootShell.UNAVAILABLE))
        assertTrue(result.errText.contains("not wired"))
        assertFalse(result.code == 0)
    }

    @Test
    fun rootShellRunnerExceptionsBecomeExplicitFailures() {
        val runner = RootShellKsuRunner(KsuRootShellExecutor { error("shell died") })
        val result = runner.run(listOf("/data/adb/ksud", "module", "list"), 1_000L)
        assertEquals(-1, result.code)
        assertTrue(result.errText.contains(KsuRootShell.UNAVAILABLE))
        for ((failure, expected) in listOf(
            IllegalStateException("stream died") to KsuRootShell.UNAVAILABLE,
            TimeoutException("deadline") to "KSU_COMMAND_TIMEOUT",
            InterruptedException("interrupted") to "KSU_COMMAND_INTERRUPTED",
            CancellationException("cancelled") to "KSU_COMMAND_CANCELLED",
        )) {
            var calls = 0
            val out = mutableListOf<String>()
            val err = mutableListOf<String>()
            KsuRootShell.install(object : KsuRootShellExecutor {
                override fun exec(commandLine: String): KsuShellResult = error("use streaming")
                override fun execStreaming(
                    commandLine: String, timeoutMs: Long, globalMnt: Boolean,
                    onStdout: (String) -> Unit, onStderr: (String) -> Unit,
                ): KsuShellResult {
                    calls++
                    onStdout("partial")
                    onStdout("")
                    onStderr("warning")
                    throw IllegalStateException("outer", failure)
                }
            })
            try {
                val streamed = KsuRootShell.runner().runStreaming(
                    listOf("/data/adb/ksud", "module", "list"), 1_000L, out::add, err::add)
                assertEquals(-1, streamed.code)
                assertEquals(listOf("partial", ""), streamed.out)
                assertEquals(streamed.out, out)
                assertEquals(listOf("warning"), streamed.err.dropLast(1))
                assertEquals(streamed.err, err)
                assertTrue(streamed.err.last().startsWith("$expected:"))
                assertEquals(1, streamed.err.count { it.startsWith("$expected:") })
                assertEquals(1, calls)
                assertEquals(failure is InterruptedException, Thread.currentThread().isInterrupted)
            } finally {
                Thread.interrupted()
                KsuRootShell.resetForTest()
            }
        }
    }

    // ── 命令后端：模块/feature 走 root shell ────────────────────────────

    @Test
    fun moduleAndFeatureCommandsRunThroughRootShellWithDeployedDaemon() {
        val lines = mutableListOf<String>()
        val backend = KsuCommandBackend.forDeployedDaemon(
            daemonPath = "/data/adb/ksud",
            probe = object : KsuPathProbe {
                override fun exists(path: String): Boolean = true
                override fun canExecute(path: String): Boolean = true
            },
        )
        // 生产 runner 未装配 → 显式失败（下面再装一个 fake root shell 验证成功路径）。
        assertTrue(
            backend.runCommand(listOf("/data/adb/ksud", "module", "list"), 1_000L)
                .errText.contains(KsuRootShell.UNAVAILABLE),
        )

        KsuRootShell.install(
            KsuRootShellExecutor { line ->
                lines += line
                KsuShellResult(0, listOf("""[{"id":"m1"}]"""), emptyList())
            },
            probe = object : KsuPathProbe {
                override fun exists(path: String): Boolean = true
                override fun canExecute(path: String): Boolean = true
            },
        )
        try {
            val rootBackend = KsuCommandBackend.forDeployedDaemon()
            assertEquals("/data/adb/ksud", rootBackend.daemonPath())
            assertTrue(rootBackend.daemonExists())

            assertTrue(rootBackend.exec("module enable m1", newShell = true, globalMnt = false))
            lines.clear()
            assertEquals("""[{"id":"m1"}]""", rootBackend.capture("feature get sulog"))
            assertTrue(
                "feature 读也必须走 root shell 且指向部署后的 ksud",
                lines.contains("/data/adb/ksud feature get sulog"),
            )
            lines.clear()
            assertTrue(rootBackend.exec("feature set sulog 1", true, false))
            assertEquals(listOf("/data/adb/ksud feature set sulog 1"), lines)
        } finally {
            KsuRootShell.resetForTest()
        }
    }

    @Test
    fun deployedDaemonPathIsNotTheApkLauncher() {
        val backend = KsuCommandBackend.forDeployedDaemon()
        assertEquals("/data/adb/ksud", backend.daemonPath())
        assertFalse(KsuDaemonPolicyIsLauncher(backend.daemonPath()))
        // launcher 仍然可用（只为起 root shell），但它不是命令面。
        val app = KsuCommandBackend.forApp(File(tmp.newFolder("lib"), "libksud_ksu.so"))
        assertTrue(KsuDaemonPolicyIsLauncher(app.daemonPath()))
    }

    private fun KsuDaemonPolicyIsLauncher(path: String): Boolean =
        com.maplesu.core.ui.util.KsuDaemonPolicy.isLauncherPath(path)

    @Test
    fun daemonExistsUsesInjectedProbeNotLocalFile() {
        var probed = 0
        val backend = KsuCommandBackend(
            daemonPathProvider = { "/data/adb/ksud" },
            runner = KsuShellRunner { _, _ -> KsuShellResult(0, listOf("ok"), emptyList()) },
            probe = object : KsuPathProbe {
                override fun exists(path: String): Boolean = true
                override fun canExecute(path: String): Boolean {
                    probed++
                    return true
                }
            },
        )
        // 本地 /data/adb/ksud 在主机上必然不存在；后端必须信探针（root shell 的回答）。
        assertTrue(backend.daemonExists())
        assertEquals(1, probed)
    }

    @Test
    fun cachingProbeHonoursTtl() {
        var hits = 0
        val delegate = object : KsuPathProbe {
            override fun exists(path: String): Boolean = true
            override fun canExecute(path: String): Boolean {
                hits++
                return true
            }
        }
        var now = 0L
        val cached = CachingKsuPathProbe(delegate, ttlMs = 1_000L, clock = { now })
        assertTrue(cached.canExecute("/data/adb/ksud"))
        now = 500L
        assertTrue(cached.canExecute("/data/adb/ksud"))
        assertEquals("TTL 内不应重复探测", 1, hits)
        now = 1_500L
        assertTrue(cached.canExecute("/data/adb/ksud"))
        assertEquals(2, hits)
    }

    @Test
    fun rootShellPathProbeAnswersExistAndExecutableSeparately() {
        val commands = mutableListOf<String>()
        val probe = rootShellPathProbe(
            KsuRootShellExecutor { line ->
                commands += line
                if (line.contains(" -x ")) {
                    KsuShellResult(1, emptyList(), emptyList())
                } else {
                    KsuShellResult(0, listOf("MAPLESU_PROBE_OK"), emptyList())
                }
            },
        )
        assertTrue(probe.exists("/data/adb/ksu/lib/libadbroot.so"))
        assertFalse(probe.canExecute("/data/adb/ksud"))
        assertTrue(commands[0].contains("test -e"))
        assertTrue(commands[1].contains("test -x"))
    }

    @Test
    fun rootShellDigestParsesSha256AndDegradesToNull() {
        val digest = KsuBootstrap.rootShellDigest(
            KsuRootShellExecutor { line ->
                if (line.contains("missing")) {
                    KsuShellResult(1, emptyList(), listOf("no such file"))
                } else {
                    KsuShellResult(
                        0,
                        listOf("${"a".repeat(64)}  /data/adb/ksu/lib/libadbroot.so"),
                        emptyList(),
                    )
                }
            },
        )
        assertEquals("a".repeat(64), digest("/data/adb/ksu/lib/libadbroot.so"))
        // 读不到 ≠ 不一致：返回 null（未验证），由调用方显式处理。
        assertNull(digest("missing"))
    }

    // ── 模块列表映射：updateJson / props / stages ──────────────────────

    @Test
    fun moduleListMapperCarriesUpdateJsonPropsAndStages() {
        val raw = """
            [
              {
                "id": "demo",
                "name": "Demo",
                "version": "1.2",
                "versionCode": "12",
                "author": "me",
                "description": "d",
                "enabled": "true",
                "update": "true",
                "remove": "false",
                "web": "true",
                "action": "false",
                "metamodule": "false",
                "updateJson": "https://example.com/update.json",
                "stages": {"post-fs-data": {"status": "ok", "code": 0}},
                "props": {"applied": ["ro.demo=1"], "failed": ["ro.bad=2"]}
              },
              {"id": "no-meta", "enabled": "false"}
            ]
        """.trimIndent()
        val json = KsuModuleListMapper.toUiJson(raw)
        val rows = org.json.JSONArray(json)
        assertEquals(2, rows.length())
        val first = rows.getJSONObject(0)
        assertEquals("https://example.com/update.json", first.getString("updateJson"))
        assertEquals("ro.demo=1", first.getJSONObject("props").getJSONArray("applied").getString(0))
        assertEquals("ro.bad=2", first.getJSONObject("props").getJSONArray("failed").getString(0))
        assertEquals("ok", first.getJSONObject("stages").getJSONObject("post-fs-data").getString("status"))
        assertEquals("ksu_ksud", first.getString("backend"))
        // 缺失 = "没有"，不是编一个值
        val second = rows.getJSONObject(1)
        assertEquals("", second.getString("updateJson"))
        assertEquals(0, second.getJSONObject("props").getJSONArray("applied").length())
        assertEquals(0, second.getJSONObject("stages").length())
    }

    @Test
    fun moduleListMapperKeepsEmptyArraysForUnsupported() {
        val json = KsuModuleListMapper.toUiJson("""[{"id":"m1"}]""")
        val row = org.json.JSONArray(json).getJSONObject(0)
        assertEquals("[]", row.getJSONArray("unsupported").toString())
        assertEquals(0, row.getJSONObject("props").getJSONArray("failed").length())
    }

    @Test
    fun moduleListMapperKeepsGarbageDistinctFromEmptyArray() {
        assertTrue(runCatching { KsuModuleListMapper.toUiJson("not json") }.isFailure)
        assertTrue(runCatching { KsuModuleListMapper.toUiJson("""{"id":"x"}""") }.isFailure)
        assertTrue(runCatching { KsuModuleListMapper.count("nope") }.isFailure)
    }

    // ── 首次部署：显式状态 ────────────────────────────────────────────

    private fun fakeRunner(run: (String) -> Unit = {}): KsuRootCommandRunner =
        KsuRootCommandRunner { commandLine, _ ->
            run(commandLine)
            KsuShellResult(0, listOf("installed"), emptyList())
        }

    private fun writeDeployed(root: File) {
        File(root, "ksud").apply { parentFile?.mkdirs(); writeText("ksud") }
        File(root, "ksu/bin/ksud").apply { parentFile?.mkdirs(); writeText("ksud") }
        File(root, "ksu/lib/libadbroot.so").apply { parentFile?.mkdirs(); writeText("ADB") }
    }

    /** 部署后 `/data/adb/ksud` 的期望摘要（[writeDeployed] 写的是文本 "ksud"）。 */
    private fun deployedSha256(text: String = "ksud"): String = KsuInstallProducer.sha256(
        KsuImageFixtures.write(File(tmp.root, "expected-sha"), "ksud", text.toByteArray()),
    )

    private val deployedVersion =
        KsuVersionInfo(version = 32650, uapiVersion = 7, isLkm = true, flags = 0x21L)

    /**
     * T1：默认注入"全对"的三种事实，让既有用例只测它们本来想测的维度
     * （短路 / 部署 / 安装失败 / 安装不完整 / 缺 libadbroot）。
     */
    private fun bootstrap(
        runner: KsuRootCommandRunner,
        dataRoot: File,
        expectedKsudSha256: String? = deployedSha256(),
        version: KsuVersionInfo? = deployedVersion,
        busyboxOk: Boolean = true,
    ) = KsuBootstrap(
        daemonPath = File(tmp.root, "applib/libksud_ksu.so").absolutePath,
        runner = runner,
        dataAdbRoot = dataRoot,
        expectedKsudSha256 = expectedKsudSha256,
        versionProbe = { version },
        busyboxProbe = { busyboxOk },
    )

    @Test
    fun ensureDeployedSkipsWhenAlreadyPresent() {
        val dataRoot = tmp.newFolder("data-adb")
        writeDeployed(dataRoot)
        var runs = 0
        val result = bootstrap(fakeRunner { runs++ }, dataRoot).ensureDeployed(null)
        assertEquals(KsuBootstrapResult.Status.ALREADY_PRESENT, result.status)
        assertTrue(result.ok)
        assertEquals("已部署（摘要+版本+busybox 全对）时不得重跑 ksud install", 0, runs)
        assertNotNull(result.ksudPath)
    }

    @Test
    fun ensureDeployedReportsDeployedAndVerifiesPaths() {
        val dataRoot = tmp.newFolder("data-adb")
        val result = bootstrap(fakeRunner { writeDeployed(dataRoot) }, dataRoot).ensureDeployed(
            File(tmp.newFolder("apklib"), "libadbroot.so").apply { writeText("ADB") },
        )
        assertEquals(KsuBootstrapResult.Status.DEPLOYED, result.status)
        assertTrue(result.ok)
        assertEquals(File(dataRoot, "ksud").absolutePath, result.ksudPath)
        assertEquals(File(dataRoot, "ksu/bin/ksud").absolutePath, result.workDirKsudPath)
        assertEquals(File(dataRoot, "ksu/lib/libadbroot.so").absolutePath, result.libadbrootPath)
    }

    @Test
    fun ensureDeployedFailsExplicitlyWhenInstallFails() {
        val dataRoot = tmp.newFolder("data-adb")
        val runner = KsuRootCommandRunner { _, _ ->
            KsuShellResult(1, emptyList(), listOf("mount denied"))
        }
        val result = bootstrap(runner, dataRoot).ensureDeployed(
            File(tmp.newFolder("apklib"), "libadbroot.so").apply { writeText("ADB") },
        )
        assertEquals(KsuBootstrapResult.Status.FAILED, result.status)
        assertFalse(result.ok)
        assertEquals(KsuBootstrap.CODE_INSTALL_FAILED, result.failureCode)
        assertTrue(result.detail.contains("mount denied"))
    }

    @Test
    fun ensureDeployedFailsWhenPostInstallVerificationIncomplete() {
        val dataRoot = tmp.newFolder("data-adb")
        // 命令成功但文件没落地 → 必须失败（绝不"装完就算成功"）。
        val result = bootstrap(fakeRunner(), dataRoot).ensureDeployed(
            File(tmp.newFolder("apklib"), "libadbroot.so").apply { writeText("ADB") },
        )
        assertEquals(KsuBootstrapResult.Status.FAILED, result.status)
        assertEquals(KsuBootstrap.CODE_INSTALL_FAILED, result.failureCode)
        assertTrue(result.detail.contains("post-install verification failed"))
    }

    @Test
    fun ensureDeployedWithoutLibadbrootIsExplicitFailure() {
        val dataRoot = tmp.newFolder("data-adb")
        val result = bootstrap(fakeRunner { writeDeployed(dataRoot) }, dataRoot)
            .ensureDeployed(null)
        assertEquals(KsuBootstrapResult.Status.FAILED, result.status)
        assertEquals(KsuBootstrap.CODE_INSTALL_FAILED, result.failureCode)
    }

    @Test
    fun verifyUsesTheInjectedProbeSoDeployedPathsAreVisible() {
        val dataRoot = File("/data/adb") // 主机上不存在，且 app uid 读不到
        val probe = object : KsuPathProbe {
            override fun exists(path: String): Boolean = true
            override fun canExecute(path: String): Boolean = true
        }
        val verification = KsuBootstrap(
            daemonPath = "/x/libksud_ksu.so",
            runner = fakeRunner(),
            dataAdbRoot = dataRoot,
            probe = probe,
            digest = { "b".repeat(64) },
        ).verify(expectedLibadbrootSha256 = "b".repeat(64))
        assertTrue("root 探针说存在就必须认存在", verification.complete)
        assertEquals(true, verification.libadbrootDigestMatches)
    }

    @Test
    fun skippedResultIsExplicitNotSuccess() {
        val skipped = KsuBootstrapResult.skipped()
        assertEquals(KsuBootstrapResult.Status.SKIPPED_NOT_KSU, skipped.status)
        assertFalse(skipped.ok)
        assertEquals("mode is not KSU", skipped.detail)
    }
}
