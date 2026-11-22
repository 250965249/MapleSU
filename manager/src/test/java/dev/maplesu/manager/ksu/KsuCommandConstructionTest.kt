// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.ksu

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * ksud 命令构造 + 参数级硬拒绝。
 *
 * 这些用例是「只产候选、绝不写分区」的机器证明：任何 write/flash 类 flag
 * 在构造层就被拒绝，不依赖调用方自觉。
 */
class KsuCommandConstructionTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private val daemon = "/data/app/dev.maplesu.manager/lib/arm64/libksud_ksu.so"

    private fun sourceImage(): File = tmp.newFile("source.img").apply { writeBytes(ByteArray(16)) }

    private fun outDir(): File = tmp.newFolder("out")

    @Test
    fun bootPatchProducesCandidateOnly() {
        // TemporaryFolder.newFolder 只能建一次；这里先取一次再复用（lead 集成验证 #1）
        val out = outDir()
        val cmd = KsuCommands.bootPatch(
            daemon, sourceImage(), out, "candidate.img",
            KsuBootPatchOptions(kmi = "android15-6.6"),
        )
        assertEquals(daemon, cmd.first())
        assertTrue(cmd.containsAll(listOf("boot-patch", "--partition", "init_boot")))
        assertTrue(cmd.containsAll(listOf("-o", out.absolutePath)))
        assertTrue(cmd.containsAll(listOf("--out-name", "candidate.img")))
        assertTrue(cmd.containsAll(listOf("--kmi", "android15-6.6")))
        // 绝不出现写分区类 flag
        listOf("--flash", "-f", "--backup", "--ota", "--force-foreign", "--no-install", "--kernel")
            .forEach { assertFalse("forbidden token leaked: $it", it in cmd) }
    }

    @Test
    fun bootPatchRejectsIllegalPartition() {
        val ex = runCatching {
            KsuCommands.bootPatch(
                daemon, sourceImage(), outDir(), "c.img",
                KsuBootPatchOptions(partition = "system"),
            )
        }.exceptionOrNull()
        assertTrue("expected KsuCommandRejectedException, got $ex",
            ex is KsuCommandRejectedException)
        assertTrue((ex as KsuCommandRejectedException).token.contains("system"))
    }

    @Test
    fun bootPatchRejectsShellMetacharactersInOutName() {
        val ex = runCatching {
            KsuCommands.bootPatch(
                daemon, sourceImage(), outDir(), "../evil;rm -rf /",
                KsuBootPatchOptions(),
            )
        }.exceptionOrNull()
        assertTrue(ex is KsuCommandRejectedException)
    }

    @Test
    fun bootPatchRejectsIllegalKmi() {
        val ex = runCatching {
            KsuCommands.bootPatch(
                daemon, sourceImage(), outDir(), "c.img",
                KsuBootPatchOptions(kmi = "android15-6.6; reboot"),
            )
        }.exceptionOrNull()
        assertTrue(ex is KsuCommandRejectedException)
    }

    @Test
    fun bootPatchRejectsMissingSource() {
        val ex = runCatching {
            KsuCommands.bootPatch(
                daemon, File(tmp.root, "nope.img"), outDir(), "c.img", KsuBootPatchOptions(),
            )
        }.exceptionOrNull()
        assertTrue(ex is IllegalArgumentException)
    }

    @Test
    fun bootPatchCarriesForceFeatureAndBlockModule() {
        val cmd = KsuCommands.bootPatch(
            daemon, sourceImage(), outDir(), "c.img",
            KsuBootPatchOptions(
                allowShell = true,
                enableAdb = true,
                forceFeatures = mapOf("sulog" to 1L, "adb_root" to 0L),
                blockModules = listOf("mod_a", "mod_b"),
            ),
        )
        assertTrue(cmd.contains("--allow-shell"))
        assertTrue(cmd.contains("--enable-adbd"))
        // 必须按 key 排序，保证命令可复现
        val first = cmd.indexOf("--force-feature")
        assertEquals("--force-feature", cmd[first])
        assertEquals("adb_root:0", cmd[first + 1])
        val blocks = cmd.indexOf("--block-module")
        assertEquals("mod_a,mod_b", cmd[blocks + 1])
    }

    @Test
    fun rawForbiddenTokensAreRejected() {
        val forbidden = listOf(
            "--flash", "-f", "--backup", "--ota", "-u", "--force-foreign",
            "--no-install", "--kernel", "--restore", "--partition",
        )
        forbidden.forEach { token ->
            val ex = runCatching { KsuCommands.rejectForbidden(listOf(token)) }.exceptionOrNull()
            assertTrue("token must be rejected: $token", ex is KsuCommandRejectedException)
        }
    }

    @Test
    fun partitionAllowedOnlyOnBootPatchPath() {
        // 受控构造允许（内部 allowPartition=true）
        KsuCommands.rejectForbidden(
            listOf("--partition", "init_boot"), allowPartition = true)
        // 其它路径（模块 action / 用户输入）不允许
        val ex = runCatching {
            KsuCommands.rejectForbidden(listOf("--partition", "init_boot"))
        }.exceptionOrNull()
        assertTrue(ex is KsuCommandRejectedException)
    }

    @Test
    fun bootRestoreImageHasNoFlashFlag() {
        val out = outDir()
        val cmd = KsuCommands.bootRestoreImage(daemon, out, "restore.img")
        assertEquals(listOf(daemon, "boot-restore", "-o", out.absolutePath,
            "--out-name", "restore.img"), cmd)
        assertFalse("-f" in cmd)
        assertFalse("--flash" in cmd)
    }

    @Test
    fun copyRebuildHasExplicitInputAndNeverSelectsALivePartition() {
        val image = tmp.newFile("input copy.img").apply { writeBytes(byteArrayOf(1)) }
        val out = outDir()
        val cmd = KsuCommands.bootRebuildCopy(daemon, image, out, "rebuilt.img")
        assertEquals(listOf(daemon, "boot-restore", "--file-only", "--boot", image.absolutePath,
            "-o", out.absolutePath, "--out-name", "rebuilt.img"), cmd)
        assertFalse(cmd.any { it in KsuCommands.FORBIDDEN_TOKENS })
    }

    @Test
    fun copyRebuildRejectsMissingInputAndExistingOrEscapingOutput() {
        val image = tmp.newFile("source.img")
        val out = outDir()
        assertTrue(runCatching { KsuCommands.bootRebuildCopy(daemon, File(tmp.root, "missing"), out, "new.img") }.isFailure)
        File(out, "exists.img").writeText("preserve")
        for (name in listOf("exists.img", "..", "../source.img")) {
            assertTrue(runCatching { KsuCommands.bootRebuildCopy(daemon, image, out, name) }.isFailure)
        }
        assertEquals("preserve", File(out, "exists.img").readText())
    }

    @Test
    fun moduleCommandsValidateIds() {
        assertTrue(KsuCommands.module(daemon, "enable", "my_module").contains("my_module"))
        val ex = runCatching {
            KsuCommands.module(daemon, "enable", "bad; id")
        }.exceptionOrNull()
        assertTrue(ex is KsuCommandRejectedException)
    }

    /**
     * 开发文档 §2.3 A1 / §10.3 D3：`-g` 只属于 `debug su`，不属于 `module action`。
     * 上游形态是 `"${ksud} module action $id"` + `withNewRootShell(true)`，全局命名空间
     * 由 **root shell** 提供。拼 `-g` 会被 clap 拒绝（`unexpected argument '-g'`），
     * Action 因此 100% 失败。
     */
    @Test
    fun moduleActionCarriesNoDashG() {
        val cmd = KsuCommands.moduleAction(daemon, "m1")
        assertEquals(listOf(daemon, "module", "action", "m1"), cmd)
        assertFalse("module action 不得携带 -g", cmd.contains("-g"))
        assertFalse("module action 不得携带任何 flag", cmd.drop(3).any { it.startsWith("-") })
    }

    /** 非法模块 id 必须在构造层被拒（不允许把任意 token 送进 ksud）。 */
    @Test
    fun moduleActionRejectsIllegalId() {
        val ex = runCatching { KsuCommands.moduleAction(daemon, "bad id; rm -rf /") }.exceptionOrNull()
        assertTrue(ex is KsuCommandRejectedException)
    }

    @Test
    fun featureCommandsValidateNameAndAction() {
        assertEquals(
            listOf(daemon, "feature", "set", "kernel_umount", "1"),
            KsuCommands.feature(daemon, "set", "kernel_umount", 1L),
        )
        assertTrue(
            runCatching { KsuCommands.feature(daemon, "set", "not_a_feature", 1L) }
                .exceptionOrNull() is KsuCommandRejectedException)
        assertTrue(
            runCatching { KsuCommands.feature(daemon, "explode", "sulog") }
                .exceptionOrNull() is KsuCommandRejectedException)
    }

    @Test
    fun installStagingFlagIsExplicit() {
        val cmd = KsuCommands.install(daemon, null, null, stageForSwitch = true)
        assertEquals(listOf(daemon, "install", "--stage-for-switch"), cmd)
        val normal = KsuCommands.install(daemon, null, null, stageForSwitch = false)
        assertFalse("--stage-for-switch" in normal)
    }

    @Test
    fun debugInfoAndBootInfoShapes() {
        // Windows 上没有 /tmp；镜像参数必须是真实存在的临时文件（lead 集成验证 #2）
        val image = tmp.newFile("boot.img").apply { writeBytes(ByteArray(8)) }
        assertEquals(listOf(daemon, "debug", "info"), KsuCommands.debugInfo(daemon))
        assertEquals(
            listOf(daemon, "boot-info", "ramdisk-state", "--boot", image.absolutePath),
            KsuCommands.bootInfo(
                daemon, KsuBootInfoSubcommand.RAMDISK_STATE, image),
        )
        assertTrue(
            runCatching {
                KsuCommands.bootInfo(daemon, KsuBootInfoSubcommand.CURRENT_KMI, image)
            }.exceptionOrNull() is KsuCommandRejectedException)
    }
}
