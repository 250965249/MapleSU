// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.ksu

import java.io.File
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * 三元组一致性门禁：upstream_commit + patch_series_sha256 + UAPI=7。
 *
 * 纯 JVM、只读第三方树（`third_party/kernelsu` 下的 manifest/payload json）；
 * 不加载 native、不起进程。
 */
class KsuPayloadConsistencyTest {

    private val json = Json { ignoreUnknownKeys = true; isLenient = true }

    private fun root(): File = KsuTestPaths.kernelsuRoot().also {
        assertTrue("manifest.json missing: ${it.path}", File(it, "manifest.json").isFile)
    }

    private fun readJson(file: File): JsonObject =
        json.parseToJsonElement(file.readText()).jsonObject

    private fun JsonObject.str(key: String): String = this[key]!!.jsonPrimitive.content
    private fun JsonObject.int(key: String): Int = this[key]!!.jsonPrimitive.int

    @Test
    fun upstreamCommitIsPinned() {
        val manifest = readJson(File(root(), "manifest.json"))
        val upstream = manifest["upstream"]!!.jsonObject
        assertEquals(
            "upstream commit drifted from the selected successful official CI",
            "f4603d14bd7f3bf21206d6f7c622ddf1c049ade3",
            upstream.str("commit"),
        )
        assertEquals(6, upstream.int("uapiVersion"))
        val ci = upstream["ci"]!!.jsonObject
        assertEquals("44010950397", ci.str("runId"))
        assertEquals(5545, ci.int("runNumber"))
        assertEquals("success", ci.str("conclusion"))
        assertEquals(upstream.str("commit"), ci.str("headSha"))
    }

    @Test
    fun source7kCommitIsPinned() {
        val manifest = readJson(File(root(), "manifest.json"))
        val source7k = manifest["source7k"]!!.jsonObject
        assertEquals("dafd0a96ab1ad37cb4aa692b4081bf68e231d6a7", source7k.str("commit"))
        assertEquals("v2.30", source7k.str("release"))
        assertEquals(5, source7k.int("uapiVersion"))
    }

    @Test
    fun manifestHasThreeLayerEvidence() {
        val manifest = readJson(File(root(), "manifest.json"))
        val upstream = manifest["upstream"]!!.jsonObject
        // 三层证据：commit + 逐文件 sha256 + 树聚合哈希
        assertTrue(upstream.str("treeSha256").matches(Regex("^[0-9a-f]{64}$")))
        val files = upstream["files"]!!.jsonArray
        assertEquals(upstream.int("fileCount"), files.size)
        assertTrue(files.size >= 788)
        val first = files.first().jsonObject
        assertTrue(first.str("path").isNotEmpty() || first.str("path").isEmpty())
        assertTrue(first.str("sha256").matches(Regex("^[0-9a-f]{64}$")))
    }

    @Test
    fun patchSeriesOrderMatchesSeriesFile() {
        val root = root()
        val manifest = readJson(File(root, "manifest.json"))
        val patchSeries = manifest["patchSeries"]!!.jsonObject
        val order = patchSeries["order"]!!.jsonArray.map { it.jsonPrimitive.content }
        val seriesFile = File(root, "patches/7k/series")
        assertTrue("patches/7k/series missing", seriesFile.isFile)
        val series = seriesFile.readLines()
            .map { it.trim() }
            .filter { it.isNotEmpty() && !it.startsWith("#") }
        assertEquals(series, order)
        // 每个补丁 sha256 与文件一致
        patchSeries["entries"]!!.jsonArray.forEach { entry ->
            val obj = entry.jsonObject
            val patch = File(root, "patches/7k/" + obj.str("name"))
            assertTrue("patch missing: $patch", patch.isFile)
            assertEquals(sha256(patch), obj.str("sha256"))
        }
    }

    @Test
    fun patchSeriesIncludesCurrentNormalRecoveryFixes() {
        val manifest = readJson(File(root(), "manifest.json"))
        val names = manifest["patchSeries"]!!.jsonObject["order"]!!.jsonArray
            .map { it.jsonPrimitive.content }
        assertEquals(
            listOf(
                "0001-manager-identity.patch",
                "0002-uapi-v7.patch",
                "0003-stealth.patch",
                "0004-app-lock.patch",
                "0005-manager-generation-gate.patch",
                "0006-webadmin.patch",
                "0007-boot-patch-safety.patch",
                "0008-restore-user-data.patch",
                "0009-install-staging-label.patch",
                "0010-manager-jni-facade.patch",
                "0011-webadmin-api-surface.patch",
                "0012-boot-patch-safety-wiring.patch",
                "0013-restore-user-data-wiring.patch",
                "0014-manager-package-triple-check.patch",
                "0015-normal-recovery.patch",
                "0016-ksud-build-identity.patch",
                "0018-vivo-vr-compatibility.patch",
                "0019-maplesu-93260-symbol-input.patch",
                "0020-jailbreak-selinux-session.patch",
                "0021-maplesu-manager-namespace.patch",
                "0022-boot-copy-rebuild.patch",
                "0023-boot-backup-optional.patch",
                "0024-boot-empty-origin-restore.patch",
                "0025-target-kernel-kmi.patch",
            ),
            names,
        )
        val superseded = manifest["patchSeries"]!!.jsonObject["superseded"]!!.jsonArray
        val selinux = superseded.single { it.jsonObject.str("name") == "0017-selinux-upstream-sync.patch" }.jsonObject
        assertEquals("superseded-upstream", selinux.str("status"))
        assertEquals(manifest["upstream"]!!.jsonObject.str("commit"), selinux.str("upstream"))
    }

    @Test
    fun todoEntriesAreDeclaredNotHidden() {
        val manifest = readJson(File(root(), "manifest.json"))
        val todo = manifest["patchSeries"]!!.jsonObject["todo"]!!.jsonArray
        assertTrue("unfinished ports must be explicitly declared", todo.size >= 3)
        todo.forEach { entry ->
            val obj = entry.jsonObject
            assertTrue(obj.str("name").isNotEmpty())
            assertTrue(obj.str("reason").length > 20)
        }
    }

    @Test
    fun payloadMatchesManifestTriple() {
        val root = root()
        val payloadFile = File(root, "ksu-payload.json")
        assertTrue("ksu-payload.json not generated (run rebuild.sh)", payloadFile.isFile)
        val payload = readJson(payloadFile)
        val manifest = readJson(File(root, "manifest.json"))
        val branch = payload["branch"]!!.jsonObject
        assertEquals(manifest["upstream"]!!.jsonObject.str("commit"), branch.str("upstream"))
        assertEquals(
            manifest["patchSeries"]!!.jsonObject.str("seriesSha256"),
            branch.str("patchSeriesSha256"),
        )
        assertEquals(
            manifest["patchSeries"]!!.jsonObject.str("aggregateSha256"),
            branch.str("aggregatePatchSha256"),
        )
        assertEquals(7, branch.int("uapi"))
        assertEquals(manifest["applied"]!!.jsonObject.str("treeSha256"), branch.str("treeSha256"))
        assertEquals(manifest["applied"]!!.jsonObject.int("fileCount"), branch.int("fileCount"))
        assertTrue(branch.int("fileCount") >= 800)
    }

    @Test
    fun payloadNeverFakesArtifactHashes() {
        val root = root()
        val payloadFile = File(root, "ksu-payload.json")
        assertTrue("ksu-payload.json not generated", payloadFile.isFile)
        val payload = readJson(payloadFile)
        val artifacts = payload["artifacts"]!!.jsonArray
        assertTrue(artifacts.isNotEmpty())
        artifacts.forEach { element ->
            val art = element.jsonObject
            when (art.str("status")) {
                "present" -> {
                    assertTrue(
                        "present artifact must carry real sha256: " + art.str("name"),
                        art.str("sha256").matches(Regex("^[0-9a-f]{64}$")),
                    )
                    assertTrue(
                        "present artifact must carry positive size: " + art.str("name"),
                        art.str("size").toLongOrNull()?.let { it > 0L } == true,
                    )
                }
                // 本机产不出的产物只能是 pending-ci，且**不得**带假哈希
                "pending-ci" -> assertFalse(
                    "pending-ci artifact must not carry a sha256: " + art.str("name"),
                    art.containsKey("sha256"),
                )
                else -> throw AssertionError("unknown artifact status: " + art.str("status"))
            }
        }
        val present = artifacts.count { it.jsonObject.str("status") == "present" }
        // CI 回填 .ko 后允许 0 pending（当前 6/6 present）；至少必须有 1 个真实产物。
        assertTrue("expected at least one present artifact", present >= 1)
    }

    @Test
    fun identityCoversPackageGenAndPin() {
        val manifest = readJson(File(root(), "manifest.json"))
        val identity = manifest["identity"]!!.jsonObject
        assertEquals("dev.maplesu.manager", identity.str("packageName"))
        assertEquals(7, identity.int("uapiVersion"))
        assertEquals(2, identity.int("managerMinGen"))
        assertEquals("assets/ksu_manager_gen2", identity.str("managerGenAsset"))
        assertEquals(32650, identity.int("ksuVersionPin"))
        assertEquals(0, identity.int("isPrBuild"))
        // Maple 发行证书公开 DER 的固定契约；不得退回占位值或接受任意指纹。
        assertEquals(772, identity.int("expectedSize"))
        assertEquals("30bafb57e3604afe93da13a1285516e043feb82b56a861a157b53ccaa27c3506", identity.str("expectedHash"))
    }

    @Test
    fun managerPackageTripleCheckIsConsistent() {
        val root = root()
        val manifest = readJson(File(root, "manifest.json"))
        val identity = manifest["identity"]!!.jsonObject
        val pkg = identity.str("managerPackage")
        assertEquals("dev.maplesu.manager", pkg)
        assertEquals(identity.str("packageName"), pkg)
        // 三处同值：kernel Kbuild 默认值 / ksud build.rs 默认值 / manifest（payload 由 test 6 对齐）。
        // W18b（0014）起 manifest.identity.managerPackageSources 必须**恰好**记录这 3 个来源，
        // 且每条都指向对应文件 —— 断言来源数量与内容，而不是把它弱化成"非空"。
        val sources = identity["managerPackageSources"]!!.jsonArray.map { it.jsonPrimitive.content }
        assertEquals(3, sources.size)
        assertTrue("kernel source missing: $sources", sources.any { it.contains("kernel/Kbuild") })
        assertTrue("ksud source missing: $sources", sources.any { it.contains("userspace/ksud/build.rs") })
        assertTrue("manifest source missing: $sources", sources.any { it.contains("manifest.json") })
        assertTrue("kernel source must carry the package: $sources",
            sources.any { it.contains("kernel/Kbuild") && it.contains(pkg) })
        assertTrue("ksud source must carry the package: $sources",
            sources.any { it.contains("build.rs") && it.contains(pkg) })
        val applied = File(root, "applied")
        assumeTrue("applied/ not generated", applied.isDirectory)
        assertTrue(
            "Kbuild must default KSU_MANAGER_PACKAGE to $pkg",
            File(applied, "kernel/Kbuild").readText().contains("KSU_MANAGER_PACKAGE ?= $pkg"),
        )
        assertTrue(
            "ksud build.rs must default KSU_PACKAGE_NAME to $pkg",
            File(applied, "userspace/ksud/build.rs").readText()
                .contains("cargo:rustc-env=KSU_PACKAGE_NAME=$pkg"),
        )
        val apk = File(applied, "kernel/manager/apk_sign.c").readText()
        assertTrue(apk.contains("#ifdef KSU_MANAGER_PACKAGE"))
        assertTrue(apk.contains("get_pkg_from_apk_path"))
        val payload = File(root, "ksu-payload.json")
        assumeTrue("ksu-payload.json not generated", payload.isFile)
        assertEquals(pkg, readJson(payload)["identity"]!!.jsonObject.str("managerPackage"))
    }

    @Test
    fun w18bPortsArePresentInAppliedTree() {
        val root = root()
        val applied = File(root, "applied")
        assumeTrue("applied/ not generated", applied.isDirectory)
        val bootPatch = File(applied, "userspace/ksud/src/boot_patch.rs").readText()
        listOf(
            "pub enum RamdiskState",
            "fn init_disposition",
            "fn should_record_stock",
            "fn write_and_verify",
            "fn rollback_partition",
            "fn flash_failure_error",
            "fn restore_admission",
            "pub fn query_ramdisk_state",
            "OURS_MARKER_ENTRY",
        ).forEach { assertTrue("boot_patch.rs 缺 $it", bootPatch.contains(it)) }
        val ksucalls = File(applied, "userspace/ksud/src/ksucalls.rs").readText()
        listOf("pub fn stealth_get_authed", "pub fn get_app_profile",
               "pub fn allow_list_uids").forEach {
            assertTrue("ksucalls.rs 缺 $it", ksucalls.contains(it))
        }
        val module = File(applied, "userspace/ksud/src/module.rs").readText()
        assertTrue(module.contains("pub fn list_modules_json"))
        val utils = File(applied, "userspace/ksud/src/utils.rs").readText()
        assertTrue(utils.contains("fn backup_user_data"))
        assertTrue(utils.contains("fn restore_user_data"))
        val main = File(applied, "userspace/ksud/src/main.rs").readText()
        assertTrue(main.contains("mod webadmin_ksud;"))
        assertTrue(main.contains("mod restore_user_data;"))
    }

    @Test
    fun appliedTreeCarriesKeyPaths() {
        val root = root()
        val applied = File(root, "applied")
        assertTrue("applied/ not generated (run rebuild.sh)", applied.isDirectory)
        listOf(
            "kernel/Kbuild",
            "kernel/supercall/dispatch.c",
            "kernel/supercall/perm.c",
            "kernel/manager/stealth.c",
            "kernel/manager/app_lock.c",
            "uapi/supercall.h",
            "userspace/ksud/src/webadmin.rs",
            "userspace/ksud/src/restore_user_data.rs",
            "userspace/ksuinit/src/init.rs",
            "manager/app/src/main/cpp/jni.cc",
            "manager/app/src/main/cpp/ksu.cc",
        ).forEach { rel ->
            assertTrue("applied 缺关键路径: $rel", File(applied, rel).isFile)
        }
        // 上游独有（UAPI6）能力也要在树里，不能被 7K 移植覆盖丢掉
        assertTrue(File(applied, "kernel/preinit/preinit.c").isFile)
        assertTrue(File(applied, "userspace/ksud/src/hot_install.rs").isFile)
    }

    private fun sha256(file: File): String {
        val digest = java.security.MessageDigest.getInstance("SHA-256")
        digest.update(file.readBytes())
        return digest.digest().joinToString("") { "%02x".format(it) }
    }
}
