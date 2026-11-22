// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.installer

import dev.maplesu.manager.ksu.KsuTestPaths
import java.io.File
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 多 KMI 矩阵 / 设备 KMI 检测 / 产物选择（Normal/KSU 模式）。
 *
 * 纯 JVM：不碰 Android、不 exec ksud、不读 /proc。payload 与 `lkm/` 的交叉断言只读文件。
 */
class KsuKmiMatrixTest {

    private val json = Json { ignoreUnknownKeys = true; isLenient = true }

    // ------------------------------------------------------------------ matrix

    @Test
    fun matrixIsTheEightBuiltNormalKmis() {
        assertEquals(
            listOf(
                "android12-5.10",
                "android13-5.10",
                "android13-5.15",
                "android14-5.15",
                "android14-6.1",
                "android15-6.6",
                "android16-6.12",
                "android17-6.18",
            ),
            KsuKmiMatrix.KMIS,
        )
        assertEquals(KsuKmiMatrix.KMIS.size, KsuKmiMatrix.KMIS.toSet().size)
    }

    @Test
    fun everySpecCarriesArtifactAndDdkIdentity() {
        KsuKmiMatrix.ENTRIES.forEach { spec ->
            assertEquals("${spec.kmi}_kernelsu.ko", spec.artifactName)
            assertEquals("ghcr.io/ylarod/ddk-min:${spec.kmi}-${KsuKmiMatrix.DDK_RELEASE}", spec.ddkImage)
            assertTrue("sdk range", spec.minSdk in 31..37 && spec.maxSdk >= spec.minSdk)
            assertEquals(
                "android${spec.androidMajor}-${spec.kernelSeries}",
                spec.kmi,
            )
        }
    }

    @Test
    fun onlyAndroid12IsNotDirectInstallable() {
        // android12 设备没有独立 init_boot：矩阵里有产物，但不走独立 init_boot 直装。
        assertFalse(KsuKmiMatrix.spec("android12-5.10")!!.directInstall)
        KsuKmiMatrix.ENTRIES.filter { it.kmi != "android12-5.10" }.forEach {
            assertTrue("${it.kmi} must stay direct-installable", it.directInstall)
        }
    }

    @Test
    fun kernelSeriesMapsToEveryAndroidMajorOnThatSeries() {
        assertEquals(listOf("android12-5.10", "android13-5.10"), KsuKmiMatrix.forKernelSeries("5.10").map { it.kmi })
        assertEquals(listOf("android13-5.15", "android14-5.15"), KsuKmiMatrix.forKernelSeries("5.15").map { it.kmi })
        assertEquals(listOf("android16-6.12"), KsuKmiMatrix.forKernelSeries("6.12").map { it.kmi })
        assertEquals(listOf("android17-6.18"), KsuKmiMatrix.forKernelSeries("6.18").map { it.kmi })
    }

    @Test
    fun sdkDoesNotChooseBetweenMultipleKernelKmis() {
        assertEquals("android12-5.10", KsuKmiMatrix.forSdk(31)!!.kmi)
        assertEquals("android12-5.10", KsuKmiMatrix.forSdk(32)!!.kmi)
        assertNull(KsuKmiMatrix.forSdk(33))
        assertNull(KsuKmiMatrix.forSdk(34))
        assertEquals("android15-6.6", KsuKmiMatrix.forSdk(35)!!.kmi)
        assertEquals("android16-6.12", KsuKmiMatrix.forSdk(36)!!.kmi)
        assertNull(KsuKmiMatrix.forSdk(30))
        assertEquals("android17-6.18", KsuKmiMatrix.forSdk(37)!!.kmi)
        assertNull(KsuKmiMatrix.forSdk(38))
    }

    // ------------------------------------------------------------------ detection

    @Test
    fun detectsEveryMatrixKmiFromRealisticUname() {
        val releases = mapOf(
            "android12-5.10" to "5.10.252-android12-9-00001-g1234567890ab",
            "android13-5.10" to "5.10.252-android13-4-g1234567890ab",
            "android13-5.15" to "5.15.202-android13-5.15.202_r00-00002-gabcdef",
            "android14-5.15" to "5.15.180-android14-8-g1234567890ab",
            "android14-6.1" to "6.1.166-android14-11-g1234567890ab",
            "android15-6.6" to "6.6.127-android15-8-4k-g46a034eca005",
            "android16-6.12" to "6.12.76-android16-6-gdeadbeef",
            "android17-6.18" to "6.18.21-android17-5-g1234567890ab",
        )
        assertEquals(KsuKmiMatrix.KMIS, releases.keys.toList())
        releases.forEach { (expected, release) ->
            val detection = KsuKmiDetector.detect(release)
            assertTrue("${detection.code}: ${detection.detail}", detection.ok)
            assertEquals(expected, detection.kmi)
            assertTrue(detection.evidence.contains("uname="))
        }
    }

    @Test
    fun unbuiltKernelIsNamedNotSilentlyRemapped() {
        val detection = KsuKmiDetector.detect("5.10.252-android14-4-g1234567890ab")
        assertFalse(detection.ok)
        assertEquals(KsuKmiDetection.CODE_NOT_IN_MATRIX, detection.code)
        assertEquals("android14-5.10", detection.kmi)
        assertTrue(detection.detail.contains("android13-5.15"))

        val android15 = KsuKmiDetector.detect("5.15.180-android15-8-g1234567890ab")
        assertEquals(KsuKmiDetection.CODE_NOT_IN_MATRIX, android15.code)
        assertEquals("android15-5.15", android15.kmi)
    }

    @Test
    fun unparseableReleaseFailsClosed() {
        listOf("", "garbage", "6.1.166", "android14").forEach { release ->
            val detection = KsuKmiDetector.detect(release)
            assertFalse("expected failure for '$release'", detection.ok)
            assertEquals(KsuKmiDetection.CODE_UNPARSEABLE, detection.code)
            assertNull(detection.kmi)
        }
    }

    @Test
    fun sdkDoesNotOverrideTheKernelKmi() {
        // 系统升级不要求同时升级内核；未知 SDK 也不能替代 uname 的 KMI。
        val releases = mapOf(
            "android12-5.10" to "5.10.252-android12-9-g1234567890ab",
            "android13-5.10" to "5.10.252-android13-4-g1234567890ab",
            "android13-5.15" to "5.15.202-android13-8-g1234567890ab",
            "android14-5.15" to "5.15.180-android14-8-g1234567890ab",
            "android14-6.1" to "6.1.166-android14-11-g1234567890ab",
            "android15-6.6" to "6.6.127-android15-8-g1234567890ab",
            "android16-6.12" to "6.12.76-android16-6-g1234567890ab",
            "android17-6.18" to "6.18.5-android17-5-g1234567890ab",
        )
        releases.forEach { (kmi, release) ->
            listOf(0, 34, 35, 36, 37).forEach { sdk ->
                val detection = KsuKmiDetector.detect(release, sdkInt = sdk)
                assertTrue("$kmi with SDK $sdk: ${detection.code}", detection.ok)
                assertEquals(kmi, detection.kmi)
                if (sdk > 0) assertTrue(detection.evidence.contains("sdk=$sdk"))
            }
        }
    }

    @Test
    fun boardPlatformIsCrossCheckNotSelector() {
        // 已知平台与内核代际冲突 → 报错（不静默选其中一个）。
        // gs201 只出现在 android13；内核说 android15 → 矛盾。
        val conflict = KsuKmiDetector.detect(
            "6.6.127-android15-8-4k-gabcdef", boardPlatform = "gs201",
        )
        assertEquals(KsuKmiDetection.CODE_MISMATCH, conflict.code)
        assertTrue(conflict.detail.contains("gs201"))
        // 平台自身跨多个 Android 大版本时，不因"平台老"而拒绝合法内核代际。
        assertTrue(
            KsuKmiDetector.detect(
                "5.15.202-android13-5.15.202_r00-gabcdef", boardPlatform = "taro",
            ).ok,
        )
        assertTrue(
            KsuKmiDetector.detect("6.6.127-android15-8-4k-gabcdef", boardPlatform = "sun").ok,
        )
        // 未知平台只作为证据，不阻塞。
        val unknown = KsuKmiDetector.detect(
            "6.6.127-android15-8-4k-gabcdef", boardPlatform = "some-new-soc",
        )
        assertTrue(unknown.ok)
        assertTrue(unknown.evidence.contains("platform=some-new-soc"))
    }

    // ------------------------------------------------------------------ selection

    @Test
    fun selectorReturnsReadyWhenPackaged() {
        val selection = KsuKmiSelector.select("android14-6.1", KsuKmiMatrix.KMIS)
        assertTrue(selection is KsuKmiSelection.Ready)
        val ready = selection as KsuKmiSelection.Ready
        assertEquals("android14-6.1", ready.kmi)
        assertEquals("android14-6.1_kernelsu.ko", ready.artifactName)
    }

    @Test
    fun selectorFailsWhenArtifactNotPackaged() {
        // 旧 APK 只打包了 android15-6.6：请求 android16-6.12 必须明确失败并报出期望的资产名。
        val selection = KsuKmiSelector.select("android16-6.12", setOf("android15-6.6"))
        assertTrue(selection is KsuKmiSelection.Missing)
        val missing = selection as KsuKmiSelection.Missing
        assertEquals(KsuKmiSelector.CODE_ARTIFACT_MISSING, missing.code)
        assertTrue(missing.detail.contains("android16-6.12_kernelsu.ko"))
        assertTrue(missing.detail.contains("android15-6.6"))
    }

    @Test
    fun selectorRejectsKmiOutsideMatrix() {
        val selection = KsuKmiSelector.select("android14-5.10", setOf("android14-5.10"))
        assertTrue(selection is KsuKmiSelection.Missing)
        assertEquals(
            KsuKmiSelector.CODE_NOT_IN_MATRIX,
            (selection as KsuKmiSelection.Missing).code,
        )
    }

    @Test
    fun selectorNeverAssumesFullCatalogWhenUnknown() {
        // null = 设备事实未上报：既不能 Ready，也不能 Missing（不等于"全都没有"）。
        val selection = KsuKmiSelector.select("android15-6.6", null)
        assertTrue(selection is KsuKmiSelection.Unknown)
        assertEquals("android15-6.6_kernelsu.ko", (selection as KsuKmiSelection.Unknown).artifactName)
    }

    @Test
    fun selectorRejectsEmptyKmi() {
        listOf(null, "", "   ").forEach { kmi ->
            val selection = KsuKmiSelector.select(kmi, KsuKmiMatrix.KMIS)
            assertTrue("expected Missing for '$kmi'", selection is KsuKmiSelection.Missing)
            assertEquals(
                KsuKmiSelector.CODE_NOT_IN_MATRIX,
                (selection as KsuKmiSelection.Missing).code,
            )
        }
    }

    // ------------------------------------------------------------------ payload cross-check

    @Test
    fun ultraCompanionsKeepTheirIndependentSixKmis() {
        val payload = File(KsuTestPaths.kernelsuRoot(), "ksu-payload.json")
        val artifacts = json.parseToJsonElement(payload.readText()).jsonObject["artifacts"]!!
            .jsonArray.map { it.jsonObject }
        val companions = artifacts.filter { it["kind"]!!.jsonPrimitive.content == "compatibility-lkm" }
        assertEquals(listOf("android12-5.10", "android13-5.15", "android14-6.1", "android15-6.6",
            "android16-6.12", "android17-6.18"), companions.map { it["kmi"]!!.jsonPrimitive.content })
        companions.forEach { entry ->
            val kmi = entry["kmi"]!!.jsonPrimitive.content
            assertEquals("${kmi}_maplesu_vr.ko", entry["name"]!!.jsonPrimitive.content)
            assertEquals("present", entry["status"]!!.jsonPrimitive.content)
            val module = File(KsuTestPaths.repoRoot(), entry["path"]!!.jsonPrimitive.content)
            assertTrue("missing Ultra companion: $kmi", module.isFile)
            assertEquals(entry["size"]!!.jsonPrimitive.content.toLong(), module.length())
        }
    }

    @Test
    fun payloadCarriesExactlyOneLkmEntryPerMatrixKmi() {
        val payloadFile = File(KsuTestPaths.kernelsuRoot(), "ksu-payload.json")
        assertTrue("ksu-payload.json not generated (run gen_payload.py)", payloadFile.isFile)
        val artifacts = json.parseToJsonElement(payloadFile.readText()).jsonObject["artifacts"]!!
            .jsonArray.map { it.jsonObject }
        val lkm = artifacts.filter { it["kind"]!!.jsonPrimitive.content == "lkm" }
        assertEquals(
            "payload lkm entries must follow ksu_common.KMI_MATRIX order",
            KsuKmiMatrix.KMIS,
            lkm.map { it["kmi"]!!.jsonPrimitive.content },
        )
        lkm.forEach { entry ->
            val kmi = entry["kmi"]!!.jsonPrimitive.content
            val name = KsuKmiMatrix.artifactName(kmi)
            assertEquals(name, entry["name"]!!.jsonPrimitive.content)
            assertEquals(
                "third_party/kernelsu/lkm/$name",
                entry["path"]!!.jsonPrimitive.content,
            )
            val status = entry["status"]!!.jsonPrimitive.content
            if (status == "present") {
                assertTrue(
                    "present lkm entry must carry builtBy: $name",
                    (entry["builtBy"]?.jsonPrimitive?.content ?: "").isNotBlank(),
                )
                // present 的条目必须有真实文件（lkm/ 是生成物，登记过就该在）。
                val ko = File(KsuTestPaths.repoRoot(), entry["path"]!!.jsonPrimitive.content)
                assertTrue("present artifact file missing: ${ko.path}", ko.isFile)
                assertEquals(
                    "size mismatch for $name",
                    entry["size"]!!.jsonPrimitive.content.toLong(),
                    ko.length(),
                )
            } else {
                assertEquals("pending-ci", status)
                assertFalse("pending-ci must not carry sha256: $name", entry.containsKey("sha256"))
            }
        }
    }
}
