package dev.maplesu.manager.litehidden

import dev.maplesu.manager.workmode.Hashes
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/**
 * 注入执行端（root `app_process` 里跑的那一段）的主机测试：
 * 补丁写入/原子换入/清单增量落盘/元数据失败即中止，全部用临时目录 + fake 元数据命令验证。
 */
class HostSoPatchEngineTest {

    @get:Rule
    val temp = TemporaryFolder()

    private val loaderName = ParasitePaths.LOADER_NAME

    // 夹具以 `<原名>.bin` 存放：AGP 的 processDebugUnitTestJavaRes 会把 .so/.class 后缀
    // 从 java resources 里过滤掉（MergeJavaResourceTask.excludedFileSuffixes），
    // 直接叫 libt2host.orig.so 的话运行期只会得到 null。字节不变，见同目录 README。
    private fun fixture(name: String): ByteArray = checkNotNull(
        javaClass.getResourceAsStream("/parasite/$name.bin"),
    ) { "missing fixture $name.bin" }.use { it.readBytes() }

    private class Harness(
        val libraryDir: File,
        val backupDir: File,
        val loaderSource: File,
        val manifest: File,
        val output: MutableList<String> = mutableListOf(),
    )

    private fun harness(files: List<String> = listOf("libt2host.so")): Harness {
        val libraryDir = temp.newFolder("lib")
        val backupDir = temp.newFolder("backup")
        val loaderSource = temp.newFile(loaderName).apply { writeBytes(ByteArray(512) { 3 }) }
        val manifest = File(temp.root, "host.manifest")
        files.forEach { name ->
            File(backupDir, "$name.orig").writeBytes(fixture("libt2host.orig.so"))
        }
        return Harness(libraryDir, backupDir, loaderSource, manifest)
    }

    private fun engine(
        harness: Harness,
        exec: (List<String>) -> Int = { 0 },
    ) = HostSoPatchEngine(
        exec = exec,
        meta = { _, format ->
            when (format) {
                "%a" -> "755"
                "%u" -> "1000"
                "%g" -> "1000"
                else -> null
            }
        },
        emit = { harness.output += it },
    )

    private fun args(harness: Harness, files: List<String>): Array<String> = arrayOf(
        "--libdir", harness.libraryDir.absolutePath,
        "--backup", harness.backupDir.absolutePath,
        "--loader-src", harness.loaderSource.absolutePath,
        "--loader-name", loaderName,
        "--label", "u:object_r:apk_data_file:s0",
        "--manifest", harness.manifest.absolutePath,
        "--package", "dev.maplesu.t2host",
        "--files", files.joinToString(":"),
    )

    // 1
    @Test
    fun patchesHostLibraryAndInstallsLoaderWithManifest() {
        val harness = harness()
        val report = engine(harness).run(args(harness, listOf("libt2host.so")))
        assertTrue(harness.output.joinToString("\n"), report.ok)
        assertTrue(harness.output.any { it.startsWith("PARASITE_PATCHED ") })
        assertTrue(harness.output.any { it.startsWith("PARASITE_LOADER ") })
        assertTrue(harness.output.any { it.startsWith("PARASITE_OK ") })

        val installed = File(harness.libraryDir, "libt2host.so")
        assertTrue(installed.isFile)
        val inspection = HiddenElf.inspect(installed.readBytes())
        assertTrue("宿主库里必须真的多出 loader 的 DT_NEEDED", inspection!!.needed.contains(loaderName))
        val loaderInstalled = File(harness.libraryDir, loaderName)
        assertTrue(loaderInstalled.isFile)
        assertEquals(Hashes.sha256(harness.loaderSource.readBytes()), Hashes.sha256(loaderInstalled.readBytes()))

        val manifest = HostManifestCodec.decode(harness.manifest.readText())
        assertTrue(manifest != null && manifest.isComplete)
        assertEquals("dev.maplesu.t2host", manifest!!.packageName)
        assertEquals(1, manifest.files.size)
        assertEquals(Hashes.sha256(installed.readBytes()), manifest.files[0].patchedSha256)
    }

    // 2
    @Test
    fun missingOriginalFailsWithoutTouchingTheLibraryDirectory() {
        val harness = harness()
        val report = engine(harness).run(args(harness, listOf("libmissing.so")))
        assertFalse(report.ok)
        assertEquals("PATCH_ORIGINAL_MISSING", report.code)
        assertTrue(harness.libraryDir.listFiles().orEmpty().isEmpty())
    }

    // 3
    @Test
    fun metadataFailureAbortsBeforeTheFileIsInstalled() {
        val harness = harness()
        val failing = engine(harness, exec = { command ->
            // 执行端用绝对路径（app_process 环境不保证 PATH），断言按结尾匹配。
            if (command.firstOrNull()?.endsWith("chcon") == true) 1 else 0
        })
        val report = failing.run(args(harness, listOf("libt2host.so")))
        assertFalse(report.ok)
        assertEquals("PATCH_METADATA_FAILED", report.code)
        assertFalse("元数据失败绝不能换入目标文件", File(harness.libraryDir, "libt2host.so").isFile)
    }

    // 4
    @Test
    fun nonElfOriginalIsRejected() {
        val harness = harness()
        File(harness.backupDir, "libbad.so.orig").writeBytes(ByteArray(64) { 1 })
        val report = engine(harness).run(args(harness, listOf("libbad.so")))
        assertFalse(report.ok)
        // 结构不支持 → 跳过该库；唯一目标被跳过 = 没有可注入的库 → 明确失败。
        assertEquals("PATCH_NO_ELIGIBLE", report.code)
        assertFalse("被跳过的库绝不能被换入", File(harness.libraryDir, "libbad.so").isFile)
    }

    // 5
    @Test
    fun missingLoaderSourceFailsAfterLibrariesWerePatched() {
        val harness = harness()
        harness.loaderSource.delete()
        val report = engine(harness).run(args(harness, listOf("libt2host.so")))
        assertFalse(report.ok)
        assertEquals("PATCH_LOADER_MISSING", report.code)
        // 库已换入（第一步成功），清单已增量落盘 → 回滚仍有依据。
        assertTrue(File(harness.libraryDir, "libt2host.so").isFile)
        assertTrue(harness.manifest.isFile)
    }

    // 6
    @Test
    fun chunkedRunsMergeTheManifestInsteadOfOverwritingPreviousEntries() {
        // 真机 48 个 .so → 分批注入；第二批绝不能把第一批的恢复依据从清单里抹掉。
        val harness = harness(listOf("liba.so", "libb.so"))
        assertTrue(engine(harness).run(args(harness, listOf("liba.so"))).ok)
        val first = HostManifestCodec.decode(harness.manifest.readText())
        assertEquals(listOf("liba.so"), first!!.files.map { it.name })
        assertTrue(engine(harness).run(args(harness, listOf("libb.so"))).ok)
        val merged = HostManifestCodec.decode(harness.manifest.readText())
        assertEquals(listOf("liba.so", "libb.so"), merged!!.files.map { it.name })
        assertTrue("合并后的清单仍要完整", merged.isComplete)
    }

    // 7
    @Test
    fun invalidArgumentsAreRejected() {
        val harness = harness()
        assertFalse(engine(harness).run(arrayOf("--libdir")).ok)
        assertFalse(engine(harness).run(arrayOf("--files", "x.so")).ok)
        val badLoader = args(harness, listOf("libt2host.so")).toMutableList()
        badLoader[badLoader.indexOf("--loader-name") + 1] = "../evil.so"
        assertEquals("BAD_ARGS", engine(harness).run(badLoader.toTypedArray()).code)
    }
}
