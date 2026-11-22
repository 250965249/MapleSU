package dev.maplesu.manager.litehidden

import dev.maplesu.manager.workmode.Hashes
import java.io.File
import java.nio.file.Files
import java.nio.file.StandardCopyOption

/**
 * 宿主 so 注入的**执行端**：以 root 身份由 `app_process` 启动（见 [ParasiteScripts.inject]）。
 *
 * 为什么需要它：`/data/app/**/lib/` 只有 root 能写，而 ELF `DT_NEEDED` 改写是纯 JVM 代码；
 * 让 root 直接跑 APK 里的这个类，比把 20KB 补丁字节用 base64 分片塞进 shell 命令更短、
 * 更可验证（同样的字节由同一份 [HiddenElf] 产生）。
 *
 * 每一步都可失败且**先写临时文件再原子换入**：宿主库要么是原件、要么是完整补丁，
 * 不存在半个 ELF；清单每完成一个文件就落盘一次，中途失败也能按清单/备份回滚。
 *
 * 只依赖 JDK：不加载 Android 框架、不读凭据、不访问网络。
 */
class HostSoPatchEngine(
    private val exec: (List<String>) -> Int = ::defaultExec,
    private val meta: (path: String, format: String) -> String? = ::defaultStat,
    private val emit: (String) -> Unit = { println(it) },
) {

    data class Report(val ok: Boolean, val code: String = "", val detail: String = "", val patched: Int = 0)

    fun run(args: Array<String>): Report {
        val options = parseOptions(args)
            ?: return fail("BAD_ARGS", "options")
        val libraryDir = options["libdir"].orEmpty()
        val backupDir = options["backup"].orEmpty()
        val loaderSource = options["loader-src"].orEmpty()
        val loaderName = options["loader-name"].orEmpty()
        val label = options["label"].orEmpty()
        val manifestPath = options["manifest"].orEmpty()
        val targets = ParasitePolicy.parseTargets(options["files"].orEmpty())
        if (!ParasitePolicy.isAbsolutePath(libraryDir) || !ParasitePolicy.isAbsolutePath(backupDir) ||
            !ParasitePolicy.isAbsolutePath(manifestPath)
        ) {
            return fail("BAD_ARGS", "paths")
        }
        if (!ParasitePolicy.isSafeLibName(loaderName)) return fail("BAD_ARGS", "loader-name")
        if (targets.isEmpty()) return fail("BAD_ARGS", "files")

        // 分批注入（ParasitePolicy.INJECT_CHUNK）：每次只带一部分 `--files`，清单必须**合并**
        // 前几批的条目，否则第 2 批会把第 1 批的恢复依据从清单里抹掉。
        val previous = HostManifestCodec.decode(
            runCatching { File(manifestPath).readText(Charsets.UTF_8) }.getOrNull(),
        )?.takeIf { it.libraryDir == libraryDir }?.files.orEmpty()
        val entries = mutableListOf<HostBackupFile>()
        fun mergedEntries(): List<HostBackupFile> =
            (previous + entries).distinctBy { it.name }.sortedBy { it.name }
        var mode = "755"
        var uid = -1
        var gid = -1

        for (name in targets) {
            val originalPath = "$backupDir/$name.orig"
            val original = runCatching { File(originalPath).readBytes() }.getOrNull()
                ?: return fail("PATCH_ORIGINAL_MISSING", name)
            val originalSha = Hashes.sha256(original)
            val inspection = HiddenElf.inspect(original)
            // 结构上无法安全注入的库（不是 ELF64 共享库 / 没有空闲 phdr / 无 dynamic 等）
            // **跳过而不是拖垮整次激活**：真实 App 有几十个 .so，只要有一个能加载 loader 即可；
            // 写入/元数据/回读这类真错误仍然致命。跳过项进清单外记录，回滚按 sha 跳过。
            if (inspection == null) {
                emit("${ParasiteMarkers.SKIP}name=$name code=${HiddenElf.Codes.NOT_ELF64_LE}")
                continue
            }
            if (!inspection.isSharedObject || !inspection.isAarch64) {
                emit("${ParasiteMarkers.SKIP}name=$name code=${HiddenElf.Codes.NOT_SHARED_OBJECT}")
                continue
            }
            val patched = when (val result = HiddenElf.addNeeded(original, loaderName)) {
                is ElfPatchResult.Failed -> {
                    val skip = result.code in SKIPPABLE
                    if (!skip) return fail(result.code, "$name:${result.detail}")
                    emit("${ParasiteMarkers.SKIP}name=$name code=${result.code}")
                    continue
                }
                is ElfPatchResult.Ok -> result
            }
            mode = meta(originalPath, "%a")?.trim().orEmpty().ifEmpty { mode }
            uid = meta(originalPath, "%u")?.trim()?.toIntOrNull() ?: uid
            gid = meta(originalPath, "%g")?.trim()?.toIntOrNull() ?: gid

            val temporary = "$libraryDir/$name.maplesu.new"
            if (!writeFile(temporary, patched.bytes)) return fail("PATCH_WRITE_FAILED", name)
            if (!applyMetadata(temporary, name, mode, uid, gid, label)) return fail("PATCH_METADATA_FAILED", name)
            if (!moveIntoPlace(temporary, "$libraryDir/$name")) return fail("PATCH_RENAME_FAILED", name)
            val installed = runCatching { File("$libraryDir/$name").readBytes() }.getOrNull()
                ?: return fail("PATCH_VERIFY_FAILED", name)
            if (Hashes.sha256(installed) != patched.sha256) return fail("PATCH_VERIFY_FAILED", name)

            entries += HostBackupFile(name, originalSha, patched.sha256, mode, uid.coerceAtLeast(0), gid.coerceAtLeast(0))
            emit(
                "${ParasiteMarkers.PATCHED}name=$name orig=$originalSha " +
                    "patched=${patched.sha256} inserted=${if (patched.inserted) 1 else 0}",
            )
            // 清单增量落盘：中途失败时回滚仍有 sha 级依据（并保留前几批的条目）。
            writeManifest(
                manifestPath,
                options["package"].orEmpty(),
                libraryDir,
                label,
                loaderName,
                options["loader-sha"].orEmpty(),
                mergedEntries(),
            )
        }

        if (mergedEntries().isEmpty()) {
            return fail("PATCH_NO_ELIGIBLE", "files=${targets.size}")
        }

        val loaderBytes = runCatching { File(loaderSource).readBytes() }.getOrNull()
            ?: return fail("PATCH_LOADER_MISSING", loaderSource)
        val loaderSha = Hashes.sha256(loaderBytes)
        val loaderTemp = "$libraryDir/$loaderName.maplesu.new"
        if (!writeFile(loaderTemp, loaderBytes)) return fail("PATCH_LOADER_WRITE_FAILED", loaderName)
        if (!applyMetadata(loaderTemp, loaderName, "755", uid, gid, label)) {
            return fail("PATCH_LOADER_METADATA_FAILED", loaderName)
        }
        if (!moveIntoPlace(loaderTemp, "$libraryDir/$loaderName")) return fail("PATCH_LOADER_RENAME_FAILED", loaderName)
        val installedLoader = runCatching { File("$libraryDir/$loaderName").readBytes() }.getOrNull()
            ?: return fail("PATCH_LOADER_VERIFY_FAILED", loaderName)
        if (Hashes.sha256(installedLoader) != loaderSha) return fail("PATCH_LOADER_VERIFY_FAILED", loaderName)
        emit("${ParasiteMarkers.LOADER}name=$loaderName sha=$loaderSha")

        if (!writeManifest(
                manifestPath,
                options["package"].orEmpty(),
                libraryDir,
                label,
                loaderName,
                loaderSha,
                mergedEntries(),
            )
        ) {
            return fail("PATCH_MANIFEST_FAILED", manifestPath)
        }
        chmod(manifestPath, "600")
        emit("${ParasiteMarkers.OK} files=${mergedEntries().size}")
        return Report(ok = true, patched = mergedEntries().size)
    }

    private fun parseOptions(args: Array<String>): Map<String, String>? {
        val options = mutableMapOf<String, String>()
        var index = 0
        while (index < args.size) {
            val key = args[index]
            if (!key.startsWith("--") || index + 1 >= args.size) return null
            options[key.substring(2)] = args[index + 1]
            index += 2
        }
        val required = listOf("libdir", "backup", "loader-src", "loader-name", "manifest", "package", "files")
        if (required.any { options[it].isNullOrBlank() }) return null
        return options
    }

    private fun writeFile(path: String, bytes: ByteArray): Boolean = runCatching {
        File(path).writeBytes(bytes)
        File(path).isFile && File(path).length() == bytes.size.toLong()
    }.getOrDefault(false)

    private fun moveIntoPlace(from: String, to: String): Boolean = runCatching {
        Files.move(File(from).toPath(), File(to).toPath(), StandardCopyOption.REPLACE_EXISTING)
        true
    }.getOrDefault(false)

    private fun applyMetadata(
        path: String,
        name: String,
        mode: String,
        uid: Int,
        gid: Int,
        label: String,
    ): Boolean {
        if (exec(listOf(CHMOD, mode, path)) != 0) return false
        if (uid >= 0 && gid >= 0 && exec(listOf(CHOWN, "$uid:$gid", path)) != 0) return false
        if (label.isNotBlank() && exec(listOf(CHCON, label, path)) != 0) return false
        return true
    }

    private fun chmod(path: String, mode: String) {
        exec(listOf(CHMOD, mode, path))
    }

    private fun writeManifest(
        path: String,
        packageName: String,
        libraryDir: String,
        label: String,
        loaderName: String,
        loaderSha: String,
        entries: List<HostBackupFile>,
    ): Boolean {
        val manifest = HostManifest(
            packageName = packageName.ifBlank { File(libraryDir).parentFile?.name.orEmpty() },
            libraryDir = libraryDir,
            label = label,
            loaderName = loaderName,
            loaderSha256 = loaderSha,
            files = entries,
        )
        return writeFile(path, HostManifestCodec.encode(manifest).toByteArray(Charsets.UTF_8))
    }

    private fun fail(code: String, detail: String): Report {
        emit("${ParasiteMarkers.FAIL} code=$code detail=$detail")
        return Report(ok = false, code = code, detail = detail)
    }

    companion object {
        // app_process 由 root 通道直接 exec，环境里不一定有可用的 PATH —— 一律用绝对路径。
        private const val CHMOD = "/system/bin/chmod"
        private const val CHOWN = "/system/bin/chown"
        private const val CHCON = "/system/bin/chcon"
        private const val STAT = "/system/bin/stat"

        /**
         * 「结构上不能注入」的失败码：跳过该库、继续处理其余目标（真实 App 有几十个 .so，
         * 只要有一个能加载 loader 就够）。写入/元数据/回读失败**不在**此列，仍然致命。
         */
        private val SKIPPABLE = setOf(
            HiddenElf.Codes.NOT_ELF64_LE,
            HiddenElf.Codes.NOT_SHARED_OBJECT,
            HiddenElf.Codes.TRUNCATED,
            HiddenElf.Codes.NO_DYNAMIC,
            HiddenElf.Codes.NO_STRTAB,
            HiddenElf.Codes.NO_SPARE_PHDR,
            HiddenElf.Codes.INVALID_NAME,
        )

        /** 默认元数据执行器：直接跑系统命令（本进程已是 root）。 */
        private fun defaultExec(command: List<String>): Int = runCatching {
            val process = ProcessBuilder(command).redirectErrorStream(true).start()
            process.inputStream.readBytes()
            process.waitFor()
        }.getOrDefault(-1)

        /** 默认 stat：`stat -c <format> <path>`。 */
        private fun defaultStat(path: String, format: String): String? = runCatching {
            val process = ProcessBuilder(STAT, "-c", format, path).redirectErrorStream(true).start()
            val out = process.inputStream.readBytes().toString(Charsets.UTF_8)
            if (process.waitFor() != 0) null else out.trim()
        }.getOrNull()
    }
}

/**
 * `app_process` 入口（root）：见 [HostSoPatchEngine]。
 * 失败以非 0 退出码结束 —— 调用方（root 通道）据此判定步骤失败。
 */
object HostSoPatchMain {
    @JvmStatic
    fun main(args: Array<String>) {
        val report = runCatching { HostSoPatchEngine().run(args) }
            .getOrElse { error ->
                HostSoPatchEngine.Report(
                    ok = false,
                    code = "PATCH_EXCEPTION",
                    detail = error.javaClass.simpleName,
                )
            }
        if (!report.ok) {
            // stdout（不是 stderr）：root 回执只转发 stdout 时，失败码/细节也不能丢。
            println("${ParasiteMarkers.FAIL} code=${report.code} detail=${report.detail}")
            kotlin.system.exitProcess(60)
        }
    }
}
