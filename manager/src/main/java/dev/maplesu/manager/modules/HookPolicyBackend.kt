package dev.maplesu.manager.modules

import android.content.Context
import android.system.Os
import android.system.OsConstants
import java.io.File
import java.io.FileOutputStream
import java.security.MessageDigest
import org.json.JSONObject

/** Bundled inventory is cached; each explicit load checks the live boot identity. */
internal object HookPolicyBackend {
    private const val MANIFEST = "maplesu-policy-hook.json"
    private const val ABI = 2
    data class Image(val asset: String, val sha256: String, val bytes: Long,
        val buildId: String, val release: String, val pageSize: Long)
    @Volatile private var inventory: List<Image>? = null

    internal fun parse(text: String): List<Image> {
        val document = JSONObject(text)
        require(document.getInt("schemaVersion") == 1 && document.getInt("controlAbi") == ABI)
        val images = document.getJSONArray("images")
        val parsed = (0 until images.length()).map { index ->
            val image = images.getJSONObject(index)
            Image(image.getString("asset"), image.getString("sha256"), image.getLong("bytes"),
                image.getString("buildId"), image.getString("kernelRelease"), image.getLong("pageSize"))
                .also {
                    require(it.asset.matches(Regex("maplesu/policy-hook/[a-zA-Z0-9._/-]+\\.ko")) &&
                        it.asset.split('/').none { part -> part == ".." } &&
                        it.sha256.matches(Regex("[0-9a-f]{64}")) && it.bytes in 64L..4_194_304L &&
                        it.buildId.matches(Regex("[0-9a-f]{32,128}")) && it.buildId.length % 2 == 0 &&
                        it.release.isNotBlank() && it.pageSize in setOf(4096L, 16384L, 65536L))
                }
        }
        require(parsed.map { it.buildId to it.pageSize }.distinct().size == parsed.size)
        return parsed
    }

    private fun images(context: Context): List<Image> = inventory ?: synchronized(this) {
        inventory ?: context.assets.open(MANIFEST).bufferedReader().use { parse(it.readText()) }
            .also { inventory = it }
    }

    /** This only advertises a candidate for an explicit attempt, never effective Hide. */
    fun canAttempt(context: Context): Boolean = runCatching {
        images(context).any { it.release == Os.uname().release && it.pageSize == Os.sysconf(OsConstants._SC_PAGESIZE) }
    }.getOrDefault(false)

    private fun command(context: Context, arguments: String): JSONObject {
        val tool = ModuleToolDeployment.policySource(context)
        val result = RootExecModuleScriptRunner.runHook(context, "${quote(tool.path)} $arguments")
        check(result.isSuccess) { "MODULE_POLICY_HOOK_LOAD:${result.code}:${result.err.take(256)}" }
        return JSONObject(result.out.trim())
    }

    @Synchronized
    fun ensure(context: Context) {
        val live = command(context, "hook-info")
        if (live.getBoolean("present")) return
        val selected = images(context).singleOrNull {
            it.buildId == live.getString("buildId") && it.pageSize == live.getLong("pageSize")
        } ?: error("MODULE_POLICY_HOOK_IMAGE_NOT_PACKAGED")
        val directory = File(context.filesDir, "policy-hook")
        check(directory.isDirectory || directory.mkdir()) { "MODULE_POLICY_HOOK_STAGE" }
        Os.chmod(directory.path, 448)
        val bytes = context.assets.open(selected.asset).use { it.readBytes() }
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
        check(bytes.size.toLong() == selected.bytes && digest == selected.sha256) { "MODULE_POLICY_HOOK_DIGEST" }
        val staged = File.createTempFile("backend-", ".ko", directory)
        try {
            FileOutputStream(staged).use { it.write(bytes); it.fd.sync() }
            Os.chmod(staged.path, 384)
            val result = command(context, "hook-load ${quote(staged.path)} ${quote(selected.buildId)}")
            check(result.getBoolean("loaded")) { "MODULE_POLICY_HOOK_LOAD_READBACK" }
        } finally { staged.delete() }
    }

    private fun quote(value: String): String = "'" + value.replace("'", "'\\''") + "'"
}
