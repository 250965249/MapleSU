package dev.maplesu.manager.liteweb.daemon

import dev.maplesu.manager.litehidden.RecoveryIdentity
import dev.maplesu.manager.liteweb.LiteWebUnhideCodes
import dev.maplesu.manager.runtime.ultra.UltraRecoveryKey
import dev.maplesu.manager.runtime.ultra.UltraBootSdkRecovery
import dev.maplesu.manager.runtime.ultra.UltraRuntimeClient
import java.io.File
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermissions
import java.util.zip.ZipFile

class UltraSdkSuAuthRevoke(
    private val shell: DaemonShell,
    private val recoveryRoot: String = "/data/adb/maplesu/recovery",
    private val managerPackage: String = "dev.maplesu.manager",
    loadSdk: (String) -> Boolean = UltraSdkLibrary::load,
) : DaemonSuAuthRevoke {
    private val access = DaemonUltraSdkAccess(shell, recoveryRoot, managerPackage, loadSdk)

    override fun revoke(hostPackage: String): DaemonRevokeResult {
        if (hostPackage.isEmpty()) {
            return DaemonRevokeResult(false, LiteWebUnhideCodes.SU_AUTH_REVOKE_FAILED, "host_missing")
        }
        val sdk = when (val opened = access.open()) {
            is DaemonUltraSdkResult.Ready -> opened
            is DaemonUltraSdkResult.Unavailable -> return DaemonRevokeResult(
                false,
                LiteWebUnhideCodes.SU_AUTH_BACKEND_UNAVAILABLE,
                opened.detail,
            )
        }
        return runCatching {
            val client = sdk.client
            if (sdk.source == "boot-session") {
                val revoked = DaemonBootSuperuserAuthority.production(shell, recoveryRoot, managerPackage, client)
                    ?.setAllowed(hostPackage, false) == true
                if (!revoked) return@runCatching DaemonRevokeResult(
                    false, LiteWebUnhideCodes.SU_AUTH_REVOKE_FAILED, "authority_sync_pending",
                )
            }
            // Historical/restored hosts may already be absent. Verify that fact before
            // issuing another removal, so retries do not depend on SDK delete semantics.
            val before = client.suAuthSnapshot()
            if (before.receipt.succeeded) {
                val absent = SuAuthReadbackPolicy.verify(hostPackage, before.packages,
                    before.receipt.array("packages") != null, before.count, sdk.source)
                if (absent.ok) return@runCatching absent
            }
            val removal = client.removeSuAuth(hostPackage)
            if (!removal.succeeded) {
                return@runCatching DaemonRevokeResult(
                    false,
                    LiteWebUnhideCodes.SU_AUTH_REVOKE_FAILED,
                    "sdk=${removal.sdkError}",
                )
            }
            val snapshot = client.suAuthSnapshot()
            if (!snapshot.receipt.succeeded) {
                return@runCatching DaemonRevokeResult(
                    false,
                    LiteWebUnhideCodes.SU_AUTH_REVOKE_FAILED,
                    "readback=${snapshot.receipt.sdkError}",
                )
            }
            // 回读判定单独成纯函数（[SuAuthReadbackPolicy]）：回执缺 packages 数组 / 宿主仍在列表里，
            // 都必须是**显式失败**，绝不能把「读不到」当「已撤销」（真机 D1 的假成功防线）。
            SuAuthReadbackPolicy.verify(
                hostPackage = hostPackage,
                packages = snapshot.packages,
                listReadable = snapshot.receipt.array("packages") != null,
                remaining = snapshot.count,
                source = sdk.source,
            )
        }.getOrElse {
            DaemonRevokeResult(false, LiteWebUnhideCodes.SU_AUTH_REVOKE_FAILED, it.javaClass.simpleName)
        }
    }
}

sealed interface DaemonUltraSdkResult {
    data class Ready(val client: UltraRuntimeClient, val source: String) : DaemonUltraSdkResult
    data class Unavailable(val code: String, val detail: String) : DaemonUltraSdkResult
}

/** Shared in-process SDK entry for runtime facts and superuser operations. No credential leaves it. */
class DaemonUltraSdkAccess(
    private val shell: DaemonShell,
    private val recoveryRoot: String = "/data/adb/maplesu/recovery",
    private val managerPackage: String = "dev.maplesu.manager",
    private val loadSdk: (String) -> Boolean = UltraSdkLibrary::load,
    private val bootId: () -> String? = {
        runCatching { File("/proc/sys/kernel/random/boot_id").readText().trim() }.getOrNull()
    },
) {
    @Volatile private var ready: DaemonUltraSdkResult.Ready? = null
    private var readyMaterial: String? = null

    @Synchronized
    fun open(): DaemonUltraSdkResult {
        val sessionFile = File(recoveryRoot, UltraBootSdkRecovery.FILE_NAME)
        if (Files.exists(sessionFile.toPath(), LinkOption.NOFOLLOW_LINKS)) return openBootSession(sessionFile)
        val material = runCatching { File(recoveryRoot, ROOT_KEY_NAME).readText(Charsets.UTF_8) }.getOrNull()
        val key = when (val resolved = readRootKey()) {
            is DaemonRecoveryKey.Outcome.Ok -> resolved
            is DaemonRecoveryKey.Outcome.Missing -> return invalidate(resolved.detail)
        }
        ready?.takeIf { readyMaterial == material }?.let { return it }
        val library = ensureSdkLibrary() ?: return unavailable("sdk_library_unavailable")
        if (!runCatching { loadSdk(library) }.getOrDefault(false)) return unavailable("sdk_library_not_loadable")
        return runCatching {
            DaemonUltraSdkResult.Ready(UltraRuntimeClient(rootKeyProvider = {
                key.key.takeIf {
                    !Files.exists(sessionFile.toPath(), LinkOption.NOFOLLOW_LINKS) &&
                        runCatching { File(recoveryRoot, ROOT_KEY_NAME).readText(Charsets.UTF_8) }.getOrNull() == material
                }
            }), key.source).also { ready = it; readyMaterial = material }
        }.getOrElse { unavailable("sdk_client_unavailable") }
    }

    /** An existing session file owns recovery. Expired/corrupt material never selects an old permanent key. */
    private fun openBootSession(file: File): DaemonUltraSdkResult {
        val material = readBootMaterial(file) ?: return invalidate("sdk_session_unreadable")
        val session = UltraBootSdkRecovery.open(material, bootId(), managerPackage)
            ?: return invalidate("sdk_session_expired_or_invalid")
        ready?.takeIf { readyMaterial == material }?.let { return it }
        val library = ensureSdkLibrary() ?: return invalidate("sdk_library_unavailable")
        if (!runCatching { loadSdk(library) }.getOrDefault(false)) return invalidate("sdk_library_not_loadable")
        val client = UltraRuntimeClient(rootKeyProvider = {
            session.key.takeIf { session.current(bootId()) && readBootMaterial(file) == material }
        })
        return DaemonUltraSdkResult.Ready(client, "boot-session").also { ready = it; readyMaterial = material }
    }

    private fun readBootMaterial(file: File): String? = runCatching {
        if (Files.isSymbolicLink(file.toPath()) || !file.isFile || file.length() !in 1..8192) return null
        val root = File(recoveryRoot)
        if (Files.isSymbolicLink(root.toPath())) return null
        val quote: (String) -> String = { "'" + it.replace("'", "'\\''") + "'" }
        val checked = shell.run("[ ! -L ${quote(root.absolutePath)} ] && " +
            "[ ! -L ${quote(file.absolutePath)} ] && " +
            "[ \"\$(stat -c '%a %u %g' ${quote(root.absolutePath)})\" = '700 0 0' ] && " +
            "[ \"\$(stat -c '%a %u %g' ${quote(file.absolutePath)})\" = '600 0 0' ] && echo SDK_SESSION_PRIVATE")
        if (checked.code != 0 || checked.output.trim() != "SDK_SESSION_PRIVATE") return null
        file.readText(Charsets.UTF_8).takeIf { it.length <= 8192 }
    }.getOrNull()

    private fun invalidate(detail: String): DaemonUltraSdkResult {
        ready = null
        readyMaterial = null
        return unavailable(detail)
    }

    private fun unavailable(detail: String): DaemonUltraSdkResult.Unavailable {
        System.err.println("MAPLESU_RECOVERY_UNAVAILABLE reason=$detail")
        return DaemonUltraSdkResult.Unavailable("SU_AUTH_BACKEND_UNAVAILABLE", detail)
    }

    /**
     * rootKey 备份 + 身份材料 → 明文 key（只在内存；解不开 → 结构化失败，不猜）。
     *
     * 身份来源顺序（真机 D1 的修法）：
     *  1. **App 激活时落盘的 `recovery/identity.json`**（App 作用域的 `Settings.Secure.ANDROID_ID`）；
     *  2. 读不到/格式不对才回退 `settings get secure android_id`（系统值，Android 8+ 与 App 作用域
     *     值不同，因此只对「老版本激活过、没写 identity」的现场有意义）。
     */
    private fun readRootKey(): DaemonRecoveryKey.Outcome {
        val payload = runCatching {
            File(recoveryRoot, ROOT_KEY_NAME).readText(Charsets.UTF_8)
        }.getOrNull()
        return DaemonRecoveryKey.resolve(
            payload = payload,
            identity = readIdentity(),
            systemAndroidId = readAndroidId(),
            managerPackage = managerPackage,
        )
    }

    /** 读 App 激活时落盘的身份材料（0600 root-only）；读不到/格式不合规 → null（触发回退）。 */
    private fun readIdentity(): RecoveryIdentity? = runCatching {
        RecoveryIdentity.parse(File(recoveryRoot, IDENTITY_NAME).readText(Charsets.UTF_8))
    }.getOrNull()

    private fun readAndroidId(): String? {
        val result = runCatching { shell.run("/system/bin/settings get secure android_id 2>/dev/null") }
            .getOrNull() ?: return null
        if (result.code != 0) return null
        return result.output.trim()
            .takeIf { it.isNotEmpty() && it != "null" && it.length <= 64 && it.all { c -> c.isLetterOrDigit() } }
    }

    internal fun ensureSdkLibrary(classpathApks: List<String> = currentClasspathApks()): String? {
        val dir = File(recoveryRoot, "native")
        val target = File(dir, SDK_LIBRARY)
        val apk = File(recoveryRoot, APK_NAME)
        val candidates = (classpathApks.mapNotNull { path ->
            File(path).takeIf { it.isAbsolute && it.extension == "apk" && it.isFile && it.canRead() }
        } + listOfNotNull(apk.takeIf { it.isFile && it.canRead() })).distinctBy { it.absolutePath }
        // Legacy recovery may have retained only its extracted SDK. An available APK
        // is authoritative: extraction failure must never silently select that cache.
        if (candidates.isEmpty()) return target.takeIf { it.isFile && it.length() > 0 }?.absolutePath
        for (candidate in candidates) {
            extractSdkLibrary(candidate, dir, target)?.let { return it }
        }
        return null
    }

    private fun currentClasspathApks(): List<String> = buildList {
        DaemonClasspathApk.path()?.let { add(it) }
        addAll(System.getProperty("java.class.path").orEmpty().split(File.pathSeparatorChar))
        addAll(System.getenv("CLASSPATH").orEmpty().split(File.pathSeparatorChar))
    }

    private fun extractSdkLibrary(apk: File, dir: File, target: File): String? {
        if (!apk.isFile || !apk.canRead()) return null
        return runCatching {
            ZipFile(apk).use { zip ->
                val entries = zip.entries().asSequence()
                    .filter {
                        val name = it.name.substringAfterLast('/')
                        !it.isDirectory && it.name == "$LIB_PREFIX$name" && name.endsWith(".so")
                    }
                    // The manager also packages large patch/policy/provider libraries. They must
                    // never consume the extraction budget before the recovery SDK itself.
                    .sortedByDescending { it.name == "$LIB_PREFIX$SDK_LIBRARY" }
                    .toList()
                val sdk = entries.firstOrNull { it.name == "$LIB_PREFIX$SDK_LIBRARY" } ?: return null
                if (sdk.size <= 0 || sdk.size > MAX_LIB_BYTES) return null
                if (!dir.isDirectory && !dir.mkdirs() && !dir.isDirectory) return null
                var total = 0L
                var sdkExtracted = false
                for (entry in entries) {
                    val name = entry.name.substringAfterLast('/')
                    if (name.isEmpty() || name.contains("..") || name.contains('/')) continue
                    val size = entry.size
                    if (size <= 0 || size > MAX_LIB_BYTES) continue
                    if (total + size > MAX_TOTAL_LIB_BYTES) continue
                    val out = File(dir, name)
                    val temp = File(dir, "$name.tmp")
                    try {
                        zip.getInputStream(entry).use { input ->
                            temp.outputStream().use { output ->
                                val buffer = ByteArray(16 * 1024)
                                var copied = 0L
                                while (true) {
                                    val read = input.read(buffer)
                                    if (read < 0) break
                                    copied += read
                                    check(copied <= size) { "sdk_library_size_mismatch" }
                                    output.write(buffer, 0, read)
                                }
                                check(copied == size) { "sdk_library_size_mismatch" }
                            }
                        }
                        Files.move(temp.toPath(), out.toPath(),
                            StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
                    } finally {
                        temp.delete()
                    }
                    total += size
                    if (name == SDK_LIBRARY) sdkExtracted = true
                    runCatching {
                        Files.setPosixFilePermissions(
                            out.toPath(),
                            PosixFilePermissions.fromString("rwx------"),
                        )
                    }
                }
                target.takeIf { sdkExtracted && it.isFile && it.length() > 0 }?.absolutePath
            }
        }.getOrNull()
    }

    private companion object {
        /** 管理器包名（`UltraRecoveryKey` 的 KDF 用它；改包名需要同步迁移备份）。 */
        const val APK_NAME = "manager.apk"
        const val ROOT_KEY_NAME = "rootkey"
        const val IDENTITY_NAME = "identity.json"
        const val SDK_LIBRARY = "libmaplesu_ultra_bridge.so"
        const val LIB_PREFIX = "lib/arm64-v8a/"
        const val MAX_LIB_BYTES: Long = 16L * 1024 * 1024
        const val MAX_TOTAL_LIB_BYTES: Long = 48L * 1024 * 1024
    }
}

object UltraSdkLibrary {
    private const val BRIDGE_CLASS = "dev.maplesu.manager.runtime.ultra.bridge.NativeBridge"

    fun load(absolutePath: String): Boolean {
        val library = File(absolutePath)
        if (!library.isAbsolute || !library.isFile) return false
        return runCatching {
            System.load(library.absolutePath)
            System.setProperty("maplesu.ultra.boot.library", library.absolutePath)
            Class.forName(BRIDGE_CLASS, true, UltraSdkLibrary::class.java.classLoader)
            true
        }.getOrDefault(false)
    }
}

/**
 * 从「rootkey 密文 + 身份材料」解出明文 key 的**纯逻辑**（不碰文件、不执行 shell，主机可测）。
 *
 * <p>为什么需要它：rootkey 的 AES-256-GCM 密钥 = `SHA-256("maplesu-ultra-recovery-v1|<androidId>|<pkg>")`，
 * 而 `<androidId>` 必须是 **App 作用域**的 `Settings.Secure.ANDROID_ID`。daemon 用
 * `settings get secure android_id` 只能拿到**系统值**（Android 8+ 两者不同）⇒ 永远解不开
 * （真机 D1：`rootkey_or_androidid_unavailable`）。因此顺序固定为：
 *
 *  1. `identity.json` 里的 `androidId`（App 落盘的身份材料）+ 管理器包名；
 *  2. 若 identity 里的包名与当前管理器包名不同，再用 identity 的包名试一次（改包名现场）；
 *  3. 前两步都失败才回退系统 androidId（与旧实现等价）。
 *
 * <p>失败一律返回 [Outcome.Missing]，detail 是**机器码**：不含 androidId、不含 key、不含密文。
 */
internal object DaemonRecoveryKey {

    const val SOURCE_IDENTITY = "identity"
    const val SOURCE_SYSTEM = "system"

    const val WHY_ROOTKEY_ABSENT = "rootkey_absent"
    const val WHY_ROOTKEY_NOT_OURS = "rootkey_not_ours"
    const val WHY_NO_ANDROID_ID = "androidid_unavailable"
    const val WHY_UNDECRYPTABLE = "rootkey_undecryptable"

    sealed interface Outcome {
        data class Ok(val key: String, val source: String) : Outcome

        data class Missing(val detail: String) : Outcome
    }

    fun resolve(
        payload: String?,
        identity: RecoveryIdentity?,
        systemAndroidId: String?,
        managerPackage: String,
    ): Outcome {
        if (payload.isNullOrBlank()) return Outcome.Missing(WHY_ROOTKEY_ABSENT)
        // 「存在但不是我们的格式」与「解不开」必须分开：前者是文件被换/被截断，后者是身份不符。
        if (!UltraRecoveryKey.looksLikeRecoveryPayload(payload)) return Outcome.Missing(WHY_ROOTKEY_NOT_OURS)

        val system = systemAndroidId?.trim()?.takeIf { it.isNotEmpty() }
        val candidates = ArrayList<Pair<String, String>>(3)
        if (identity != null) {
            candidates += identity.androidId to managerPackage
            if (identity.packageName != managerPackage) {
                candidates += identity.androidId to identity.packageName
            }
        }
        if (system != null) candidates += system to managerPackage

        for ((androidId, packageName) in candidates.distinct()) {
            val key = runCatching { UltraRecoveryKey.open(payload, androidId, packageName) }.getOrNull()
            if (key != null) {
                val source = if (identity != null && androidId == identity.androidId) {
                    SOURCE_IDENTITY
                } else {
                    SOURCE_SYSTEM
                }
                return Outcome.Ok(key, source)
            }
        }
        if (candidates.isEmpty()) return Outcome.Missing(WHY_NO_ANDROID_ID)
        // identity / system 各自「有没有」要能在真机上区分（不打印值本身）。
        return Outcome.Missing(
            "$WHY_UNDECRYPTABLE;identity=${if (identity != null) 1 else 0};system=${if (system != null) 1 else 0}",
        )
    }
}

/**
 * 「撤销后回读」的判定（纯函数，主机可测）。
 *
 * <p>三条硬规则（任何一条不满足都**不得**返回成功）：
 *  1. 回执里必须有 `packages` 数组 —— 读不到列表 ≠ 已撤销；
 *  2. 宿主包名**不得**再出现在列表里；
 *  3. 成功回执的 detail 只带 `sdk=ok;remaining=<n>;id=<identity|system>`（不含 key/包名清单）。
 */
internal object SuAuthReadbackPolicy {

    const val READBACK_UNPARSABLE = "readback_unparsable"

    fun verify(
        hostPackage: String,
        packages: List<String>?,
        listReadable: Boolean,
        remaining: Int,
        source: String,
    ): DaemonRevokeResult {
        if (!listReadable || packages == null) {
            return DaemonRevokeResult(false, LiteWebUnhideCodes.SU_AUTH_REVOKE_FAILED, READBACK_UNPARSABLE)
        }
        if (packages.any { it == hostPackage }) {
            return DaemonRevokeResult(
                false,
                LiteWebUnhideCodes.SU_AUTH_REVOKE_FAILED,
                "still_listed;count=$remaining",
            )
        }
        return DaemonRevokeResult(true, detail = "sdk=ok;remaining=$remaining;id=$source")
    }
}

/** daemon 内的 root 执行（生产实现；测试用 [DaemonShell] 的 fake）。 */
object DaemonRuntimeShell : DaemonShell {
    override fun run(script: String): DaemonShellResult = RuntimeRecoveryCommandRunner.run(script).let {
        DaemonShellResult(it.code, it.output)
    }
}
