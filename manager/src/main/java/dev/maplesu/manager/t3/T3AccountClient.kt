package dev.maplesu.manager.t3

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

internal enum class T3Operation { REGISTER, LOGIN, HEARTBEAT, UPDATE_CORE, NOTICE }

internal data class T3Response(val code: Int, val message: String = "", val statecode: String? = null) {
    override fun toString(): String = "T3Response(code=$code, statecode=<redacted>)"
}

internal fun interface T3Transport {
    fun call(operation: T3Operation, parameters: Map<String, String>): T3Response?
}

internal data class T3Session(val account: String, val identity: String, val statecode: String) {
    override fun toString(): String = "T3Session(<redacted>)"
}

internal data class T3AccountIdentity(val account: String, val identity: String) {
    override fun toString(): String = "T3AccountIdentity(<redacted>)"
}

internal interface T3AccountStore {
    fun read(): T3Session?
    fun write(session: T3Session)
    fun readIdentity(): T3AccountIdentity? = read()?.let { T3AccountIdentity(it.account, it.identity) }
    fun writeIdentity(identity: T3AccountIdentity) {}
    fun readNotice(): String? = null
    fun writeNotice(notice: String) {}
}

/** Blocking account work; the foreground controller always calls this on its IO dispatcher. */
internal class T3AccountClient(
    private val transport: T3Transport,
    private val store: T3AccountStore,
    private val identityProvider: () -> String?,
    private val coreProvider: () -> String,
) {
    private val mutableDisabledMessage = MutableStateFlow<String?>(null)
    val disabledMessage: StateFlow<String?> = mutableDisabledMessage.asStateFlow()
    private val mutableNotice = MutableStateFlow(runCatching { store.readNotice() }.getOrNull()?.takeIf(String::isNotBlank))
    val notice: StateFlow<String?> = mutableNotice.asStateFlow()
    private var uploadedCore: Pair<String, String>? = null
    private var selectedIdentity: T3AccountIdentity? = null

    @Synchronized
    fun synchronize() {
        if (mutableDisabledMessage.value != null) return
        synchronizeAccount()
        if (mutableDisabledMessage.value == null) refreshNotice()
    }

    private fun synchronizeAccount() {
        val cached = runCatching { store.read() }.getOrNull()
        if (cached != null) {
            val response = request(T3Operation.HEARTBEAT, credentials(cached.account) +
                ("statecode" to cached.statecode)) ?: return
            if (applyDisabled(response)) return
            if (response.code == 200) {
                updateCore(cached.account)
                return
            }
            if (!isSessionExpired(response.message) && !isAccountMissing(response.message)) return
            login(cached.account, cached.identity, registerFirst = isAccountMissing(response.message))
            return
        }
        val selected = selectedIdentity ?: (
            runCatching { store.readIdentity() }.getOrNull()
                ?: runCatching(identityProvider).getOrNull()?.takeIf(String::isNotBlank)
                    ?.let { T3AccountIdentity(it.take(20), it) }
            )?.also {
                selectedIdentity = it
                runCatching { store.writeIdentity(it) }
            } ?: return
        login(selected.account, selected.identity)
    }

    private fun login(account: String, identity: String, registerFirst: Boolean = false) {
        if (registerFirst && !register(account)) return
        var response = request(T3Operation.LOGIN, credentials(account) + ("imei" to identity)) ?: return
        if (applyDisabled(response)) return
        if (!registerFirst && isAccountMissing(response.message) && response.code != 200) {
            if (!register(account)) return
            response = request(T3Operation.LOGIN, credentials(account) + ("imei" to identity)) ?: return
            if (applyDisabled(response)) return
        }
        if (response.code != 200) return
        val statecode = response.statecode?.takeIf(String::isNotBlank) ?: return
        runCatching { store.write(T3Session(account, identity, statecode)) }
        updateCore(account)
    }

    private fun register(account: String): Boolean {
        val response = request(T3Operation.REGISTER, credentials(account) +
            ("email" to "$account@maplesu.app")) ?: return false
        if (applyDisabled(response)) return false
        return response.code == 200 || isAlreadyRegistered(response.message)
    }

    private fun updateCore(account: String) {
        val core = runCatching(coreProvider).getOrNull()?.takeIf(String::isNotBlank) ?: return
        if (uploadedCore == (account to core)) return
        val response = request(T3Operation.UPDATE_CORE, credentials(account) + ("core" to core)) ?: return
        if (applyDisabled(response)) return
        if (response.code == 200) uploadedCore = account to core
    }

    private fun refreshNotice() {
        val response = request(T3Operation.NOTICE, emptyMap()) ?: return
        if (applyDisabled(response) || response.code != 200) return
        val notice = response.message.trim()
        runCatching { store.writeNotice(notice) }
        mutableNotice.value = notice.takeIf(String::isNotBlank)
    }

    private fun request(operation: T3Operation, parameters: Map<String, String>): T3Response? {
        checkInterrupted()
        return try {
            transport.call(operation, parameters).also { checkInterrupted() }
        } catch (interrupted: InterruptedException) {
            Thread.currentThread().interrupt()
            throw interrupted
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            checkInterrupted()
            null
        }
    }

    private fun checkInterrupted() {
        if (Thread.currentThread().isInterrupted) throw InterruptedException("T3 synchronization cancelled")
    }

    private fun applyDisabled(response: T3Response): Boolean {
        if (response.code == 200 || !isProgramDisabled(response.message)) return false
        mutableDisabledMessage.value = response.message
        return true
    }

    private fun credentials(account: String) = mapOf("user" to account, "pass" to PASSWORD)

    companion object {
        const val PASSWORD = "MapleSULove520"

        fun isAccountMissing(message: String): Boolean =
            listOf("用户不存在", "账号不存在", "账户不存在", "用户名不存在", "用户未注册", "账号未注册")
                .any(message::contains)

        fun isAlreadyRegistered(message: String): Boolean =
            listOf("用户已存在", "账号已存在", "账户已存在", "用户名已存在", "用户已注册", "账号已注册")
                .any(message::contains)

        fun isSessionExpired(message: String): Boolean =
            listOf("状态码不可为空", "状态码不存在", "状态码失效", "状态码已过期", "登录状态不存在",
                "登录状态失效", "登录状态已过期").any(message::contains)

        private val programDisabled = Regex(
            "^(?:(?:错误|提示)\\s*[:：]\\s*)?(?:当前|该|此)?(?:程序|版本)" +
                "(?:已被禁用|已经禁用|已禁用|被禁用|禁用|已被停用|已经停用|已停用|被停用|停用|未开启)" +
                "(?:[。.!！，,：:；;（(].*)?$"
        )

        fun isProgramDisabled(message: String): Boolean = programDisabled.matches(message.trim())
    }
}
