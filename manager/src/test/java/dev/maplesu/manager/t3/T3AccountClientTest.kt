package dev.maplesu.manager.t3

import org.junit.Assert.*
import org.junit.Test

class T3AccountClientTest {
    private class Store(
        var session: T3Session? = null,
        var savedNotice: String? = null,
        var identity: T3AccountIdentity? = null,
    ) : T3AccountStore {
        override fun read() = session
        override fun write(session: T3Session) { this.session = session }
        override fun readIdentity() = session?.let { T3AccountIdentity(it.account, it.identity) } ?: identity
        override fun writeIdentity(identity: T3AccountIdentity) { this.identity = identity }
        override fun readNotice() = savedNotice
        override fun writeNotice(notice: String) { savedNotice = notice }
    }

    private class Transport : T3Transport {
        val calls = mutableListOf<Pair<T3Operation, Map<String, String>>>()
        var answer: (T3Operation) -> T3Response? = { operation ->
            if (operation == T3Operation.LOGIN) T3Response(200, statecode = "fresh-session") else T3Response(200)
        }
        override fun call(operation: T3Operation, parameters: Map<String, String>): T3Response? {
            calls += operation to parameters
            return answer(operation)
        }
    }

    @Test fun missingAccountRegistersOnceThenRestoresCachedSession() {
        val store = Store()
        val transport = Transport()
        var logins = 0
        transport.answer = { operation ->
            when {
                operation == T3Operation.LOGIN && logins++ == 0 -> T3Response(400, "用户不存在")
                operation == T3Operation.LOGIN -> T3Response(200, statecode = "fresh-session")
                else -> T3Response(200)
            }
        }
        val client = T3AccountClient(transport, store, { "device-id" }, { "kernel model" })
        client.synchronize()
        client.synchronize()
        assertEquals(T3Session("device-id", "device-id", "fresh-session"), store.session)
        assertEquals(listOf(T3Operation.LOGIN, T3Operation.REGISTER, T3Operation.LOGIN,
            T3Operation.UPDATE_CORE, T3Operation.NOTICE, T3Operation.HEARTBEAT, T3Operation.NOTICE),
            transport.calls.map { it.first })
        assertEquals("MapleSULove520", transport.calls.first().second["pass"])
        assertEquals(setOf("user", "pass", "core"),
            transport.calls.single { it.first == T3Operation.UPDATE_CORE }.second.keys)
    }

    @Test fun existingAccountLogsInWithoutRegistration() {
        val transport = Transport()
        T3AccountClient(transport, Store(), { "device-id" }, { "kernel model" }).synchronize()
        assertEquals(0, transport.calls.count { it.first == T3Operation.REGISTER })
        assertEquals(1, transport.calls.count { it.first == T3Operation.LOGIN })
    }

    @Test fun accountRespectsTwentyCharacterLimitWhileKeepingFullIdentity() {
        val transport = Transport()
        val store = Store()
        val identity = "1234567890abcdef1234567890abcdef"
        T3AccountClient(transport, store, { identity }, { "kernel model" }).synchronize()
        assertEquals(identity.take(20), store.session?.account)
        assertEquals(identity, store.session?.identity)
        assertEquals(identity, transport.calls.first().second["imei"])
        assertEquals(identity.take(20), transport.calls.first().second["user"])
    }

    @Test fun cachedAccountRetainsOriginalIdentityWithoutReadingNewDeviceId() {
        val store = Store(T3Session("original-account", "original-id", "old-session"))
        val transport = Transport()
        val client = T3AccountClient(transport, store, { error("cached identity wins") }, { "kernel model" })
        client.synchronize()
        assertEquals(T3Operation.HEARTBEAT, transport.calls.first().first)
        assertEquals("original-account", transport.calls.first().second["user"])
        assertEquals("old-session", store.session?.statecode)
    }

    @Test fun firstIdentitySurvivesFailedLoginAndLaterDrmRecoveryAcrossClientRestart() {
        val store = Store()
        val transport = Transport()
        var logins = 0
        var identityReads = 0
        var drmRecovered = false
        transport.answer = { operation ->
            when {
                operation == T3Operation.LOGIN && logins++ == 0 -> T3Response(400, "用户不存在")
                operation == T3Operation.LOGIN && logins == 2 -> T3Response(400, "网络超时")
                operation == T3Operation.LOGIN -> T3Response(200, statecode = "state")
                else -> T3Response(200)
            }
        }
        val identityProvider = {
            identityReads++
            if (drmRecovered) "widevine-identity" else "android-identity"
        }
        T3AccountClient(transport, store, identityProvider, { "kernel model" }).synchronize()
        assertNull(store.session)
        assertEquals(T3AccountIdentity("android-identity", "android-identity"), store.identity)
        drmRecovered = true
        T3AccountClient(transport, store, identityProvider, { "kernel model" }).synchronize()
        assertEquals(1, identityReads)
        assertEquals(T3Session("android-identity", "android-identity", "state"), store.session)
        assertEquals(1, transport.calls.count { it.first == T3Operation.REGISTER })
    }

    @Test fun savedIdentityWithoutUsableSessionLogsInWithoutReadingDeviceSignals() {
        val store = Store(identity = T3AccountIdentity("saved-account", "saved-id"))
        val transport = Transport()
        T3AccountClient(transport, store, { error("saved identity wins") }, { "kernel model" }).synchronize()
        assertEquals("saved-account", transport.calls.first().second["user"])
        assertEquals("saved-id", transport.calls.first().second["imei"])
        assertEquals(0, transport.calls.count { it.first == T3Operation.REGISTER })
    }

    @Test fun expiredSessionRelogsInWithoutRegistration() {
        val store = Store(T3Session("original-account", "original-id", "old-session"))
        val transport = Transport()
        val original = transport.answer
        transport.answer = { if (it == T3Operation.HEARTBEAT) T3Response(400, "状态码不存在") else original(it) }
        T3AccountClient(transport, store, { error("cached identity wins") }, { "kernel model" }).synchronize()
        assertEquals("fresh-session", store.session?.statecode)
        assertEquals("original-id", transport.calls.single { it.first == T3Operation.LOGIN }.second["imei"])
        assertEquals(0, transport.calls.count { it.first == T3Operation.REGISTER })
    }

    @Test fun concurrentRegistrationConflictStillLogsIn() {
        val transport = Transport()
        var logins = 0
        transport.answer = { operation ->
            when (operation) {
                T3Operation.LOGIN -> if (logins++ == 0) T3Response(400, "用户不存在")
                    else T3Response(200, statecode = "state")
                T3Operation.REGISTER -> T3Response(400, "用户名已存在")
                else -> T3Response(200)
            }
        }
        val store = Store()
        T3AccountClient(transport, store, { "identity" }, { "kernel model" }).synchronize()
        assertEquals("state", store.session?.statecode)
        assertEquals(2, logins)
    }

    @Test fun networkAndAccountFailuresKeepLocalFeaturesAndCachedSession() {
        for (message in listOf("接口未开启", "用户被禁用", "网络超时", "机器码不存在")) {
            val session = T3Session("account", "id", "session")
            val store = Store(session)
            val transport = Transport().apply { answer = { T3Response(400, message) } }
            val client = T3AccountClient(transport, store, { "id" }, { "kernel model" })
            client.synchronize()
            assertNull(message, client.disabledMessage.value)
            assertEquals(session, store.session)
            assertEquals(0, transport.calls.count { it.first == T3Operation.REGISTER })
        }
        val client = T3AccountClient(T3Transport { _, _ -> throw IllegalStateException("offline") },
            Store(), { "id" }, { "kernel model" })
        client.synchronize()
        assertNull(client.disabledMessage.value)
    }

    @Test fun explicitProgramDisableIsHandledForEveryOperation() {
        for (blockedOperation in T3Operation.entries) {
            val transport = Transport()
            var logins = 0
            transport.answer = { operation ->
                when {
                    operation == blockedOperation -> T3Response(400, "程序未开启")
                    operation == T3Operation.LOGIN && blockedOperation == T3Operation.REGISTER && logins++ == 0 ->
                        T3Response(400, "用户不存在")
                    operation == T3Operation.LOGIN -> T3Response(200, statecode = "state")
                    else -> T3Response(200)
                }
            }
            val session = if (blockedOperation == T3Operation.HEARTBEAT) T3Session("account", "id", "state") else null
            val client = T3AccountClient(transport, Store(session), { "id" }, { "kernel model" })
            client.synchronize()
            assertEquals(blockedOperation.name, "程序未开启", client.disabledMessage.value)
            if (blockedOperation != T3Operation.NOTICE) {
                assertFalse(blockedOperation.name, transport.calls.any { it.first == T3Operation.NOTICE })
            }
            val callsAfterDisable = transport.calls.size
            transport.answer = { T3Response(200, statecode = "state") }
            client.synchronize()
            assertEquals(blockedOperation.name, callsAfterDisable, transport.calls.size)
            assertEquals(blockedOperation.name, "程序未开启", client.disabledMessage.value)
        }
    }

    @Test fun noticeRetainsLastNonemptySuccessAcrossFailures() {
        val store = Store(savedNotice = "cached notice")
        val transport = Transport()
        var noticeResponse: T3Response? = T3Response(200, " new notice ")
        val original = transport.answer
        transport.answer = { if (it == T3Operation.NOTICE) noticeResponse else original(it) }
        val client = T3AccountClient(transport, store, { "id" }, { "kernel model" })
        assertEquals("cached notice", client.notice.value)
        client.synchronize()
        assertEquals("new notice", client.notice.value)
        assertEquals("new notice", store.savedNotice)
        for (response in listOf(null, T3Response(400, "接口未开启"))) {
            noticeResponse = response
            client.synchronize()
            assertEquals("new notice", client.notice.value)
        }
    }

    @Test fun successfulEmptyNoticeClearsFlowAndPersistentCache() {
        val store = Store(savedNotice = "old notice")
        val transport = Transport()
        val client = T3AccountClient(transport, store, { "id" }, { "kernel model" })
        client.synchronize()
        assertNull(client.notice.value)
        assertEquals("", store.savedNotice)
        assertNull(T3AccountClient(transport, store, { "id" }, { "kernel model" }).notice.value)
    }

    @Test fun changedCoreIsUploadedAndFailedUploadRetries() {
        val transport = Transport()
        var core = "kernel1 model"
        var coreResponse = T3Response(200)
        val original = transport.answer
        transport.answer = { if (it == T3Operation.UPDATE_CORE) coreResponse else original(it) }
        val client = T3AccountClient(transport, Store(), { "id" }, { core })
        client.synchronize()
        client.synchronize()
        core = "kernel2 model"
        coreResponse = T3Response(400, "offline")
        client.synchronize()
        coreResponse = T3Response(200)
        client.synchronize()
        client.synchronize()
        assertEquals(listOf("kernel1 model", "kernel2 model", "kernel2 model"),
            transport.calls.filter { it.first == T3Operation.UPDATE_CORE }.map { it.second["core"] })
    }

    @Test fun missingIdentitySkipsAccountCallsButStillFetchesNotice() {
        val transport = Transport()
        val store = Store()
        T3AccountClient(transport, store, { null }, { "kernel model" }).synchronize()
        assertEquals(listOf(T3Operation.NOTICE), transport.calls.map { it.first })
        assertNull(store.session)
    }

    @Test fun successfulLoginWithoutStatecodeDoesNotReplaceSession() {
        val store = Store()
        val transport = Transport().apply { answer = { T3Response(200) } }
        T3AccountClient(transport, store, { "id" }, { "kernel model" }).synchronize()
        assertNull(store.session)
        assertFalse(transport.calls.any { it.first == T3Operation.UPDATE_CORE })
    }

    @Test fun stateClassificationDoesNotConfuseAccountSessionAndProgram() {
        assertFalse(T3AccountClient.isAccountMissing("状态码不存在"))
        assertFalse(T3AccountClient.isProgramDisabled("用户被禁用"))
        assertFalse(T3AccountClient.isProgramDisabled("程序接口未开启"))
        assertTrue(T3AccountClient.isProgramDisabled("版本已禁用"))
        assertTrue(T3AccountClient.isProgramDisabled("程序未开启"))
    }

    @Test fun programDisableRequiresAnExplicitAffirmativeMessage() {
        for (message in listOf("程序禁用状态查询失败", "程序已禁用状态查询失败", "未检测到程序禁用",
            "程序未被禁用", "无法确认程序已禁用", "程序禁用检查失败", "当前程序未被禁用",
            "程序未开启接口", "程序接口未开启", "版本禁用状态查询失败")) {
            assertFalse(message, T3AccountClient.isProgramDisabled(message))
        }
        for (message in listOf("程序禁用", "程序已被禁用", "当前程序已禁用", "程序未开启",
            "提示：程序未开启，请联系管理员", "版本已停用：升级后再试", " 程序已禁用。 ")) {
            assertTrue(message, T3AccountClient.isProgramDisabled(message))
        }
    }
}
