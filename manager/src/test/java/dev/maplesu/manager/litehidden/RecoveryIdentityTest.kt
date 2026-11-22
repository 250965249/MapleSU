package dev.maplesu.manager.litehidden

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 撤销授权所需的**身份材料**（真机 D1 的修法）：格式、严格解析、原子写脚本、权限回读。
 *
 * 安全边界由这些用例锁住：
 *  - 文件里**只有** androidId / package / uid，**没有** rootKey 明文、密文或 token；
 *  - 解析是严格整行白名单（坏文件 = 没有身份材料，不是「尽力解析」）；
 *  - 写入是 `tmp → chmod 600 → mv -f` 的原子三步，并且 `stat -c '%a %u'` 必须回读到 `600 0`，
 *    否则删掉文件并显式失败（不留宽权限文件）。
 */
class RecoveryIdentityTest {

    private val androidId = "0123456789abcdef"
    private val pkg = "dev.maplesu.manager"
    private val uid = 10_123

    private fun identity(androidId: String = this.androidId, pkg: String = this.pkg, uid: Int = this.uid) =
        requireNotNull(RecoveryIdentity.of(androidId, pkg, uid))

    // ── 格式 ──────────────────────────────────────────────────────────────

    @Test
    fun jsonRoundTripsThroughStrictParser() {
        val json = identity().toJson()
        assertEquals(
            "{\"v\":1,\"androidId\":\"$androidId\",\"package\":\"$pkg\",\"uid\":$uid}",
            json,
        )
        assertEquals(identity(), RecoveryIdentity.parse(json))
        // 末尾换行（printf 落盘的常见形态）要能容忍。
        assertEquals(identity(), RecoveryIdentity.parse("$json\n"))
    }

    @Test
    fun jsonContainsNoKeyOrTokenMaterial() {
        val json = identity().toJson()
        assertFalse("身份材料不能带 rootKey 字段", json.contains("rootkey", ignoreCase = true))
        assertFalse("身份材料不能带 key 字段", json.contains("\"key\""))
        assertFalse("身份材料不能带 token", json.contains("token"))
        assertTrue("只有三个字段", json.split(':').size == 5)
    }

    @Test
    fun parserRejectsAnythingButTheExactShape() {
        val good = identity().toJson()
        val bad = listOf(
            "",
            "   ",
            "null",
            "{}",
            good.replace("\"v\":1", "\"v\":2"),
            good.replace(",\"uid\":$uid", ""),
            good.replace("\"package\":\"$pkg\"", "\"package\":\"nope\""),
            good.replace(androidId, "zzzz-not-hex!"),
            good.replace(",\"uid\":$uid", ",\"uid\":9999999999"),
            good.replace("\"v\":1,", "\"extra\":1,\"v\":1,"),
            good.substring(0, good.length - 1),
            "$good$good",
        )
        bad.forEach { text ->
            assertNull("必须拒绝：$text", RecoveryIdentity.parse(text))
        }
    }

    @Test
    fun ofRejectsIncompleteOrInvalidMaterial() {
        assertNull(RecoveryIdentity.of(null, pkg, uid))
        assertNull(RecoveryIdentity.of("", pkg, uid))
        assertNull(RecoveryIdentity.of(androidId, null, uid))
        assertNull(RecoveryIdentity.of(androidId, "", uid))
        assertNull("没有 uid 的身份材料不能用来解密", RecoveryIdentity.of(androidId, pkg, null))
        assertNull(RecoveryIdentity.of(androidId, pkg, -1))
        assertNull(RecoveryIdentity.of(androidId, "no-dots", uid))
        assertEquals(identity(), RecoveryIdentity.of(" $androidId ", " $pkg ", uid))
    }

    @Test
    fun invalidIdentityHasNoJsonSoNothingIsWritten() {
        val broken = RecoveryIdentity("", "no-dots", -5)
        assertFalse(broken.isValid)
        assertEquals("", broken.toJson())
        val script = RecoveryIdentityScripts.write(broken)
        assertTrue("非法身份材料必须显式失败：$script", script.contains("IDENTITY_INVALID"))
        assertFalse("非法身份材料绝不能落盘", script.contains("printf"))
    }

    // ── 写入脚本（原子 + 0600 + 回读） ────────────────────────────────────

    @Test
    fun writeScriptIsAtomicAndRootOnly() {
        val script = RecoveryIdentityScripts.write(identity())
        val temp = ParasitePaths.IDENTITY_TEMP
        val target = ParasitePaths.IDENTITY_FILE

        assertTrue("必须先写临时文件", script.contains("'$temp'"))
        assertTrue("必须 chmod 600 临时文件", script.contains("chmod 600 '$temp'"))
        assertTrue("必须 mv -f 原子替换", script.contains("mv -f '$temp' '$target'"))
        assertTrue("必须回读权限", script.contains("stat -c '%a %u'"))
        assertTrue("必须要求 600 0（root:root）", script.contains("600 0"))
        assertTrue("权限不符必须删掉文件", script.contains("rm -f '$target'"))
        assertTrue("成功后打自证标记", script.contains(ParasiteMarkers.IDENTITY_OK))
        assertTrue("目录也要收紧到 0700", script.contains("chmod 700"))

        // 原子顺序：先写 tmp → 再 rename，不能反过来。
        val write = script.indexOf("printf %s")
        val rename = script.indexOf("mv -f")
        assertTrue("写入必须发生在 rename 之前", write in 1 until rename)

        // 只落身份材料：脚本里不许出现 rootkey / token 字样。
        assertFalse(script.contains("rootkey", ignoreCase = true))
        assertFalse(script.contains("token"))
        assertFalse(script.contains("BEGIN"))
    }

    @Test
    fun writeScriptCarriesTheExactJsonAndNoSecrets() {
        val script = RecoveryIdentityScripts.write(identity())
        val json = identity().toJson()
        assertTrue(script.contains(json))
        // 三个字段都是白名单字符集 → 单引号内无转义风险，也不会把 shell 语法带进去。
        assertFalse(json.contains("`"))
        assertFalse(json.contains("$("))
        assertFalse(json.contains("'"))
    }

    @Test
    fun removeScriptFailsWhenTheFileSurvives() {
        val script = RecoveryIdentityScripts.remove()
        assertTrue(script.contains("rm -f '${ParasitePaths.IDENTITY_FILE}'"))
        assertTrue("删完必须用文件事实复核", script.contains("[ -e '${ParasitePaths.IDENTITY_FILE}' ]"))
        assertTrue(script.contains("IDENTITY_DELETE_FAILED"))
        assertTrue(script.contains(ParasiteMarkers.IDENTITY_GONE))
    }

    @Test
    fun readScriptUsesTheSharedPathAndSwallowsErrors() {
        val script = RecoveryIdentityScripts.read()
        assertTrue(script.startsWith("cat "))
        assertTrue(script.contains(ParasitePaths.IDENTITY_FILE))
        assertTrue("读不到不能刷屏 stderr", script.contains("2>/dev/null"))
    }

    @Test
    fun identityPathIsUnderRecoveryNotUnderTheAppDataDirectory() {
        // 与 rootkey 同目录：普通卸载只清 App 数据目录，/data/adb 会留下（重装后仍能自救）。
        assertEquals("/data/adb/maplesu/recovery/identity.json", ParasitePaths.IDENTITY_FILE)
        assertTrue(ParasitePaths.IDENTITY_FILE.startsWith(ParasitePaths.RECOVERY))
        assertEquals("${ParasitePaths.IDENTITY_FILE}.tmp", ParasitePaths.IDENTITY_TEMP)
    }
}
