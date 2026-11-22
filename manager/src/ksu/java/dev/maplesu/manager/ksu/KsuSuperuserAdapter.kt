// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.ksu

import com.maplesu.core.Natives.Profile
import java.io.File

/**
 * 只做「内核态授权」的读写。
 *
 * **枚举应用的包名列表不在这里**：那是 `IKsuInterface` 的职责，两种模式共用
 * （`SuperUserRepositoryImpl`）。本适配器只回答「内核是否允许某 uid 拿 root」。
 *
 * 约束：
 * - `available()` 必须为 true 才能写；未认主/kernel UAPI 不匹配时一切写返回 false；
 * - `getProfile` 返回 `allowSu=false` **不能**被当作「用户拒绝过」——可能是未认主时
 *   JNI 的默认 profile 分支（03 §3.9）；
 * - `setAllow` 必须回读当前 profile 再只改 `allowSu`，不得用默认值覆盖
 *   caps/context/rules（那会把用户的 per-app 配置抹掉）。
 */
interface KsuSuperuserAdapter {
    fun available(): Boolean
    fun count(): Int
    fun getProfile(packageName: String, uid: Int): Profile?
    fun setAllow(packageName: String, uid: Int, allow: Boolean): Boolean
    fun allowListFile(): File
}

/** 生产实现：内核态读写走 `KsuNatives` 安全调用层。 */
class KsuSuperuserAdapterImpl(
    private val natives: KsuNativesBackend,
    private val allowListPath: String = "/data/adb/ksu/.allowlist",
) : KsuSuperuserAdapter {

    override fun available(): Boolean = natives.available && natives.isManager

    override fun count(): Int = if (available()) natives.getSuperuserCount() else 0

    override fun getProfile(packageName: String, uid: Int): Profile? {
        if (!available()) return null
        return natives.getAppProfile(packageName, uid)
    }

    override fun setAllow(packageName: String, uid: Int, allow: Boolean): Boolean {
        if (!available()) {
            KsuLog.unavailable("KsuSuperuserAdapter", "not manager or native unavailable")
            return false
        }
        val current = natives.getAppProfile(packageName, uid) ?: return false
        if (current.name != packageName || current.currentUid != uid) return false
        if (current.allowSu == allow) return true
        // 只改 allowSu；其余字段（currentUid/uid/gid/groups/capabilities/context/rules/...）
        // 原样回写，避免用默认值覆盖 per-app 配置。
        val next = current.copy(allowSu = allow)
        val ok = natives.setAppProfile(next)
        if (!ok) KsuLog.record("set-allow-failed", "$packageName uid=$uid allow=$allow")
        return ok
    }

    override fun allowListFile(): File = File(allowListPath)
}

/**
 * 不可用替身：**不抛、不写、不伪造**。
 * 返回 false/0/null，并记录 `ksu.unavailable`（03 §3.9 的「不静默成功」）。
 */
class UnavailableKsuSuperuserAdapter(private val reason: String) : KsuSuperuserAdapter {
    init {
        KsuLog.unavailable("KsuSuperuserAdapter", reason)
    }

    override fun available(): Boolean = false
    override fun count(): Int = 0
    override fun getProfile(packageName: String, uid: Int): Profile? = null
    override fun setAllow(packageName: String, uid: Int, allow: Boolean): Boolean = false
    override fun allowListFile(): File = File("/data/adb/ksu/.allowlist")
}
