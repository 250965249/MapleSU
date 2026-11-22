// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.ksu

/**
 * `ksud debug info` 的**部署判定投影**（开发文档 T1「部署内容寻址 + 二进制自校验」）。
 *
 * 与 [KsuKernelInfo] 的分工：
 * - [KsuKernelInfo] 是**诊断**用的全字段投影，缺字段取 sentinel（`-1`/`0`）；
 * - 本类只回答「部署的这份 ksud 报出来的版本，能不能与 APK 内那份对齐」，
 *   因此在 `userspace_version` / `userspace_uapi_version` 缺失或不是数字时**返回 null**（不猜默认值）。
 *
 * 部署判定读取编译期 userspace_* 字段；version/uapi_version 是内核回执，不证明守护进程兼容：
 * ```
 * KernelSU version: 32650
 * userspace_version: 32650
 * userspace_uapi_version: 7
 * flags: 0x00000021
 * features: 0x0000001f
 * lkm: true
 * ```
 *
 * ⚠️ 只解析 `key: value` 行；`KernelSU version: 32650` 这种**带前缀**的行不算 `version`。
 */
data class KsuVersionInfo(
    val version: Int,
    val uapiVersion: Int,
    val isLkm: Boolean,
    val flags: Long,
) {
    /**
     * 部署侧「版本对」的判据（与 `KernelProof.usable` 同口径）：
     * `version > 0`（内核已认主，0 = 未接线）且 `uapi == 7`（本构建的契约）。
     *
     * 只比版本号不够：UAPI 代际不一致时 ksud 的所有 supercall 都会被内核拒绝
     * （开发文档 §2.1「F1 UAPI/句柄代际不一致」是头号根因）。
     */
    val matchesBuild: Boolean
        get() = version > 0 && uapiVersion == REQUIRED_UAPI_VERSION

    companion object {
        /** 本构建编译期 UAPI（`KsuUapiFreezeTest` 冻结为 7；`KERNEL_SU_UAPI_VERSION`）。 */
        const val REQUIRED_UAPI_VERSION = 7

        /**
         * 解析 `ksud debug info` 输出。
         *
         * 解析失败（空串/无 `userspace_version:`/无 `userspace_uapi_version:`/值非数字）→ `null`，**不抛**。
         * 缺 `lkm`/`flags` 不影响判定（取 `false`/`0`）——它们不是部署门禁。
         */
        fun parse(text: String): KsuVersionInfo? {
            if (text.isBlank()) return null
            fun field(name: String): String? = text.lineSequence()
                .map { it.trim() }
                .firstOrNull { it.startsWith("$name:") }
                ?.substringAfter(':')?.trim()

            // Kernel fields describe the running kernel, not the binary being deployed.
            val version = field("userspace_version")?.toIntOrNull() ?: return null
            val uapiVersion = field("userspace_uapi_version")?.toIntOrNull() ?: return null
            val flags = field("flags")?.let { raw ->
                if (raw.startsWith("0x", ignoreCase = true)) {
                    raw.substring(2).toLongOrNull(16)
                } else {
                    raw.toLongOrNull()
                }
            } ?: 0L
            return KsuVersionInfo(
                version = version,
                uapiVersion = uapiVersion,
                isLkm = field("lkm")?.equals("true", ignoreCase = true) == true,
                flags = flags,
            )
        }
    }
}
