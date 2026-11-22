// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.installer

import android.content.res.Resources
import android.util.Log
import com.maplesu.core.R

/**
 * 分派结论的用户可读文案（安装页 + 修补入口**共用**，避免两处各写一套字符串映射）。
 *
 * 放在本包而不是 UI 包：`com.maplesu.core.ui.util.installBoot`（修补入口）也要用同一份文案。
 * 纯逻辑仍在 `InstallTargetDispatch`；本文件只做 `blocker → string res` 的 1:1 翻译。
 */

/** 仅做 UI 文案投影：判据不变，机器码和原始 detail 只写日志。 */
fun installTargetBlockerMessage(
    resources: Resources,
    blocked: InstallTargetDecision.Blocked,
): String {
    val text = when (blocked.blocker) {
        InstallTargetBlocker.NORMAL_REQUIRES_IMAGE ->
            resources.getString(R.string.install_target_blocker_normal_requires_image)

        InstallTargetBlocker.NORMAL_DOWNLOAD_UNSUPPORTED ->
            resources.getString(R.string.install_target_blocker_normal_download)

        InstallTargetBlocker.PARTITION_FIXED ->
            resources.getString(
                R.string.install_target_blocker_partition_fixed,
                blocked.target.productName,
            )

        InstallTargetBlocker.PARTITION_UNSUPPORTED ->
            resources.getString(
                R.string.install_target_blocker_partition_unsupported,
                InstallPartition.ALLOWED.joinToString(", ") { it.wire },
            )

        InstallTargetBlocker.KMI_UNPARSEABLE ->
            resources.getString(R.string.install_target_blocker_kmi_unparseable)

        InstallTargetBlocker.KMI_NOT_IN_MATRIX ->
            resources.getString(R.string.install_target_blocker_kmi_not_in_matrix)

        InstallTargetBlocker.KMI_ARTIFACT_MISSING ->
            resources.getString(R.string.install_target_blocker_kmi_artifact_missing)

        InstallTargetBlocker.KMI_KERNEL_PLATFORM_MISMATCH ->
            resources.getString(R.string.install_target_blocker_kmi_mismatch)
    }
    Log.w("InstallTarget", "${blocked.code}: ${blocked.kmi.orEmpty()} ${blocked.detail}")
    return text
}

/**
 * 安装确认 / 事务记录里的「目标：…」行（用户点「下一步」后在刷写日志第一条就能看到）。
 *
 * Normal 额外带上选中的 KMI 与期望产物名；目录未上报时说明"由 ksud 内嵌查找硬失败兜底"
 * —— 用户能看出这次到底会走哪条路，而不是一句笼统的"开始安装"。
 */
fun installTargetBanner(
    resources: Resources,
    ready: InstallTargetDecision.Ready,
): String {
    val current = resources.getString(R.string.install_target_mode_current, ready.target.productName)
    return when (ready.path) {
        InstallPatchPath.ULTRA_ULTRA_KERNEL ->
            "$current · ${resources.getString(R.string.install_target_mode_ultra_summary)}"

        InstallPatchPath.NORMAL_KSU_LKM -> buildString {
            append(current)
            append(" · ")
            append(resources.getString(R.string.install_target_mode_normal_summary))
            append(" · ")
            // 分区是**用户选的那个**（`init_boot` 默认 / `boot` 可选），不是写死的常量。
            append(ready.partition ?: InstallPartitionPolicy.NORMAL_DEFAULT.wire)
            append(" · KMI=${ready.kmi}")
            append(" · ko=${ready.kmiArtifact}")
            if (!ready.kmiCatalogKnown) append(" (catalog=unknown)")
        }
    }
}
