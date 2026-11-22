package com.maplesu.core.ui.util

import android.content.Context
import dev.maplesu.manager.BootCandidatePublisher
import dev.maplesu.manager.installer.InstallCandidateImage
import dev.maplesu.manager.ultrakernel.UltraKernelSpec
import java.io.File
import java.nio.file.Files
import java.nio.file.LinkOption

/**
 * 保存本次安装实际提交的 Normal / Ultra 候选，不扫描历史工作目录。
 * 导出前重新核对尺寸和事务使用的摘要；公共 Download 发布仍执行完整回读。
 */
internal object UltraKernelBootExport {
    fun hasVerifiedCandidate(candidate: InstallCandidateImage?): Boolean = verified(candidate) != null

    fun save(context: Context, candidate: InstallCandidateImage?): String {
        val (image, sha256) = verified(candidate)
            ?: throw IllegalStateException("ULTRA_KERNEL_EXPORT_NO_CANDIDATE")
        return BootCandidatePublisher.publish(context, image, sha256)
    }

    private fun verified(candidate: InstallCandidateImage?): Pair<File, String>? {
        if (candidate == null) return null
        return runCatching {
            val image = candidate.image
            if (candidate.size <= 0 || !Files.isRegularFile(image.toPath(), LinkOption.NOFOLLOW_LINKS) ||
                image.length() != candidate.size || UltraKernelSpec.sha256(image) != candidate.sha256) null
            else image to candidate.sha256
        }.getOrNull()
    }
}
