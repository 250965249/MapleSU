package dev.maplesu.manager.workmode.detect.probes

import dev.maplesu.manager.ksu.KsuBackends
import dev.maplesu.manager.workmode.detect.KsuFacts
import dev.maplesu.manager.workmode.detect.KsuKernelProbe

/**
 * KSU 内核探针适配器（取值来源为同树 JNI `KsuNatives` 与后端门面）。
 *
 * 接线（W04b）：`manager/src/ksu/java/.../KsuNatives.kt`（main sourceSet，见
 * `manager/build.gradle.kts:61`）。**只走安全调用层** [KsuBackends.natives]：
 * native 未加载 / 符号缺失 / 结构失败 → `available=false`，抛出固定探针异常，
 * 由探测器保留 S1/S2 unknown；不把映射默认值写成"没有 KSU"。
 *
 * 映射是纯函数 [KsuProbeMapping]（主机可测）；真机路径只负责取一次快照。
 */
object KsuKernelProbeAdapter : KsuKernelProbe {
    override fun probe(): KsuFacts {
        val snapshot = currentSnapshot()
        check(snapshot.available) { "KSU_PROBE_UNAVAILABLE" }
        return KsuProbeMapping.from(snapshot)
    }

    /** 一次 native 只读快照；任何异常 → unavailable（unknown）。 */
    internal fun currentSnapshot(): KsuNativeSnapshot = runCatching {
        val natives = KsuBackends.natives()
        KsuNativeSnapshot(
            available = natives.available,
            version = natives.version,
            kernelUapi = natives.kernelUAPIVersion,
            isManager = natives.isManager,
            isLkm = natives.isLkmMode,
        )
    }.getOrDefault(KsuNativeSnapshot.UNAVAILABLE)
}

/** native 侧只读快照（与 libsu/JNI 解耦，便于主机测试）。 */
data class KsuNativeSnapshot(
    val available: Boolean,
    val version: Int,
    val kernelUapi: Int,
    val isManager: Boolean,
    val isLkm: Boolean,
) {
    companion object {
        val UNAVAILABLE = KsuNativeSnapshot(
            available = false,
            version = -1,
            kernelUapi = -1,
            isManager = false,
            isLkm = false,
        )
    }
}

/**
 * 快照 → [KsuFacts] 的**纯映射**：
 * - native 不可用 → 全 unknown（`KsuFacts()` 默认值，version=-1）；
 * - 可用但版本 <= 0 → `responded=false`（内核未响应 supercall）；
 * - 可用且版本 > 0 → `responded=true`，uapi/isManager/isLkm 原样透传。
 */
object KsuProbeMapping {
    /** Match full detection: a responding foreign KSU kernel is not MapleSU_Normal. */
    fun normalStatus(snapshot: KsuNativeSnapshot): Boolean? {
        if (!snapshot.available) return null
        return snapshot.version > 0 && snapshot.isManager
    }

    fun from(snapshot: KsuNativeSnapshot): KsuFacts {
        if (!snapshot.available) return KsuFacts()
        return KsuFacts(
            responded = snapshot.version > 0,
            version = snapshot.version,
            uapi = snapshot.kernelUapi,
            isManager = snapshot.isManager,
            isLkm = snapshot.isLkm,
        )
    }
}
