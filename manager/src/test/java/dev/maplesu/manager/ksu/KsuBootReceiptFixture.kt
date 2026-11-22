// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.ksu

/**
 * T3 单测的公共 fixture：假探针 + 现场样本（**internal**，同包两个测试类共用）。
 *
 * 样本全部取自 T0 现场（`evidence/normal-ksu-parity-20261102/T0-verdict.md`），
 * 不用"理想值"，否则判据在真实形态下会误判（P8 的 `mountify` 就是这样被打回来的）。
 */
internal object KsuBootReceiptFixture {

    /** 本次开机时刻（测试固定值，所有判据相对它）。 */
    const val EPOCH = 1_700_000_000_000L

    /** "现在"（开机 1 小时后；只进证据文本，不参与判定）。 */
    const val NOW = EPOCH + 3_600_000L

    const val KERNEL_VERSION = 32650
    const val KERNEL_UAPI = 7

    /**
     * T0 §7 的真实形态：`mountify` 用 `overlay`/`mountify` 作挂载源，
     * 所以 `grep ' KSU ' /proc/mounts` 恒为 0，只有 lowerdir/upperdir 能证明挂上了。
     */
    const val MOUNTIFY_STYLE_MOUNT =
        "overlay /system overlay rw,lowerdir=/data/adb/modules/mountify/system:/system," +
            "upperdir=/data/adb/modules/mountify/work/upper,workdir=/data/adb/modules/" +
            "mountify/work 0 0"

    /** T0 §5 的真实 logcat 片段（含 `post-fs-data.d` 一次性脚本，必须被排除）。 */
    val LOGCAT_SAMPLE = """
        11-02 07:56:33.025 21442 21442 I KernelSU: ksud::module: exec /data/adb/modules/zygisksu/emulated-soft-reboot.sh
        11-02 07:56:33.126 21442 21442 I KernelSU: ksud::module: exec /data/adb/post-fs-data.d/auditpatch.sh
        11-02 07:56:33.413 21442 21442 I KernelSU: ksud::module: exec /data/adb/modules/playintegrityfix/post-fs-data.sh
        11-02 07:56:33.793 21442 21442 I KernelSU: ksud::module: exec /data/adb/modules/auditpatch/post-fs-data.sh
        11-02 07:56:33.797 21442 21442 I KernelSU: ksud::module: exec /data/adb/modules/MapleOwn/post-fs-data.sh
    """.trimIndent()
}

/**
 * 可编程假探针：默认**全绿**（与本 boot 健康设备一致），单测按需打破一条判据。
 *
 * [calls] 记录接口被调用的次数——"LITE 零探针"用它证明（不是靠"看起来没调用"）。
 */
internal class KsuBootReceiptFakeProbe : KsuBootReceiptProbe {

    var version: KsuVersionInfo? = KsuVersionInfo(
        version = KsuBootReceiptFixture.KERNEL_VERSION,
        uapiVersion = KsuBootReceiptFixture.KERNEL_UAPI,
        isLkm = true,
        flags = 5L,
    )

    val mtimes = mutableMapOf(
        KsuBootReceipt.LOG_CAT to KsuBootReceiptFixture.EPOCH + 1_000L,
        KsuBootReceipt.DMESG_LOG to KsuBootReceiptFixture.EPOCH + 1_000L,
        KsuBootReceipt.PREINIT_STATUS to KsuBootReceiptFixture.EPOCH + 1_000L,
    )

    val texts = mutableMapOf<String, String?>(KsuBootReceipt.PROC_MOUNTS to "")

    var executed: List<String>? = listOf("zygisksu")
    var modules: List<String>? = listOf("zygisksu")
    var enabled: List<String>? = listOf("zygisksu")
    var processes: List<String>? = listOf("21574 zn-daemon")
    var link: Boolean? = false
    var ksuMounts: Int? = 0
    var busybox: Boolean? = true
    var selfReport: String? = null
    var calls: Int = 0

    override fun statMtime(path: String): Long? {
        calls++
        return mtimes[path]
    }

    override fun readText(path: String): String? {
        calls++
        return texts[path]
    }

    override fun versionInfo(): KsuVersionInfo? {
        calls++
        return version
    }

    override fun moduleIds(): List<String>? {
        calls++
        return modules
    }

    override fun executedModuleIds(): List<String>? {
        calls++
        return executed
    }

    override fun processNames(): List<String>? {
        calls++
        return processes
    }

    override fun isSymlink(path: String): Boolean? {
        calls++
        return if (path == KsuBootReceipt.METAMODULE_POINTER) link else null
    }

    override fun ksuMountCount(): Int? {
        calls++
        return ksuMounts
    }

    override fun busyboxOk(): Boolean? {
        calls++
        return busybox
    }

    override fun enabledModuleIds(): List<String>? {
        calls++
        return enabled
    }

    override fun metamoduleSelfReport(): String? {
        calls++
        return selfReport
    }
}
