package dev.maplesu.manager.recovery

data class BootPersistenceEvidence(
    val proven: Boolean,
    val mechanism: String,
    val detail: String,
) {
    companion object {
        const val UNPROVEN_CODE = "BOOT_PERSISTENCE_UNPROVEN"

        val UNPROVEN = BootPersistenceEvidence(
            proven = false,
            mechanism = "none",
            detail = "Ultra /data/<key16>/init 未验证可承载 MapleSU 自定义 daemon；/data/adb 无启动钩子；未做重启恢复演练",
        )

        /**
         * 由真机探针提供证据：探针必须证明「重启后 daemon 自动可用」（例如重启后 ping 成功），
         * 仅证明"存在 /data/<key16>/init"或"文件可写"不算。
         */
        fun fromDeviceProbe(
            bootId: String,
            daemonPingAfterReboot: Boolean?,
        ): BootPersistenceEvidence = if (daemonPingAfterReboot == true) {
            BootPersistenceEvidence(
                proven = true,
                mechanism = "device-probe:reboot-ping",
                detail = "bootId=$bootId 重启后 daemon ping 成功",
            )
        } else {
            UNPROVEN.copy(detail = UNPROVEN.detail + "；bootId=$bootId 探针=${daemonPingAfterReboot ?: "unknown"}")
        }
    }
}
