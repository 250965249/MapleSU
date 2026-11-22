// SPDX-License-Identifier: GPL-3.0-or-later
package dev.maplesu.manager.ksu

import java.io.File

/**
 * KSU 后端的装配点（集成轮的**唯一**入口）。
 *
 * 用途：门面（`com.maplesu.core.Natives` / `ui/util/KsuCli.kt`）与 `BackendRouter`
 * 在模式判定为 KSU 之后，从这里取后端实例；**LITE 路径不得调用**（R5：
 * 加载 native 只允许发生在 KSU 模式）。
 *
 * 每个 getter 都保证「可用则真实现、不可用则安全替身」，调用方不需要 try/catch；
 * 不可用原因写入 [KsuLog]（`ksu.unavailable: <component> reason=...`）。
 */
object KsuBackends {

    /** native 是否已加载（不代表已认主；认主看 `natives().isManager`）。 */
    fun nativeLoaded(): Boolean = KsuNativeLoader.ensureLoaded()

    fun nativeLoadError(): String? = KsuNativeLoader.lastError

    fun natives(): KsuNativesBackend = KsuNativesBackend.current()

    fun nativesUnavailable(reason: String): KsuNativesBackend =
        KsuNativesBackend.unavailable(reason)

    /** 生产入口：`nativeLibraryDir` 来自 `context.applicationInfo.nativeLibraryDir`。 */
    fun command(nativeLibraryDir: File): KsuCommandBackend =
        KsuCommandBackend.forApp(nativeLibraryDir)

    /**
     * 生产入口（**模块/设置/列表**）：部署后的 ksud。
     *
     * `ksud module install/enable/disable/uninstall/action`、`feature check/get/set/save`、
     * `debug info` 都必须在**已部署的** ksud 上、由 root shell 执行；APK 内的
     * `libksud_ksu.so` 只是 launcher（起 root shell 用），不是模块系统的 owner。
     */
    fun deployedCommand(
        daemonPath: String = KsuCommands.DEPLOYED_DAEMON,
        probe: KsuPathProbe = deployedProbe(),
    ): KsuCommandBackend = KsuCommandBackend.forDeployedDaemon(daemonPath, probe)

    /** 部署路径探针（root shell + 5s 缓存）；root shell 未装配时退回本地 File。 */
    fun deployedProbe(): KsuPathProbe =
        CachingKsuPathProbe(KsuRootShell.pathProbe(), ttlMs = 5_000L)

    fun commandUnavailable(reason: String): KsuCommandBackend =
        KsuCommandBackend.unavailable(reason)

    fun bootInfo(backend: KsuCommandBackend): KsuBootInfo = KsuBootInfo(backend)

    fun modules(backend: KsuCommandBackend): KsuModuleOps = KsuModuleOps(backend)

    fun superuser(natives: KsuNativesBackend = natives()): KsuSuperuserAdapter =
        if (natives.available) KsuSuperuserAdapterImpl(natives)
        else UnavailableKsuSuperuserAdapter("native unavailable")

    fun settingsFeature(backend: KsuCommandBackend): KsuSettingsFeature =
        if (backend.daemonExists()) KsuSettingsFeatureImpl(backend)
        else KsuSettingsFeatureImpl.unavailable("ksud missing")

    /**
     * 一次装配全部后端（供切到 KSU 模式时调用一次并缓存）。
     * 任一子后端不可用不影响其它子后端构造——它们各自降级。
     */
    fun wire(nativeLibraryDir: File): KsuBackendSet {
        val natives = natives()
        val command = command(nativeLibraryDir)
        return KsuBackendSet(
            natives = natives,
            command = command,
            bootInfo = bootInfo(command),
            modules = modules(command),
            superuser = superuser(natives),
            settingsFeature = settingsFeature(command),
        )
    }

    /**
     * **生产装配**（Normal 模式的唯一接线）：native + 部署后的 ksud 命令面 +
     * 模块操作 + 设置 feature + 超级用户。
     *
     * 与 [wire] 的区别只有一个但是决定性的：命令面指向 `/data/adb/ksud`
     * （由 `KsuBootstrap` 部署），不是 APK 里的 launcher。
     */
    fun wireDeployed(
        daemonPath: String = KsuCommands.DEPLOYED_DAEMON,
        probe: KsuPathProbe = deployedProbe(),
    ): KsuBackendSet {
        val natives = natives()
        val command = deployedCommand(daemonPath, probe)
        return KsuBackendSet(
            natives = natives,
            command = command,
            bootInfo = bootInfo(command),
            modules = modules(command),
            superuser = superuser(natives),
            settingsFeature = settingsFeature(command),
        )
    }

    /** 不可用装配（未判定模式 / B 内核在但用户态缺失时用）。 */
    fun wireUnavailable(reason: String): KsuBackendSet {
        val command = commandUnavailable(reason)
        return KsuBackendSet(
            natives = nativesUnavailable(reason),
            command = command,
            bootInfo = KsuBootInfo.unavailable(reason),
            modules = KsuModuleOps.unavailable(reason),
            superuser = UnavailableKsuSuperuserAdapter(reason),
            settingsFeature = KsuSettingsFeatureImpl.unavailable(reason),
        )
    }
}

/** 一组 KSU 后端；由 [KsuBackends.wire] 构造后缓存。 */
data class KsuBackendSet(
    val natives: KsuNativesBackend,
    val command: KsuCommandBackend,
    val bootInfo: KsuBootInfo,
    val modules: KsuModuleOps,
    val superuser: KsuSuperuserAdapter,
    val settingsFeature: KsuSettingsFeature,
) {
    /** 是否具备完整的 B 模式运行时（认主 + ksud 可执行）。 */
    fun isReady(): Boolean = natives.available && natives.isManager && command.daemonExists()
}
