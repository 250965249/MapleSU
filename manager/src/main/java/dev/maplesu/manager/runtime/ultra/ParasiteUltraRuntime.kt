package dev.maplesu.manager.runtime.ultra

import android.content.Context
import dev.maplesu.manager.runtime.ultra.bridge.NativeBridge
import dev.maplesu.manager.modules.UltraRootKeyStore
import dev.maplesu.manager.parasite.ParasiteNativeCall
import dev.maplesu.manager.parasite.ParasiteUltraApiAdapter
import dev.maplesu.manager.parasite.ParasiteSdkPort
import dev.maplesu.manager.parasite.UltraAvailability
import dev.maplesu.manager.parasite.UltraLinkedParasiteSdkPort
import dev.maplesu.manager.parasite.UnavailableParasiteSdkPort
import dev.maplesu.manager.parasite.selectProductionParasitePort
import dev.maplesu.manager.workmode.ModeRuntime
import dev.maplesu.manager.workmode.WorkMode
import dev.maplesu.manager.workmode.superuser.LiteImplantQuiesceGate

/**
 * Ultra SDK 5.1.0 的寄生接线。旧 JNI/回调 ABI 保留，root 通道使用 Ultra SDK。
 * 旧库缺符号时仍映射 ULTRA_API_UNLINKED，不把安装回执等同于宿主已加载。
 */
class NativeParasiteCall : ParasiteNativeCall {
    override fun precheck(rootKey: String, targetPidCmdline: String): String? =
        NativeBridge.parasitePrecheckApp(rootKey, targetPidCmdline)

    override fun implantApp(rootKey: String, targetPidCmdline: String, soPath: String): String? =
        NativeBridge.parasiteImplantApp(rootKey, targetPidCmdline, soPath)

    override fun implantSuEnv(
        rootKey: String,
        targetPidCmdline: String,
        soPath: String,
        suDir: String,
    ): String? = NativeBridge.parasiteImplantSuEnv(rootKey, targetPidCmdline, soPath, suDir)
}

/** Ultra 运行态 → 寄生端口可用性（纯映射，主机可测）。 */
object ParasiteRuntimeAvailability {
    fun current(): UltraAvailability = fromUltraState(UltraEnvironmentProbe.current())

    fun fromUltraState(state: UltraEnvironmentProbe.State): UltraAvailability = when (state) {
        UltraEnvironmentProbe.State.Running -> UltraAvailability.RUNNING
        UltraEnvironmentProbe.State.NoKey -> UltraAvailability.NO_ROOT_KEY
        UltraEnvironmentProbe.State.NotInstalled -> UltraAvailability.NOT_RUNNING
        UltraEnvironmentProbe.State.Fault -> UltraAvailability.NOT_RUNNING
        UltraEnvironmentProbe.State.Unknown -> UltraAvailability.UNLINKED
    }
}

/**
 * 生产端口：Ultra SDK 回执 → 四码映射。rootKey 只在进程内以 ByteArray 传入 JNI。
 *
 * @param rootKeyProvider 由调用方提供（通常 `UltraRootKeyStore.read(ctx)`）；
 *   缺失只返回 `ULTRA_ROOT_KEY_UNAVAILABLE`，绝不伪造 key。
 */
fun productionParasiteSdkPort(
    rootKeyProvider: () -> ByteArray?,
    native: ParasiteNativeCall = NativeParasiteCall(),
    availability: () -> UltraAvailability = { ParasiteRuntimeAvailability.current() },
    quiescing: () -> Boolean = { LiteImplantQuiesceGate.isBlocked() },
): ParasiteSdkPort = UltraLinkedParasiteSdkPort(
    api = ParasiteUltraApiAdapter(native),
    rootKeyProvider = rootKeyProvider,
    availabilityProvider = availability,
    quiescing = quiescing,
)

/**
 * A（Ultra / LITE）走 Ultra SDK 和 Ultra rootKey；KSU/未判定保持不可用。
 * Lite CLI 端口保留供旧调用方使用，不向它传 Ultra 凭据。
 */
fun productionParasiteSdkPort(
    context: Context,
    mode: WorkMode? = ModeRuntime.active,
): ParasiteSdkPort {
    val appContext = context.applicationContext
    return selectProductionParasitePort(
        mode = mode,
        litePort = {
            productionParasiteSdkPort(
                rootKeyProvider = {
                    runCatching { UltraRootKeyStore.read(appContext)?.toByteArray(Charsets.US_ASCII) }.getOrNull()
                },
            )
        },
        unavailablePort = { UnavailableParasiteSdkPort(UltraAvailability.RUNNING) },
    )
}
