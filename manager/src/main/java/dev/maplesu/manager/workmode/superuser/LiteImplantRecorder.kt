package dev.maplesu.manager.workmode.superuser

import android.content.Context
import java.io.File

/** 一次"修改前备份 + 登记"的结果；[ok]=false 时调用方**必须放弃写入**（fail closed）。 */
data class ImplantPreparation(
    val ok: Boolean,
    val code: String = "",
    val detail: String = "",
    val intent: ImplantIntent? = null,
) {
    companion object {
        fun failed(code: String, detail: String = "") = ImplantPreparation(false, code, detail)
    }
}

/**
 * runtime 侧植入登记端口（W19）。`SuDelivery`/`SuPathWiring` 在**写任何字节之前**
 * 调用 `before*`（备份 + 登记未激活条目），成功后 `after*` 置激活。
 *
 * 未安装记录器时（[LiteImplantRecorderProvider.current] == null）runtime 保持旧行为；
 * 生产接线必须安装（见 [installLiteImplantRecorder]），否则 S0-15 无法证明可恢复。
 */
interface LiteImplantRecorder {
    fun beforeDelivery(
        packageName: String,
        uid: Int,
        deliverPath: String,
        deliverSha256: String,
        createdDirs: List<String>,
        now: Long,
    ): ImplantPreparation

    fun afterDelivery(preparation: ImplantPreparation)

    fun beforeWiring(
        packageName: String,
        uid: Int,
        targetLibraryPath: String,
        deliverPath: String,
        deliverSha256: String,
        createdDirs: List<String>,
        now: Long,
    ): ImplantPreparation

    fun afterWiring(preparation: ImplantPreparation)

    /** 瞬态 PATH 注入：无持久修改，登记 `originalAbsent=true` 的 PATH_INJECTION 条目。 */
    fun recordPathInjection(
        packageName: String,
        uid: Int,
        deliverPath: String,
        deliverSha256: String,
        now: Long,
    ): ImplantPreparation
}

/** 生产实现：备份工作流 + 控制面登记表（shared/lite-implants.json）。 */
class RegistryLiteImplantRecorder(
    private val registry: LiteImplantRegistry,
    private val workflow: LiteImplantBackupWorkflow,
) : LiteImplantRecorder {

    override fun beforeDelivery(
        packageName: String,
        uid: Int,
        deliverPath: String,
        deliverSha256: String,
        createdDirs: List<String>,
        now: Long,
    ): ImplantPreparation = prepare(
        workflow.prepareDelivery(packageName, uid, deliverPath, deliverSha256, createdDirs, now),
    )

    override fun afterDelivery(preparation: ImplantPreparation) = confirm(preparation)

    override fun beforeWiring(
        packageName: String,
        uid: Int,
        targetLibraryPath: String,
        deliverPath: String,
        deliverSha256: String,
        createdDirs: List<String>,
        now: Long,
    ): ImplantPreparation = prepare(
        workflow.prepareWiring(
            packageName, uid, targetLibraryPath, deliverPath, deliverSha256, createdDirs, now,
        ),
    )

    override fun afterWiring(preparation: ImplantPreparation) = confirm(preparation)

    override fun recordPathInjection(
        packageName: String,
        uid: Int,
        deliverPath: String,
        deliverSha256: String,
        now: Long,
    ): ImplantPreparation {
        val intent = ImplantIntent(
            packageName = packageName,
            uid = uid,
            deliverPath = deliverPath,
            deliverSha256 = deliverSha256,
            wiringTargetLib = null,
            sideLibraryPath = null,
            createdDirs = emptyList(),
            pathInjection = true,
            recordedAt = now,
            kind = ImplantKinds.PATH_INJECTION,
            originalAbsent = true,
            active = true,
        )
        return record(intent)
    }

    private fun prepare(preparation: ImplantPreparation): ImplantPreparation {
        if (!preparation.ok || preparation.intent == null) return preparation
        if (LiteImplantQuiesceGate.isBlocked()) {
            return ImplantPreparation.failed(LiteImplantCodes.QUIESCING, "writes quiesced for mode switch")
        }
        return record(preparation.intent).let { recorded ->
            if (recorded.ok) preparation else recorded
        }
    }

    private fun record(intent: ImplantIntent): ImplantPreparation = try {
        registry.record(intent)
        ImplantPreparation(ok = true, intent = intent)
    } catch (error: Throwable) {
        ImplantPreparation.failed(LiteImplantCodes.REGISTRY_WRITE_FAILED, error.javaClass.simpleName)
    }

    private fun confirm(preparation: ImplantPreparation) {
        val intent = preparation.intent ?: return
        runCatching { registry.record(intent.copy(active = true)) }
    }
}

/** runtime 读取的全局记录器（未安装 = 旧行为；安装后所有投递/植入自动备份+登记）。 */
object LiteImplantRecorderProvider {
    @Volatile
    private var installed: LiteImplantRecorder? = null

    fun current(): LiteImplantRecorder? = installed

    fun install(recorder: LiteImplantRecorder?) {
        installed = recorder
    }

    fun resetForTest() {
        installed = null
    }
}

/**
 * 生产接线（由 App 启动/W19 集成调用一次）：
 * `sharedDirectory` = `/data/adb/maplesu-workmode/shared`（0700 root；登记表 0600）。
 * 返回的 recorder 已安装到 [LiteImplantRecorderProvider]。
 *
 * @param registry 可注入（测试/迁移）；默认文件登记表 + `ScriptImplantReverter`。
 */
fun installLiteImplantRecorder(
    sharedDirectory: File,
    context: Context,
    registry: LiteImplantRegistry? = null,
    runner: RootScriptRunner = DirectRootScriptRunner(context),
): LiteImplantRecorder {
    val actualRegistry = registry ?: FileLiteImplantRegistry(
        directory = sharedDirectory,
        originals = FileOriginalBackupStore(sharedDirectory),
        reverter = ScriptImplantReverter(runner),
    )
    val recorder = GateGuardedLiteImplantRecorder(
        RegistryLiteImplantRecorder(
            registry = actualRegistry,
            workflow = LiteImplantBackupWorkflow(runner, sharedDirectory),
        ),
    )
    LiteImplantRecorderProvider.install(recorder)
    return recorder
}

/** 测试/嵌入式装配：用自定义 runner 与目录构造（不安装到 provider）。 */
fun createLiteImplantRecorder(
    sharedDirectory: File,
    runner: RootScriptRunner,
    clock: dev.maplesu.manager.workmode.detect.Clock =
        dev.maplesu.manager.workmode.detect.WallClock,
): Pair<RegistryLiteImplantRecorder, FileLiteImplantRegistry> {
    val registry = FileLiteImplantRegistry(
        directory = sharedDirectory,
        originals = FileOriginalBackupStore(sharedDirectory),
        reverter = ScriptImplantReverter(runner),
        clock = clock,
    )
    return RegistryLiteImplantRecorder(
        registry,
        LiteImplantBackupWorkflow(runner, sharedDirectory, clock),
    ) to registry
}
