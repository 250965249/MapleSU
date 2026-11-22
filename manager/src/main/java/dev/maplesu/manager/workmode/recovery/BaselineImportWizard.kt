package dev.maplesu.manager.workmode.recovery

import dev.maplesu.manager.workmode.switch.BaselineErrors
import dev.maplesu.manager.workmode.switch.BaselineImportRequest
import dev.maplesu.manager.workmode.switch.BaselineManifest
import dev.maplesu.manager.workmode.switch.BaselineProvenance
import dev.maplesu.manager.workmode.switch.BaselineResult
import dev.maplesu.manager.workmode.switch.BaselineRules
import dev.maplesu.manager.workmode.switch.BaselineState
import dev.maplesu.manager.workmode.switch.BaselineStore
import dev.maplesu.manager.workmode.switch.BaselineVerification
import dev.maplesu.manager.workmode.switch.DeviceBootFacts

/**
 * baseline 导入向导（主文档 §6.5 / §6.6）。
 *
 * 纯状态机 + 对 [BaselineStore] host 接口的调用；不 import Android、不碰分区。
 * 硬约束：
 * - takeover 只能"恢复接管前状态"，**永不可晋升 baseline**（发布红线 3）；
 * - `Ace6/`、`.analysis/` 研究镜像不得自动当 baseline，只能显式导入并校验；
 * - import 必须过 [BaselineRules.validateImport]（clean/来源/AVB 尾部/分区非空）。
 */
enum class BaselineWizardStep { IDLE, SOURCE_CHOSEN, VALIDATED, COMMITTING, IMPORTED, FAILED }

enum class BaselineSourceKind {
    /** 用户显式导入 OEM/已确认干净的镜像文件。 */
    OEM_IMAGE_FILE,

    /** 当前分区接管快照（仅恢复接管前状态，不可当 baseline）。 */
    TAKEOVER_SNAPSHOT,
}

data class BaselineWizardState(
    val step: BaselineWizardStep = BaselineWizardStep.IDLE,
    val sourceKind: BaselineSourceKind? = null,
    val sourcePath: String = "",
    val manifest: BaselineManifest? = null,
    /** 已选文件的基础事实（size/sha）——由调用方提供，测试可直接构造。 */
    val sourceSize: Long = 0,
    val sourceSha256: String = "",
    /** 设备事实（用于 import 后复验 STALE）。 */
    val device: DeviceBootFacts = DeviceBootFacts("", "", ""),
    /** 非空 = 当前步骤失败；取值域优先复用 [BaselineErrors]。 */
    val errorCode: String? = null,
    val errorDetail: String = "",
    /** 成功导入后的复验结果（PRESENT_OK/STALE/...）。 */
    val verification: BaselineVerification? = null,
    /** 下一步 i18n key。 */
    val nextStepKey: String = "baseline_next_choose_source",
) {
    val canCommit: Boolean
        get() = step == BaselineWizardStep.VALIDATED && manifest != null && errorCode == null

    val isTakeover: Boolean get() = sourceKind == BaselineSourceKind.TAKEOVER_SNAPSHOT
}

object BaselineWizardCopyKeys {
    const val NEXT_CHOOSE_SOURCE = "baseline_next_choose_source"
    const val NEXT_REVIEW = "baseline_next_review"
    const val NEXT_CONFIRM = "baseline_next_confirm"
    const val NEXT_TAKEOVER_ONLY = "baseline_next_takeover_only"
    const val NEXT_FIX_ERROR = "baseline_next_fix_error"
    const val NEXT_DONE = "baseline_next_done"
    const val NEXT_IMPORT_AGAIN = "baseline_next_import_again"
}

class BaselineImportWizard(private val store: BaselineStore) {

    private var state = BaselineWizardState()
    private var pendingTakeoverId: String? = null

    fun state(): BaselineWizardState = state

    fun reset(): BaselineWizardState {
        state = BaselineWizardState()
        pendingTakeoverId = null
        return state
    }

    /** 用户选择来源。TAKEOVER_SNAPSHOT 只允许进入"恢复接管前状态"，不允许 import。 */
    fun chooseSource(
        kind: BaselineSourceKind,
        sourcePath: String,
        sourceSize: Long = 0,
        sourceSha256: String = "",
        device: DeviceBootFacts = DeviceBootFacts("", "", ""),
    ): BaselineWizardState {
        val error = when {
            sourcePath.isBlank() -> BaselineErrors.BASELINE_CORRUPT
            kind == BaselineSourceKind.OEM_IMAGE_FILE && BaselineRules.isStudyImage(sourcePath) ->
                BaselineErrors.BASELINE_PROVENANCE_UNKNOWN
            sourceSize <= 0 && kind == BaselineSourceKind.OEM_IMAGE_FILE -> BaselineErrors.BASELINE_CORRUPT
            sourceSha256.isNotEmpty() && !sourceSha256.matches(Regex("[0-9a-fA-F]{64}")) ->
                BaselineErrors.BASELINE_CORRUPT
            else -> null
        }
        state = BaselineWizardState(
            step = if (error == null) BaselineWizardStep.SOURCE_CHOSEN else BaselineWizardStep.FAILED,
            sourceKind = kind,
            sourcePath = sourcePath,
            sourceSize = sourceSize,
            sourceSha256 = sourceSha256.lowercase(),
            device = device,
            errorCode = error,
            errorDetail = if (kind == BaselineSourceKind.OEM_IMAGE_FILE && BaselineRules.isStudyImage(sourcePath)) {
                "study image cannot become baseline"
            } else {
                ""
            },
            nextStepKey = when {
                error != null -> BaselineWizardCopyKeys.NEXT_FIX_ERROR
                kind == BaselineSourceKind.TAKEOVER_SNAPSHOT -> BaselineWizardCopyKeys.NEXT_TAKEOVER_ONLY
                else -> BaselineWizardCopyKeys.NEXT_REVIEW
            },
        )
        return state
    }

    /**
     * 载入候选 manifest 并做纯校验（不写盘）：来源、clean、patch markers、AVB 尾部、分区列表。
     * 通过后才允许 commit。
     */
    fun review(manifest: BaselineManifest): BaselineWizardState {
        val kind = state.sourceKind
        if (kind == null || state.step == BaselineWizardStep.IDLE) {
            state = state.copy(
                step = BaselineWizardStep.FAILED,
                errorCode = BaselineErrors.BASELINE_CORRUPT,
                errorDetail = "source not chosen",
                nextStepKey = BaselineWizardCopyKeys.NEXT_CHOOSE_SOURCE,
            )
            return state
        }
        if (kind == BaselineSourceKind.TAKEOVER_SNAPSHOT) {
            state = state.copy(
                manifest = manifest,
                step = BaselineWizardStep.FAILED,
                errorCode = BaselineErrors.BASELINE_PROMOTION_FORBIDDEN,
                errorDetail = "takeover snapshot can only restore the pre-takeover state",
                nextStepKey = BaselineWizardCopyKeys.NEXT_TAKEOVER_ONLY,
            )
            return state
        }
        val validationError = BaselineRules.validateImport(state.sourcePath, manifest)
        state = state.copy(
            manifest = manifest,
            step = if (validationError == null) BaselineWizardStep.VALIDATED else BaselineWizardStep.FAILED,
            errorCode = validationError,
            errorDetail = validationError.orEmpty(),
            nextStepKey = if (validationError == null) {
                BaselineWizardCopyKeys.NEXT_CONFIRM
            } else {
                BaselineWizardCopyKeys.NEXT_FIX_ERROR
            },
        )
        return state
    }

    /** 用户确认后写入 baseline（`requireAbsent=true`：baseline 一经建立不得覆盖）。 */
    fun commit(): BaselineWizardState {
        val manifest = state.manifest
        if (!state.canCommit || manifest == null) {
            state = state.copy(
                step = BaselineWizardStep.FAILED,
                errorCode = state.errorCode ?: BaselineErrors.BASELINE_CORRUPT,
                nextStepKey = BaselineWizardCopyKeys.NEXT_FIX_ERROR,
            )
            return state
        }
        state = state.copy(step = BaselineWizardStep.COMMITTING)
        return when (val result = store.import(BaselineImportRequest(state.sourcePath, manifest))) {
            is BaselineResult.Ok -> {
                val verification = store.verify(result.manifest.id)
                state = state.copy(
                    step = BaselineWizardStep.IMPORTED,
                    verification = verification,
                    errorCode = null,
                    errorDetail = "",
                    nextStepKey = if (verification.state == BaselineState.PRESENT_OK) {
                        BaselineWizardCopyKeys.NEXT_DONE
                    } else {
                        BaselineWizardCopyKeys.NEXT_IMPORT_AGAIN
                    },
                )
                state
            }
            is BaselineResult.Failed -> {
                state = state.copy(
                    step = BaselineWizardStep.FAILED,
                    errorCode = result.code,
                    errorDetail = result.detail,
                    nextStepKey = BaselineWizardCopyKeys.NEXT_FIX_ERROR,
                )
                state
            }
        }
    }

    /**
     * "恢复接管前状态"入口：只写 `boot/takeover/<id>`，绝不写 baseline 目录。
     * 返回的 manifest provenance 由 store 侧强制为 PRE_FIRST_WRITE_CAPTURE。
     */
    fun captureTakeover(id: String, manifest: BaselineManifest): BaselineWizardState {
        pendingTakeoverId = id
        val forced = manifest.copy(provenance = BaselineProvenance.PRE_FIRST_WRITE_CAPTURE)
        return when (val result = store.captureTakeover(
            dev.maplesu.manager.workmode.switch.TakeoverRequest(id, forced),
        )) {
            is BaselineResult.Ok -> {
                state = state.copy(
                    step = BaselineWizardStep.IMPORTED,
                    manifest = result.manifest,
                    sourceKind = BaselineSourceKind.TAKEOVER_SNAPSHOT,
                    errorCode = null,
                    errorDetail = "",
                    nextStepKey = BaselineWizardCopyKeys.NEXT_TAKEOVER_ONLY,
                )
                state
            }
            is BaselineResult.Failed -> {
                state = state.copy(
                    step = BaselineWizardStep.FAILED,
                    errorCode = result.code,
                    errorDetail = result.detail,
                    nextStepKey = BaselineWizardCopyKeys.NEXT_FIX_ERROR,
                )
                state
            }
        }
    }

    /** 设备事实变化后的复验（STALE 时 UI 必须阻止切换）。 */
    fun verifyImported(): BaselineVerification {
        val verification = store.verify(state.manifest?.id)
        state = state.copy(verification = verification)
        return verification
    }
}
