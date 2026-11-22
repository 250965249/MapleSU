package dev.maplesu.manager.workmode.control

import dev.maplesu.manager.workmode.Hashes
import dev.maplesu.manager.workmode.control.schema.InstalledFile
import dev.maplesu.manager.workmode.control.schema.ModesFile
import dev.maplesu.manager.workmode.control.schema.PublishFile
import dev.maplesu.manager.workmode.control.schema.SelinuxFile
import dev.maplesu.manager.workmode.control.schema.SharedSuperuserFile
import dev.maplesu.manager.workmode.control.schema.SwitchHeadView
import dev.maplesu.manager.workmode.control.schema.SwitchHeadViewCodec
import dev.maplesu.manager.workmode.control.schema.canonicalized
import dev.maplesu.manager.workmode.control.schema.validateSemantics
import dev.maplesu.manager.workmode.detect.BootIdSource
import dev.maplesu.manager.workmode.detect.Clock
import dev.maplesu.manager.workmode.detect.ProcBootIdSource
import dev.maplesu.manager.workmode.detect.WallClock
import dev.maplesu.manager.workmode.switch.FileSwitchJournal
import kotlinx.serialization.KSerializer
import java.io.File
import java.io.IOException

/** 控制面错误码（01 §4.8）。 */
object ControlErrors {
    const val CONTROL_MODES_CORRUPT = "CONTROL_MODES_CORRUPT"
    const val CONTROL_SCHEMA_TOO_NEW = "CONTROL_SCHEMA_TOO_NEW"
    const val CONTROL_REVISION_REGRESSION = "CONTROL_REVISION_REGRESSION"
    const val CONTROL_TAMPERED = "CONTROL_TAMPERED"
    const val CONTROL_WRITE_FAILED = "CONTROL_WRITE_FAILED"
    const val CONTROL_DIR_INVALID = "CONTROL_DIR_INVALID"
    const val SHARED_CORRUPT = "SHARED_CORRUPT"
    const val SHARED_ROLLED_BACK = "SHARED_ROLLED_BACK"
    const val EVIDENCE_REDACTED = "EVIDENCE_REDACTED"
    /** switch.json 解析失败 / switchId 与目录不符（02 §3.2；01 §4.7 呈现为 RECOVERY_REQUIRED）。 */
    const val SWITCH_CORRUPT = "SWITCH_CORRUPT"
    const val CONTROL_FILE_MISSING = "CONTROL_FILE_MISSING"
}

sealed interface ControlRead<out T> {
    data class Ok<T>(val value: T, val sha: ShaCheck) : ControlRead<T>
    data class Missing(val path: String) : ControlRead<Nothing>
    data class Corrupt(val path: String, val code: String, val detail: String) : ControlRead<Nothing>

    /** 无 root / EACCES / schema too new。 */
    data class Unreadable(val path: String, val code: String) : ControlRead<Nothing>
}

sealed interface ControlWrite<out T> {
    data class Ok<T>(val value: T, val revision: Long, val sha256: String) : ControlWrite<T>
    data class Rejected(val code: String, val detail: String) : ControlWrite<Nothing>
}

/**
 * 控制面读写门面。
 *
 * 读：需要 root 会话时实现方返回 [ControlRead.Unreadable]，**不得**返回默认值；
 * 写：内部做 revision 单调与 schema 闸门校验，所有写入走 [AtomicControlFile]。
 */
interface ControlPlane {
    fun readModes(): ControlRead<ModesFile>
    fun readInstalled(): ControlRead<InstalledFile>
    fun readSwitchHead(): ControlRead<SwitchHeadView>
    fun readSharedSuperuser(): ControlRead<SharedSuperuserFile>
    fun readSelinux(): ControlRead<SelinuxFile>
    fun readPublish(): ControlRead<PublishFile>

    fun writeModes(transform: (ModesFile) -> ModesFile): ControlWrite<ModesFile>
    fun writeSharedSuperuser(transform: (SharedSuperuserFile) -> SharedSuperuserFile): ControlWrite<SharedSuperuserFile>

    fun appendEvidence(line: EvidenceLine)
    /** 服务端写 WAL 用；行格式由 02 §3.3 定义，本方法只保证 append + fsync + seq 单调。 */
    fun appendStep(switchId: String, line: String): Long
}

/**
 * 文件系统实现（主机可测；设备侧由 root 适配器复用同一实现并补 chown 0:0）。
 *
 * [root] 在设备上 = `/data/adb/maplesu-workmode`，主机单测 = 临时目录。
 */
class FileControlPlane(
    private val root: File = ControlPaths.ROOT_FILE,
    private val clock: Clock = WallClock,
    private val bootIdSource: BootIdSource = ProcBootIdSource,
    private val supportedSchema: Int = 1,
    private val onDiagnostic: (String) -> Unit = {},
) : ControlPlane {

    private val evidence = EvidenceLog(File(root, "control/evidence.jsonl"), clock, bootIdSource)

    private fun control(name: String) = File(root, "control/$name")
    private fun shared(name: String) = File(root, "shared/$name")
    private fun work(switchId: String) = File(root, "boot/work/$switchId/journal.jsonl")

    override fun readModes(): ControlRead<ModesFile> = readJson(
        file = control("modes.json"),
        serializer = ModesFile.serializer(),
        schema = { it.schema },
        corruptCode = ControlErrors.CONTROL_MODES_CORRUPT,
        quarantineOnCorrupt = true,
        validate = { it.validateSemantics() },
    )

    override fun readInstalled(): ControlRead<InstalledFile> = missingOnCorrupt(
        readJson(
            file = control("installed.json"),
            serializer = InstalledFile.serializer(),
            schema = { it.schema },
            corruptCode = ControlErrors.CONTROL_MODES_CORRUPT,
        ),
    )

    override fun readSwitchHead(): ControlRead<SwitchHeadView> {
        val file = control("switch.json")
        if (!file.isFile) return ControlRead.Missing(file.path)
        if (AtomicControlFile.verifySha(file) == ShaCheck.MISMATCH) {
            return ControlRead.Corrupt(file.path, ControlErrors.SWITCH_CORRUPT, "sha mismatch")
        }
        val raw = AtomicControlFile.readUtf8(file)
            ?: return ControlRead.Corrupt(file.path, ControlErrors.SWITCH_CORRUPT, "unreadable")
        val head = SwitchHeadViewCodec.parse(raw)
            ?: return ControlRead.Corrupt(file.path, ControlErrors.SWITCH_CORRUPT, "parse failed")
        return ControlRead.Ok(head, AtomicControlFile.verifySha(file))
    }

    override fun readSharedSuperuser(): ControlRead<SharedSuperuserFile> {
        val main = shared("superuser.json")
        val primary = readJson(
            file = main,
            serializer = SharedSuperuserFile.serializer(),
            schema = { it.schema },
            corruptCode = ControlErrors.SHARED_CORRUPT,
        )
        if (primary !is ControlRead.Corrupt && primary !is ControlRead.Unreadable) return primary
        // 回退 .prev（若可解析）并记 SHARED_ROLLED_BACK；两代都坏 → 只读 + SHARED_CORRUPT。
        val prev = shared("superuser.json.prev")
        if (prev.isFile) {
            val raw = AtomicControlFile.readUtf8(prev)
            val value = raw?.let { ControlJsonCodec.decodeOrNull(it, SharedSuperuserFile.serializer()) }
            if (value != null && value.schema <= supportedSchema) {
                onDiagnostic(ControlErrors.SHARED_ROLLED_BACK)
                return ControlRead.Ok(value, ShaCheck.MISSING)
            }
        }
        return ControlRead.Corrupt(main.path, ControlErrors.SHARED_CORRUPT, "primary+prev corrupt")
    }

    override fun readSelinux(): ControlRead<SelinuxFile> {
        val result = readJson(
            file = control("selinux.json"),
            serializer = SelinuxFile.serializer(),
            schema = { it.schema },
            corruptCode = ControlErrors.CONTROL_TAMPERED,
        )
        if (result is ControlRead.Ok && result.value.policyWritten) {
            return ControlRead.Corrupt(control("selinux.json").path, ControlErrors.CONTROL_TAMPERED, "policyWritten=true")
        }
        return missingOnCorrupt(result)
    }

    override fun readPublish(): ControlRead<PublishFile> = missingOnCorrupt(
        readJson(
            file = control("publish.json"),
            serializer = PublishFile.serializer(),
            schema = { it.schema },
            corruptCode = ControlErrors.CONTROL_MODES_CORRUPT,
        ),
    )

    override fun writeModes(transform: (ModesFile) -> ModesFile): ControlWrite<ModesFile> {
        val current = readModes()
        val old = when (current) {
            is ControlRead.Ok -> current.value
            is ControlRead.Missing -> return ControlWrite.Rejected(ControlErrors.CONTROL_MODES_CORRUPT, "missing")
            is ControlRead.Corrupt -> return ControlWrite.Rejected(current.code, current.detail)
            is ControlRead.Unreadable -> return ControlWrite.Rejected(current.code, current.path)
        }
        val next = transform(old).canonicalized()
        if (next.schema > supportedSchema) {
            return ControlWrite.Rejected(ControlErrors.CONTROL_SCHEMA_TOO_NEW, "schema=${next.schema}")
        }
        if (next.revision < old.revision) {
            return ControlWrite.Rejected(ControlErrors.CONTROL_REVISION_REGRESSION, "old=${old.revision} new=${next.revision}")
        }
        val json = ControlJsonCodec.encode(next, ModesFile.serializer())
        val sha = Hashes.sha256Hex(json)
        return runCatching {
            ControlPermissions.ensureDir(File(root, "control"))
            AtomicControlFile.writeJson(control("modes.json"), json)
            ControlWrite.Ok(next, next.revision, sha)
        }.getOrElse { ControlWrite.Rejected(ControlErrors.CONTROL_WRITE_FAILED, it.message.orEmpty()) }
    }

    override fun writeSharedSuperuser(
        transform: (SharedSuperuserFile) -> SharedSuperuserFile,
    ): ControlWrite<SharedSuperuserFile> {
        val current = readSharedSuperuser()
        val old = when (current) {
            is ControlRead.Ok -> current.value
            is ControlRead.Missing -> null
            is ControlRead.Corrupt -> return ControlWrite.Rejected(current.code, current.detail)
            is ControlRead.Unreadable -> return ControlWrite.Rejected(current.code, current.path)
        }
        val next = transform(old ?: defaultSharedSuperuser()).canonicalized()
        if (next.schema > supportedSchema) {
            return ControlWrite.Rejected(ControlErrors.CONTROL_SCHEMA_TOO_NEW, "schema=${next.schema}")
        }
        if (old != null && next.revision < old.revision) {
            return ControlWrite.Rejected(ControlErrors.CONTROL_REVISION_REGRESSION, "old=${old.revision} new=${next.revision}")
        }
        val json = ControlJsonCodec.encode(next, SharedSuperuserFile.serializer())
        val sha = Hashes.sha256Hex(json)
        return runCatching {
            ControlPermissions.ensureDir(File(root, "shared"))
            // 先保留上一代（.prev），再原子替换主文件，最后写 .sha256。
            shared("superuser.json").takeIf { it.isFile }?.let { main ->
                AtomicControlFile.writeUtf8(shared("superuser.json.prev"), main.readBytes())
            }
            AtomicControlFile.writeJson(shared("superuser.json"), json)
            ControlWrite.Ok(next, next.revision, sha)
        }.getOrElse { ControlWrite.Rejected(ControlErrors.CONTROL_WRITE_FAILED, it.message.orEmpty()) }
    }

    override fun appendEvidence(line: EvidenceLine) {
        ControlPermissions.ensureDir(File(root, "control"))
        evidence.append(line)
    }

    override fun appendStep(switchId: String, line: String): Long =
        FileSwitchJournal(work(switchId), clock, bootIdSource).appendRaw(line)

    private fun defaultSharedSuperuser(): SharedSuperuserFile = SharedSuperuserFile(
        revision = 0,
        updatedAt = clock.nowMillis(),
        lastWriter = "",
        entries = emptyList(),
        tombs = emptyList(),
        policy = dev.maplesu.manager.workmode.control.schema.SharedPolicy(),
    )

    private fun <T> missingOnCorrupt(result: ControlRead<T>): ControlRead<T> =
        if (result is ControlRead.Corrupt) ControlRead.Missing(result.path) else result

    private fun <T> readJson(
        file: File,
        serializer: KSerializer<T>,
        schema: (T) -> Int,
        corruptCode: String,
        quarantineOnCorrupt: Boolean = false,
        validate: (T) -> List<String> = { emptyList() },
    ): ControlRead<T> {
        if (!file.isFile) return ControlRead.Missing(file.path)
        val sha = AtomicControlFile.verifySha(file)
        if (sha == ShaCheck.MISMATCH) {
            quarantine(file, quarantineOnCorrupt)
            return ControlRead.Corrupt(file.path, corruptCode, "sha mismatch")
        }
        val raw = AtomicControlFile.readUtf8(file)
            ?: return ControlRead.Corrupt(file.path, corruptCode, "unreadable/too large")
        val value = ControlJsonCodec.decodeOrNull(raw, serializer)
        if (value == null) {
            quarantine(file, quarantineOnCorrupt)
            return ControlRead.Corrupt(file.path, corruptCode, "parse failed")
        }
        if (schema(value) > supportedSchema) {
            // 只读模式：不写、不修、不覆盖（05:832 R25）。
            return ControlRead.Unreadable(file.path, ControlErrors.CONTROL_SCHEMA_TOO_NEW)
        }
        val issues = validate(value)
        if (issues.isNotEmpty()) {
            quarantine(file, quarantineOnCorrupt)
            return ControlRead.Corrupt(file.path, corruptCode, issues.joinToString(","))
        }
        return ControlRead.Ok(value, sha)
    }

    /** 保留现场（不自动重建）：modes.json.corrupt-<ts>。 */
    private fun quarantine(file: File, enabled: Boolean) {
        if (!enabled || !file.isFile) return
        runCatching {
            file.renameTo(File(file.parentFile, "${file.name}.corrupt-${clock.nowMillis()}"))
        }
    }
}
