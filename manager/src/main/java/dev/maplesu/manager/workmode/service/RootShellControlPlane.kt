package dev.maplesu.manager.workmode.service

import android.content.Context
import dev.maplesu.manager.workmode.Hashes
import dev.maplesu.manager.workmode.control.ControlJsonCodec
import dev.maplesu.manager.workmode.control.ControlPlane
import dev.maplesu.manager.workmode.control.ControlRead
import dev.maplesu.manager.workmode.control.ControlWrite
import dev.maplesu.manager.workmode.control.EvidenceLine
import dev.maplesu.manager.workmode.control.ShaCheck
import dev.maplesu.manager.workmode.control.schema.SharedSuperuserFile
import dev.maplesu.manager.workmode.control.schema.canonicalized
import dev.maplesu.manager.workmode.superuser.DirectRootScriptRunner
import dev.maplesu.manager.workmode.superuser.RootScriptRunner
import java.io.File

/**
 * W08 S1 的 root 侧控制面适配：`SuperuserSync.exportBeforeSwitch` 需要**写**
 * `/data/adb/maplesu-workmode/shared/superuser.json`，App 进程无权限。
 *
 * 实现只覆盖 `SuperuserSync` 用到的四个操作（read/write shared + appendEvidence + step），
 * 通过现有一次性 root 通道（`DirectRoot`，凭据只走 stdin）执行；其余方法显式拒绝，
 * 避免"以为能读写 control plane"的误用。写失败 → `ControlWrite.Rejected`（fail-closed）。
 */
internal class RootShellControlPlane(
    context: Context,
    private val root: File = File(dev.maplesu.manager.workmode.control.ControlPaths.ROOT),
    private val runner: RootScriptRunner = DirectRootScriptRunner(context),
) : ControlPlane {

    private val cache = File(context.cacheDir, "workmode-root").apply { mkdirs() }
    private val sharedMain = File(root, "shared/superuser.json")
    private val sharedPrev = File(root, "shared/superuser.json.prev")
    private val sharedSha = File(root, "shared/superuser.json.sha256")

    override fun readModes(): ControlRead<dev.maplesu.manager.workmode.control.schema.ModesFile> =
        unsupported()
    override fun readInstalled(): ControlRead<dev.maplesu.manager.workmode.control.schema.InstalledFile> =
        unsupported()
    override fun readSwitchHead(): ControlRead<dev.maplesu.manager.workmode.control.schema.SwitchHeadView> =
        unsupported()
    override fun readSelinux(): ControlRead<dev.maplesu.manager.workmode.control.schema.SelinuxFile> =
        unsupported()
    override fun readPublish(): ControlRead<dev.maplesu.manager.workmode.control.schema.PublishFile> =
        unsupported()

    override fun readSharedSuperuser(): ControlRead<SharedSuperuserFile> {
        if (!rootTest(sharedMain)) return ControlRead.Missing(sharedMain.path)
        val raw = rootRead(sharedMain) ?: return ControlRead.Corrupt(
            sharedMain.path, "SHARED_CORRUPT", "root read failed",
        )
        val expected = rootRead(sharedSha)?.trim()?.lowercase()
        val actual = Hashes.sha256(raw.toByteArray(Charsets.UTF_8))
        if (expected != null && expected.matches(Regex("[0-9a-f]{64}")) && expected != actual) {
            return ControlRead.Corrupt(sharedMain.path, "SHARED_CORRUPT", "sha mismatch")
        }
        val value = ControlJsonCodec.decodeOrNull(raw, SharedSuperuserFile.serializer())
            ?: return ControlRead.Corrupt(sharedMain.path, "SHARED_CORRUPT", "parse failed")
        if (value.schema > 1) return ControlRead.Unreadable(sharedMain.path, "CONTROL_SCHEMA_TOO_NEW")
        return ControlRead.Ok(value, if (expected == null) ShaCheck.MISSING else ShaCheck.OK)
    }

    override fun writeModes(
        transform: (dev.maplesu.manager.workmode.control.schema.ModesFile) -> dev.maplesu.manager.workmode.control.schema.ModesFile,
    ): ControlWrite<dev.maplesu.manager.workmode.control.schema.ModesFile> =
        ControlWrite.Rejected("ROOT_CONTROL_WRITE_UNSUPPORTED", root.path)

    override fun writeSharedSuperuser(
        transform: (SharedSuperuserFile) -> SharedSuperuserFile,
    ): ControlWrite<SharedSuperuserFile> {
        val current = when (val read = readSharedSuperuser()) {
            is ControlRead.Ok -> read.value
            is ControlRead.Missing -> null
            is ControlRead.Corrupt -> return ControlWrite.Rejected(read.code, read.detail)
            is ControlRead.Unreadable -> return ControlWrite.Rejected(read.code, read.path)
        }
        val next = transform(current ?: defaultShared()).canonicalized()
        if (next.schema > 1) return ControlWrite.Rejected("CONTROL_SCHEMA_TOO_NEW", "schema=${next.schema}")
        if (current != null && next.revision < current.revision) {
            return ControlWrite.Rejected("CONTROL_REVISION_REGRESSION", "${current.revision}->${next.revision}")
        }
        val json = ControlJsonCodec.encode(next, SharedSuperuserFile.serializer())
        val sha = Hashes.sha256(json.toByteArray(Charsets.UTF_8))
        val payload = writePayload("shared-main", json)
        val prevPayload = current?.let {
            writePayload("shared-prev", ControlJsonCodec.encode(it, SharedSuperuserFile.serializer()))
        }
        val script = buildString {
            append("set -e; ")
            append("mkdir -p '${File(root, "shared").path}'; ")
            if (prevPayload != null) {
                append("cp '${prevPayload.path}' '${sharedPrev.path}'; ")
                append("chown 0:0 '${sharedPrev.path}'; chmod 0600 '${sharedPrev.path}'; ")
            }
            append("cp '${payload.path}' '${sharedMain.path}.tmp'; ")
            append("chown 0:0 '${sharedMain.path}.tmp'; chmod 0600 '${sharedMain.path}.tmp'; ")
            append("mv '${sharedMain.path}.tmp' '${sharedMain.path}'; ")
            append("printf '%s' '$sha' > '${sharedSha.path}'; ")
            append("chown 0:0 '${sharedSha.path}'; chmod 0600 '${sharedSha.path}'; ")
        }
        val result = runner.run(script)
        return if (result.code == 0) {
            ControlWrite.Ok(next, next.revision, sha)
        } else {
            ControlWrite.Rejected("SHARED_CORRUPT", "root write rc=${result.code}:${result.out.take(160)}")
        }
    }

    override fun appendEvidence(line: EvidenceLine) {
        val payload = writePayload("evidence", ControlJsonCodec.encode(line, EvidenceLine.serializer()) + "\n")
        runner.run("mkdir -p '${File(root, "control").path}'; cat '${payload.path}' >> '${File(root, "control/evidence.jsonl").path}'")
    }

    override fun appendStep(switchId: String, line: String): Long {
        val payload = writePayload("step", line.trim() + "\n")
        val target = File(root, "boot/work/$switchId/journal.jsonl")
        runner.run("mkdir -p '${target.parentFile.path}'; cat '${payload.path}' >> '${target.path}'")
        return 0
    }

    /** S1 provider 需要把导出的 shared JSON 交给服务端：只读拷回 App 私有文件。 */
    fun copySharedTo(destination: File): Boolean {
        val raw = rootRead(sharedMain) ?: return false
        destination.parentFile?.mkdirs()
        destination.writeText(raw)
        return true
    }

    private fun rootRead(file: File): String? {
        val marker = "__MISSING__"
        val result = runner.run(
            "if [ -f '${file.path}' ]; then cat '${file.path}'; else printf '%s' '$marker'; fi",
        )
        if (result.code != 0) return null
        val out = result.out
        return if (out.trim() == marker) null else out
    }

    private fun rootTest(file: File): Boolean =
        runner.run("test -f '${file.path}'").code == 0

    private fun writePayload(name: String, content: String): File =
        File(cache, "$name-${System.nanoTime()}.json").apply { writeText(content) }

    private fun defaultShared() = SharedSuperuserFile(
        revision = 0,
        updatedAt = 0,
        lastWriter = "",
        entries = emptyList(),
        tombs = emptyList(),
        policy = dev.maplesu.manager.workmode.control.schema.SharedPolicy(),
    )

    private fun <T> unsupported(): ControlRead<T> =
        ControlRead.Unreadable(root.path, "ROOT_CONTROL_READ_UNSUPPORTED")
}
