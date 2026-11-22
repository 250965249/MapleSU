package dev.maplesu.manager.modules

import java.io.File
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.util.Properties

/**
 * Execution receipts are separate from the catalog's enabled preference.
 *
 * On-disk contract (task book `MODULE-COMPAT-TASKS-2026-10-27.md` §0.2): the receipt
 * carries `stage.<stage>.status`, `stage.<stage>.code`, `stage.<stage>.detail`,
 * `props.applied`, `props.failed` and `unsupported`. The internal per-boot bookkeeping
 * key `stage.<stage>.bootId` is MapleSU's own addition and is not part of that contract.
 */
internal data class LiteModuleRuntimeState(
    val installedBootId: String,
    val remove: Boolean = false,
    val removeRequestedBootId: String? = null,
    val stages: Map<String, Stage> = emptyMap(),
    /** T1: `props.applied` entries (`key=value`), in application order. */
    val propsApplied: List<String> = emptyList(),
    /** T1: `props.failed` entries (`key=value:reason`). */
    val propsFailed: List<String> = emptyList(),
    /** T1: the boot whose props run produced [propsApplied]/[propsFailed]. */
    val propsBootId: String? = null,
    /** Explicit uninstall permission for an existing disk tree; grants no boot execution. */
    val removalIdentity: String? = null,
) {
    /** `detail` is a single line; it is never the script's raw multi-line output. */
    data class Stage(
        val bootId: String,
        val status: String,
        val exitCode: Int? = null,
        val detail: String? = null,
    )

    fun withStage(name: String, boot: String, status: String, exitCode: Int? = null, detail: String? = null) =
        copy(stages = stages + (name to Stage(boot, status, exitCode, detail?.oneLine())))

    fun pendingStages(boot: String, enabled: Boolean, available: List<String>): List<String> {
        val candidates = when {
            remove && removeRequestedBootId != boot -> listOf("uninstall")
            remove || removalIdentity != null || !enabled || installedBootId == boot -> emptyList()
            else -> available
        }
        return candidates.filter { stages[it]?.bootId != boot }.sortedBy(bootStageOrder::indexOf)
    }

    fun canCancelRemoval(boot: String): Boolean = stages["uninstall"]?.let {
        it.bootId == boot && it.status in setOf("running", "started", "ok")
    } != true

    fun needsReboot(boot: String, enabled: Boolean, hasBootWork: Boolean): Boolean =
        enabled && !remove && hasBootWork && installedBootId == boot

    fun save(file: File) {
        val values = Properties().apply {
            setProperty("schema", "1")
            setProperty("installedBootId", installedBootId)
            setProperty("remove", remove.toString())
            removeRequestedBootId?.let { setProperty("removeRequestedBootId", it) }
            removalIdentity?.let { setProperty("removalIdentity", it) }
            // T1/T4 receipt contract: properties are their own section, never a stage.
            setProperty("props.applied", propsApplied.joinToString(";"))
            setProperty("props.failed", propsFailed.joinToString(";"))
            propsBootId?.let { setProperty("props.bootId", it) }
            // T4: always present, so "no unsupported entry" can never be read as
            // "everything is supported". Values come from the capability table.
            setProperty("unsupported", unsupported.joinToString(","))
            stages.forEach { (name, stage) ->
                require(name in stageNames) { "Unknown module stage: $name" }
                setProperty("stage.$name.bootId", stage.bootId)
                setProperty("stage.$name.status", stage.status)
                stage.exitCode?.let { setProperty("stage.$name.code", it.toString()) }
                setProperty("stage.$name.detail", stage.detail.orEmpty())
            }
        }
        val temporary = File.createTempFile(".state-", ".properties", file.parentFile)
        try {
            temporary.outputStream().use { output ->
                values.store(output, null)
                output.fd.sync()
            }
            Files.move(temporary.toPath(), file.toPath(), StandardCopyOption.ATOMIC_MOVE,
                StandardCopyOption.REPLACE_EXISTING)
        } finally {
            temporary.delete()
        }
    }

    companion object {
        const val POLICY_DISABLED_EXIT = 77
        fun policyStageStatus(exitCode: Int): String = when (exitCode) {
            0 -> "ok"
            POLICY_DISABLED_EXIT -> "skipped"
            else -> "failed"
        }

        /** KSU order: post-fs-data, properties, mount, post-mount, service, completion. */
        val bootStageOrder = listOf("policy", "uninstall", "post-fs-data", "props", "mount", "post-mount", "service",
            "boot-completed")
        val stageNames = setOf("hot-install", "install", "action", "service", "boot-completed", "uninstall",
            "post-fs-data", "mount", "post-mount", "policy", "tee")

        /** `started` acknowledges background dispatch without claiming a script exit. */
        val statuses = setOf("queued", "running", "started", "ok", "failed", "interrupted", "unsupported", "skipped")

        /** The backend now integrates a Zygisk host; availability belongs to the live list. */
        val unsupported = emptyList<String>()

        fun unsupportedCapabilities(usesZygisk: Boolean, hostRunning: Boolean): List<String> =
            if (usesZygisk && !hostRunning) listOf("zygisk") else unsupported

        private const val MAX_DETAIL = 512

        fun read(file: File): LiteModuleRuntimeState {
            require(file.isFile && file.length() in 1..16_384) { "Invalid module runtime receipt" }
            val values = Properties().apply { file.inputStream().use { load(it) } }
            require(values.getProperty("schema") == "1") { "Unknown module runtime receipt" }
            val boot = requireNotNull(values.getProperty("installedBootId"))
            require(boot.matches(Regex("[a-f0-9-]{36}"))) { "Invalid module boot receipt" }
            val removed = values.getProperty("remove")
            require(removed == "true" || removed == "false")
            val removalIdentity = values.getProperty("removalIdentity")
            require(removalIdentity == null || removalIdentity.matches(Regex("[0-9]+:[0-9]+"))) {
                "Invalid module removal identity"
            }
            val stages = stageNames.mapNotNull { name ->
                val stageBoot = values.getProperty("stage.$name.bootId")
                    ?: values.getProperty("$name.boot") // pre-0.2 receipts
                    ?: return@mapNotNull null
                val status = values.getProperty("stage.$name.status")
                    ?: values.getProperty("$name.status")
                    ?: return@mapNotNull null
                require(stageBoot.matches(Regex("[a-f0-9-]{36}"))) { "Invalid module stage receipt" }
                val normalized = if (status == "succeeded") "ok" else status
                require(normalized in statuses) { "Invalid module stage status: $status" }
                val code = (values.getProperty("stage.$name.code")
                    ?: values.getProperty("$name.exit"))?.toInt()
                name to Stage(stageBoot, normalized, code, values.getProperty("stage.$name.detail")?.takeIf { it.isNotEmpty() })
            }.toMap()
            val propsBootId = values.getProperty("props.bootId")
            require(propsBootId == null || propsBootId.matches(Regex("[a-f0-9-]{36}"))) {
                "Invalid module props receipt"
            }
            return LiteModuleRuntimeState(
                installedBootId = boot,
                remove = removed == "true",
                removeRequestedBootId = values.getProperty("removeRequestedBootId"),
                stages = stages,
                propsApplied = split(values.getProperty("props.applied")),
                propsFailed = split(values.getProperty("props.failed")),
                propsBootId = propsBootId,
                removalIdentity = removalIdentity,
            )
        }

        private fun split(value: String?): List<String> =
            value?.takeIf { it.isNotEmpty() }?.split(';')?.filter { it.isNotEmpty() }.orEmpty()

        private fun String.oneLine() = replace('\n', ' ').replace('\r', ' ').take(MAX_DETAIL)
    }
}
