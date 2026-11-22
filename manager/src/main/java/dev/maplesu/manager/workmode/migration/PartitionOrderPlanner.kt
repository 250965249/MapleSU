package dev.maplesu.manager.workmode.migration

import dev.maplesu.manager.workmode.WorkMode
import java.io.File

/**
 * 最终镜像计划（05 §3.2 / §3.4 / §3.7）。
 *
 * 核心不变量（红线 13/14 的实现形态）：
 * 1. 每个分区**恰好**一条 entry —— 结构上不可能"先写我们的再调外部还原"；
 * 2. `writeOrder` 前段必须是 RESTORE_EXTERNAL，`WRITE_CANDIDATE` 永远最后；
 * 3. 相交分区（restoreSet ∧ targetSet）只有一条 WRITE_CANDIDATE，producer 输入必须已验证干净；
 * 4. 已知家族缺干净镜像 → 抛 `MIGRATION_CLEAN_IMAGE_UNAVAILABLE`（本册比主文档更严格，见 05 C11）；
 *    未知管理器 → 允许 `LEAVE_UNCHANGED` + `residual=true`（D16）。
 */
object PartitionOrderPlanner {

    fun compose(input: PlanInput): MigrationPlan {
        val targetSet = input.target.targetPartitions
        val restoreSet = input.info.patchedPartitions
        val observed = LinkedHashSet<String>()
        observed += input.pre.keys
        observed += restoreSet
        observed += targetSet

        MigrationFailure.require(
            input.pre.isNotEmpty(),
            MigrationCodes.PRE_IMAGE_MISSING,
            "no pre images",
        )
        // 检测/备份不一致即阻断（主文档:1154）：restoreSet 的每个分区必须有 pre 镜像。
        val preMissing = restoreSet.filter { it !in input.pre }
        MigrationFailure.require(
            preMissing.isEmpty(),
            MigrationCodes.PRE_IMAGE_MISSING,
            preMissing.joinToString(","),
        )

        val entries = observed.map { name ->
            when {
                // ① 目标分区：最终内容永远是 candidate，即使它同时在 restoreSet（相交）。
                name in targetSet -> {
                    val intersect = name in restoreSet
                    val clean = input.clean[name] ?: input.baseline[name]
                    if (intersect && clean == null) {
                        // 相交且无干净镜像：已知家族阻断（不允许把外部已改镜像当 producer 输入）；
                        // UNKNOWN 按 D16 退化为"以当前镜像为输入"并记残留。
                        MigrationFailure.require(
                            !input.info.family.isKnown,
                            MigrationCodes.CLEAN_IMAGE_UNAVAILABLE,
                            "target=$name",
                        )
                    }
                    val preImage = input.pre.getValue(name)
                    PlannedPartition(
                        name = name,
                        action = PartitionAction.WRITE_CANDIDATE,
                        pre = preImage,
                        final = input.candidates[name],
                        // 非相交目标分区的当前内容就是 stock，可直接作为 producer 输入。
                        producerInput = clean ?: preImage,
                        residue = when {
                            !intersect -> ResidueMode.NONE
                            clean != null -> ResidueMode.NONE
                            input.info.family == Family.UNKNOWN -> ResidueMode.UNKNOWN_MANAGER
                            else -> ResidueMode.UNRESTORED_EXTERNAL
                        },
                        evidence = input.info.evidence.filter { it.source.contains(name) },
                    )
                }

                // ② 只在 restoreSet：还原成已验证干净镜像。
                name in restoreSet -> {
                    val clean = input.clean[name]
                    if (clean == null) {
                        MigrationFailure.require(
                            !input.info.family.isKnown,
                            MigrationCodes.CLEAN_IMAGE_UNAVAILABLE,
                            "restore=$name",
                        )
                        PlannedPartition(
                            name = name,
                            action = PartitionAction.LEAVE_UNCHANGED,
                            pre = input.pre.getValue(name),
                            final = input.pre.getValue(name),
                            producerInput = null,
                            residue = ResidueMode.UNKNOWN_MANAGER,
                            evidence = emptyList(),
                        )
                    } else {
                        PlannedPartition(
                            name = name,
                            action = PartitionAction.RESTORE_EXTERNAL,
                            pre = input.pre.getValue(name),
                            final = clean,
                            producerInput = null,
                            residue = ResidueMode.NONE,
                            evidence = emptyList(),
                        )
                    }
                }

                // ③ 其余（含 vbmeta）：保留原内容，只读核对。
                else -> PlannedPartition(
                    name = name,
                    action = PartitionAction.LEAVE_UNCHANGED,
                    pre = input.pre.getValue(name),
                    final = input.pre.getValue(name),
                    producerInput = null,
                    residue = ResidueMode.NONE,
                    evidence = emptyList(),
                )
            }
        }

        // 结构断言：每分区单 entry；RESTORE_EXTERNAL 只出现在 restoreSet - targetSet。
        MigrationFailure.require(
            entries.map { it.name }.toSet().size == entries.size,
            MigrationCodes.PLAN_INVALID,
            "duplicate partition entry",
        )
        MigrationFailure.require(
            entries.none { it.action == PartitionAction.RESTORE_EXTERNAL && it.name !in restoreSet },
            MigrationCodes.PLAN_INVALID,
            "restore outside restoreSet",
        )
        MigrationFailure.require(
            entries.none { it.action == PartitionAction.WRITE_CANDIDATE && it.name !in targetSet },
            MigrationCodes.PLAN_INVALID,
            "candidate outside targetSet",
        )
        val expectedRestores = (restoreSet - targetSet).filter { input.clean.containsKey(it) }.size
        MigrationFailure.require(
            entries.count { it.action == PartitionAction.RESTORE_EXTERNAL } == expectedRestores,
            MigrationCodes.ORDER_VIOLATION,
            "restore entry count",
        )

        // 尺寸门禁：pre 与 clean/final 必须等于真实分区长度（整分区语义，禁止短镜像补零）。
        input.partitionSize.forEach { (name, size) ->
            entries.firstOrNull { it.name == name }?.let { entry ->
                MigrationFailure.require(
                    entry.pre.size == size,
                    MigrationCodes.PARTITION_SIZE_MISMATCH,
                    "$name pre size ${entry.pre.size} != $size",
                )
                val final = entry.final
                if (final != null) {
                    MigrationFailure.require(
                        final.size == size,
                        MigrationCodes.PARTITION_SIZE_MISMATCH,
                        "$name final size ${final.size} != $size",
                    )
                }
            }
        }

        val order = orderFor(entries)
        validateOrder(entries, order)
        return MigrationPlan(
            migrationId = input.migrationId,
            target = input.target,
            targetSet = targetSet,
            restoreSet = restoreSet,
            entries = entries,
            writeOrder = order,
            rollbackOrder = order.reversed(),
            residual = entries.any { it.residue != ResidueMode.NONE },
        )
    }

    /** 写序：先还原（restoreSet - targetSet，按名排序），再写候选（targetSet，按名排序）。 */
    fun orderFor(entries: List<PlannedPartition>): List<String> {
        val restores = entries
            .filter { it.action == PartitionAction.RESTORE_EXTERNAL }
            .map { it.name }
            .sorted()
        val candidates = entries
            .filter { it.action == PartitionAction.WRITE_CANDIDATE }
            .map { it.name }
            .sorted()
        return restores + candidates
    }

    /**
     * 误序拒绝（红线 13）：候选出现在还原之前 / 还原出现在候选之后 / 遗漏写项 / 重复项 → 拒绝。
     * 供 `commitMigration` 入口与设备侧重新解析计划后二次校验（05 §3.7 三重门控的"计划"层）。
     */
    fun validateOrder(entries: List<PlannedPartition>, writeOrder: List<String>) {
        val byName = entries.associateBy { it.name }
        MigrationFailure.require(
            writeOrder.toSet().size == writeOrder.size,
            MigrationCodes.ORDER_VIOLATION,
            "duplicate order entry",
        )
        val writable = entries.filter { it.action != PartitionAction.LEAVE_UNCHANGED }.map { it.name }.toSet()
        MigrationFailure.require(
            writeOrder.toSet() == writable,
            MigrationCodes.ORDER_VIOLATION,
            "writeOrder != writable entries",
        )
        var candidateSeen = false
        for (name in writeOrder) {
            val entry = byName[name]
                ?: throw MigrationFailure(MigrationCodes.PLAN_INVALID, "unknown $name")
            when (entry.action) {
                PartitionAction.RESTORE_EXTERNAL -> MigrationFailure.require(
                    !candidateSeen,
                    MigrationCodes.ORDER_VIOLATION,
                    "restore $name after candidate",
                )
                PartitionAction.WRITE_CANDIDATE -> {
                    val targetSet = entries.filter { it.action == PartitionAction.WRITE_CANDIDATE }
                    MigrationFailure.require(targetSet.size <= 1, MigrationCodes.PLAN_INVALID, "two candidates")
                    candidateSeen = true
                }
                PartitionAction.LEAVE_UNCHANGED ->
                    throw MigrationFailure(MigrationCodes.ORDER_VIOLATION, "leave $name in writeOrder")
            }
        }
        // 相交分区只能出现一次，且必须是候选（结构上已在 compose 保证；导入外部计划时在此拒绝）。
        val restoreNames = entries.filter { it.action == PartitionAction.RESTORE_EXTERNAL }.map { it.name }
        val candidateNames = entries.filter { it.action == PartitionAction.WRITE_CANDIDATE }.map { it.name }
        MigrationFailure.require(
            (restoreNames.toSet() intersect candidateNames.toSet()).isEmpty(),
            MigrationCodes.ORDER_VIOLATION,
            "partition in both restore and candidate",
        )
    }

    /** M4 完成后的最终条件（主文档:1163）：restoreSet-targetSet==clean 且 targetSet==candidate。 */
    fun verifyFinal(
        plan: MigrationPlan,
        readBackSha: (String) -> String?,
    ): List<String> {
        val mismatched = mutableListOf<String>()
        for (entry in plan.writableEntries()) {
            val expected = entry.final?.sha256 ?: continue
            val observed = readBackSha(entry.name)
            if (observed != expected) mismatched += entry.name
        }
        return mismatched
    }
}

/** 候选镜像门禁（05 §3.2 长度 + §8.3 红线 2：禁止短镜像补零）。 */
object CandidateImages {
    fun validate(file: File, partitionSize: Long, expectedSha256: String? = null): ImageRef {
        MigrationFailure.require(file.isFile, MigrationCodes.CANDIDATE_LENGTH_INVALID, "missing ${file.name}")
        MigrationFailure.require(
            file.length() == partitionSize,
            MigrationCodes.CANDIDATE_LENGTH_INVALID,
            "${file.length()} != $partitionSize",
        )
        val sha = MigrationHashes.sha256(file)
        if (expectedSha256 != null) {
            MigrationFailure.require(
                sha == expectedSha256.lowercase(),
                MigrationCodes.CANDIDATE_LENGTH_INVALID,
                "sha mismatch",
            )
        }
        return ImageRef(file.name, file.length(), sha, ImageSource.CANDIDATE)
    }

    fun validateTail(plan: MigrationPlan, name: String, file: File): String {
        val entry = plan.partition(name)
        val expectedSize = entry.final?.size ?: entry.pre.size
        MigrationFailure.require(
            file.length() == expectedSize,
            MigrationCodes.CANDIDATE_LENGTH_INVALID,
            name,
        )
        return MigrationHashes.tailSha256(file)
    }
}
