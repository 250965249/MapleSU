package dev.maplesu.manager.workmode.superuser

import java.io.File

/**
 * 真机撤回实现（W19）：按 [ImplantIntent] 生成**幂等** root 脚本并执行。
 *
 * 恢复语义（不做不可逆覆盖）：
 * - `DELIVERY`：原件存在 → 恢复原件；原本不存在 → 删除我们新增的 `su` 镜像；
 * - `WIRING`：恢复被 DT_NEEDED 修改的原库（原件 + uid/gid/mode + label），并删除
 *   root 拥有的 side library（上游随机命名，特征 = root:root 的 `lib*`）；
 * - `PATH_INJECTION`：瞬态修改，进程重启即消失；脚本只回执，不写任何东西；
 * - 统一清理我们新建的空目录（非空不删）。
 *
 * SELinux label 统一回 `apk_data_file`（目标 App 的 lib 目录语义）；具体 type 的真实
 * 兼容性需设备验证（报告"仍需设备验证项"）。
 */
class ScriptImplantReverter(private val runner: RootScriptRunner) : ImplantReverter {

    override fun revert(intent: ImplantIntent): Boolean {
        if (intent.kind == ImplantKinds.PATH_INJECTION || intent.pathInjection) {
            // 无持久修改：直接回执（幂等）。
            return runCatching { runner.run("set -eu\n/system/bin/printf 'REVERTED\\n'").code == 0 }
                .getOrDefault(false)
        }
        val target = if (intent.kind == ImplantKinds.WIRING) {
            intent.wiringTargetLib ?: return false
        } else {
            intent.deliverPath
        }
        val restore = if (intent.originalAbsent) {
            LiteImplantScripts.removeTarget(target)
        } else {
            // 无 backupPath 的旧记录不可安全恢复（originals 根目录未知）→ fail closed。
            val backup = intent.originalBackupPath ?: return false
            LiteImplantScripts.restoreOriginal(
                backupPath = backup,
                targetPath = target,
                sha256 = intent.originalSha256 ?: intent.wiringOriginalSha256,
                uid = intent.originalUid,
                gid = intent.originalGid,
                mode = intent.originalMode,
            )
        }
        val scripts = mutableListOf(restore)
        if (intent.kind == ImplantKinds.WIRING) {
            scripts += LiteImplantScripts.removeSideLibraries(File(target).parent ?: "")
        }
        if (intent.createdDirs.isNotEmpty()) {
            scripts += LiteImplantScripts.cleanupCreatedDirs(intent.createdDirs)
        }
        val result = runCatching { runner.run(scripts.joinToString("\n")) }
            .getOrElse { return false }
        return result.code == 0
    }
}

/**
 * 撤回前的一致性检查（纯函数；供 hooks/诊断使用）：
 * 返回 null = 可撤回；否则返回阻断码。
 */
object ImplantRestoreEvidence {
    fun blockingCode(intents: List<ImplantIntent>, store: OriginalBackupStore): String? =
        if (intents.all { store.hasOriginal(it) }) null else LiteImplantCodes.IMPLANT_RESTORE_MISSING
}
