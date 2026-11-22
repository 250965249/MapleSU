package dev.maplesu.manager.jailbreak

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import me.yuki.fina.adbroot.core.KernelCatalog
import me.yuki.fina.adbroot.core.KernelEngine
import me.yuki.fina.adbroot.core.KernelMap
import me.yuki.fina.adbroot.core.KernelProfile
import me.yuki.fina.adbroot.core.KernelProfiles
import me.yuki.fina.adbroot.core.KernelResolution
import me.yuki.fina.adbroot.core.Manager
import me.yuki.fina.adbroot.core.Payload
import me.yuki.fina.adbroot.core.Shell
import me.yuki.fina.adbroot.core.ShizukuShell
import me.yuki.fina.adbroot.flow.Device
import me.yuki.fina.adbroot.flow.RootFlow
import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/** The retained source owns acquisition; the existing bootstrap owns the backend. */
internal object MapleSu93260Attempt {
    fun run(context: Context, request: JailbreakRequest, cancelled: () -> Boolean) {
        val boot = request.bootId ?: throw IOException("MAPLESU_93260_BOOT_ID_MISSING")
        if (boot != DirtyfragAttempt.readBootId()) throw IOException("MAPLESU_93260_BOOT_CHANGED")
        /*
         * Automatic kernel dispatch: the running `uname -r` is resolved against
         * the catalog this APK carries. Only an exact, packaged profile may bind
         * the kernel addresses; a recognised-but-unpackaged build and an unknown
         * build both fail closed with their own token.
         */
        val catalog = runCatching { Payload.catalog(context) }
            .getOrElse { KernelCatalog.builtIn() }
        val resolution = KernelProfiles.resolve(android.system.Os.uname().release, catalog)
        val profile = when (resolution) {
            is KernelResolution.Packaged -> resolution.profile
            else -> throw IOException(resolution.failureToken ?: "MAPLESU_93260_KERNEL_UNSUPPORTED")
        }
        /*
         * Only the retained engine binds link-time addresses here. A plant
         * profile carries its own tables inside the executable and must never touch
         * KernelMap; both engines still end in the same handover batch below.
         */
        if (profile.engine == KernelEngine.RETAINED &&
            !KernelMap.bind(profile, resolution.release.raw))
            throw IOException("MAPLESU_93260_PROFILE_BIND_FAILED")
        if (request.rootBackend !in setOf(JailbreakRequest.BACKEND_KSU, JailbreakRequest.BACKEND_HOOK))
            throw IOException("MAPLESU_93260_BACKEND_UNSUPPORTED")
        if (!request.attemptId.matches(Regex("[A-Za-z0-9._-]{4,63}")))
            throw IOException("MAPLESU_93260_ATTEMPT_INVALID")
        runCatching {
            JailbreakDiagnostics.progress(context.filesDir, request, "source",
                "设备=" + runCatching { com.maplesu.core.ui.util.resolveDeviceName() }
                    .getOrDefault(profile.models.firstOrNull() ?: "未知") +
                    " 内核=" + resolution.release.raw + " " + resolution.describe())
        }
        ShizukuAccess.requireReady()
        DirtyfragAttempt.requireUnusedKernelWindow(context)
        val directory = DirtyfragAttempt.attemptDirectory(context)
        val consumed = File(directory, "maplesu-93260-boot")
        if (consumed.isFile && consumed.readText().trim() == boot)
            throw IOException("MAPLESU_93260_REBOOT_REQUIRED")
        val payload = Payload.ensure(context, profile)
        GhostlockHandover.stage(context, request)
        val receipt = File(directory, "maplesu-93260-source.json")
        receipt.writeText("")
        android.system.Os.chmod(receipt.path, 384)
        val raw = ShizukuShell()
        fun checkActive() {
            if (cancelled() || Thread.currentThread().isInterrupted) throw IOException("JAILBREAK_CANCELLED")
        }
        val shell = object : Shell {
            override fun isAvailable() = raw.isAvailable()
            override suspend fun exec(cmd: String, timeoutMs: Long): me.yuki.fina.adbroot.core.ExecResult {
                checkActive()
                return raw.exec(cmd, timeoutMs).also { checkActive() }
            }
            override suspend fun push(local: File, remote: String): Boolean {
                checkActive()
                return raw.push(local, remote).also { checkActive() }
            }
        }
        var dispatched = false
        try {
            runBlocking(Dispatchers.IO) {
                withTimeout(TimeUnit.SECONDS.toMillis(JailbreakRequest.MAPLESU_93260_TIMEOUT_SECONDS)) {
                    val observation = shell.exec("uname -r; cat /proc/sys/kernel/random/boot_id; getenforce; id", 10_000)
                    val lines = observation.stdout.lines().map(String::trim)
                    if (!observation.ok || lines.getOrNull(0) != resolution.release.raw || lines.getOrNull(1) != boot)
                        throw IOException("MAPLESU_93260_SHIZUKU_TARGET_MISMATCH")
                    val entry = when (lines.getOrNull(2)) {
                        "Enforcing" -> 1
                        "Permissive" -> 0
                        else -> throw IOException("MAPLESU_93260_ENTRY_UNOBSERVED")
                    }
                    if (!HookEnv.write(directory, request.attemptId, boot, entry))
                        throw IOException("MAPLESU_93260_HOOK_ENV_UNWRITABLE")
                    JailbreakDiagnostics.progress(context.filesDir, request, "source", observation.text)
                    if (request.rootBackend == JailbreakRequest.BACKEND_HOOK && entry == 1) {
                        runCatching {
                            val status = shell.exec("od -An -v -tu4 -N20 /sys/fs/selinux/status", 5_000)
                            check(status.ok) { "JAILBREAK_SELINUX_SHELL_STATUS_READ" }
                            JailbreakSelinuxHide.captureShizuku(context, request, status.stdout)
                        }.onFailure { error ->
                            android.util.Log.w("MapleSUSELinux", "Pre-entry Shizuku status capture failed", error)
                            JailbreakDiagnostics.progress(context.filesDir, request, "selinux",
                                "Pre-entry snapshot failed: " + (error.message ?: error.javaClass.simpleName))
                        }
                    }
                    if (profile.engine == KernelEngine.PLANT) {
                        runPortedPlant(context, request, shell, profile, payload, receipt, entry,
                            cancelled,
                            onCredits = {
                                consumed.writeText(boot + "\n")
                                DirtyfragAttempt.markKernelWindow(context, boot)
                            },
                            onDispatched = { dispatched = true }) { message ->
                            JailbreakDiagnostics.progress(context.filesDir, request, "source", message)
                        }
                    } else {
                        // Same manager check as upstream, directed at this installed package.
                        val manager = Manager("maplesu", "MapleSU", context.packageName, KernelMap.KERNEL_UAPI,
                            "", 0L, "", "", 0L)
                        val flow = RootFlow(context, shell, manager, handover = {
                            checkActive()
                            JailbreakDiagnostics.progress(context.filesDir, request, "handover",
                                "来源提权完成，开始共享接管：backend=${request.rootBackend}")
                            val batchFile = File(context.cacheDir, "maplesu-93260-${request.attemptId}.sh")
                            try {
                                batchFile.writeText(batch(context, request, receipt, entry))
                                val remote = "${Device.CHAN}/maplesu-93260-${request.attemptId}"
                                if (!shell.push(batchFile, remote)) throw IOException("MAPLESU_93260_HANDOVER_PUSH_FAILED")
                                checkActive()
                                val launchFailure = AtomicReference<String?>(null)
                                dispatched = true
                                // Module initialization can stall Shizuku. Only private receipts
                                // are awaited after this one-way dispatch.
                                Thread({
                                    runCatching {
                                        val launch = runBlocking { raw.exec("mv '$remote' '${Device.CHAN}/run' && " +
                                            "{ (echo x > '${Device.CHAN}/wake') >/dev/null 2>&1 & }", 10_000) }
                                        if (!launch.ok) launchFailure.set(launch.text)
                                    }.onFailure { launchFailure.set(it.message) }
                                }, "maplesu-93260-dispatch").apply { isDaemon = true; start() }
                                awaitHandover(context, request, receipt, entry, cancelled, launchFailure) { message ->
                                    JailbreakDiagnostics.progress(context.filesDir, request, "handover", message)
                                }
                                true
                            } finally { batchFile.delete() }
                        })
                        flow.log = { message ->
                            checkActive()
                            JailbreakDiagnostics.progress(context.filesDir, request, "source", message)
                            if (message.startsWith("[2/6]")) {
                                consumed.writeText(boot + "\n")
                                DirtyfragAttempt.markKernelWindow(context, boot)
                            }
                        }
                        if (!flow.run(payload)) throw IOException("MAPLESU_93260_SOURCE_FAILED:reboot required")
                    }
                }
            }
        } catch (error: Exception) {
            if (error is kotlinx.coroutines.TimeoutCancellationException)
                throw IOException("MAPLESU_93260_SOURCE_TIMEOUT", error)
            if (error.message?.startsWith("GHOSTLOCK_") == true)
                throw IOException(error.message!!.replaceFirst("GHOSTLOCK_", "MAPLESU_93260_"), error)
            throw error
        } finally {
            // The binding is per-attempt state; a later attempt resolves its own.
            KernelMap.reset()
            if (!dispatched && consumed.isFile && consumed.readText().trim() == boot) {
                // Never destroy or reap credential anchors. A full reboot releases them.
                Thread({ runCatching { runBlocking { raw.exec(
                    "for n in louise tpd_calib timer98260; do for p in ${'$'}(pidof ${'$'}n); do kill -STOP ${'$'}p; done; done", 10_000)
                } } }, "maplesu-93260-park").apply { isDaemon = true; start() }
            }
        }
    }

    /**
     * The shared tail of both engines: wait for the batch's private receipt, then
     * require the bound shared-handover receipt. Nothing here depends on which
     * engine produced the root context.
     */
    private suspend fun awaitHandover(context: Context, request: JailbreakRequest, receipt: File,
                                      entry: Int, cancelled: () -> Boolean,
                                      launchFailure: AtomicReference<String?>,
                                      progress: (String) -> Unit) {
        val normalHandover = if (request.rootBackend == JailbreakRequest.BACKEND_KSU)
            File(DirtyfragAttempt.hookEvidence(context), "maplesu-handover.json") else null
        awaitSourceReceipt(receipt, request, entry, cancelled, launchFailure,
            readNormalHandover = normalHandover?.let { file ->
                { runCatching { file.readText() }.getOrNull() }
            }, restoreNormal = {
                dev.maplesu.manager.workmode.backend.KsuBackendRegistry.runNormalHandoverCommand(
                    context, request, "[ \"${'$'}(cat /sys/fs/selinux/enforce)\" = 1 ] || " +
                        "{ echo 1 > /sys/fs/selinux/enforce && " +
                        "[ \"${'$'}(cat /sys/fs/selinux/enforce)\" = 1 ]; }")
            }, progress = progress)
        GhostlockHandover.requireReceipt(context, request)
        progress("来源流程与共享接管已确认，开始管理器接管校验")
    }

    /**
     * Plant engine: run our per-kernel plant (built from the retained offset
     * tables) and let its fake-cred
     * child execute the *retained* handover batch as root.
     *
     * The plant normally calls `ksud late-load` through `system()` from that
     * child. `PYB110_KSUD` replaces that one command with [PLANT_WRAPPER], which
     * execs the batch - so the escalation, the SELinux window, the handover and
     * the receipt are exactly the ones the 98260 mode already verifies. The
     * plant is never asked to late-load anything itself and its manager
     * finishing code never runs (we only start its plant stage).
     */
    private suspend fun runPortedPlant(
        context: Context,
        request: JailbreakRequest,
        shell: Shell,
        profile: KernelProfile,
        payloadDir: File,
        receipt: File,
        entry: Int,
        cancelled: () -> Boolean,
        onCredits: () -> Unit,
        onDispatched: () -> Unit,
        progress: (String) -> Unit,
    ) {
        val dir = "${Device.TMP}/maplesu-93260"
        val prepared = shell.exec(
            "rm -rf $dir; mkdir -p $dir; chmod 700 $dir; echo PLANT_DIR_READY", 15_000)
        if (!prepared.ok || !prepared.text.contains("PLANT_DIR_READY"))
            throw IOException("MAPLESU_93260_PLANT_STAGE_FAILED")
        val batchFile = File(context.cacheDir, "maplesu-93260-${request.attemptId}.sh")
        val wrapperFile = File(context.cacheDir, "maplesu-93260-src-${request.attemptId}.sh")
        try {
            // The wrapper exports the symbol snapshot only when its own dump is
            // readable, so the batch must not set it unconditionally here.
            batchFile.writeText(batch(context, request, receipt, entry, kallsymsEnv = false))
            wrapperFile.writeText(PLANT_WRAPPER.replace("__BATCH__", "$dir/batch.sh"))
            val plant = File(payloadDir, Payload.RUNNER)
            if (!plant.isFile) throw IOException("MAPLESU_93260_PAYLOAD_PROFILE_MISSING:" + profile.id)
            if (!shell.push(batchFile, "$dir/batch.sh")) throw IOException("MAPLESU_93260_PLANT_PUSH_FAILED:batch")
            if (!shell.push(wrapperFile, "$dir/src.sh")) throw IOException("MAPLESU_93260_PLANT_PUSH_FAILED:wrapper")
            if (!shell.push(plant, "$dir/plant")) throw IOException("MAPLESU_93260_PLANT_PUSH_FAILED:plant")
            val staged = shell.exec(
                "chmod 755 $dir/plant $dir/src.sh; " +
                    "[ -x $dir/plant ] && [ -s $dir/batch.sh ] && echo PLANT_STAGED", 15_000)
            if (!staged.ok || !staged.text.contains("PLANT_STAGED"))
                throw IOException("MAPLESU_93260_PLANT_STAGE_FAILED")
            onDispatched()
            val started = shell.exec(
                "cd $dir && PYB110_KSUD=$dir/src.sh " +
                    "PYB110_MANAGER_PKG=${context.packageName} " +
                    "PYB110_KMI=${profile.kmi} PYB110_FILES_DIR=$dir " +
                    "setsid sh -c 'nohup ./plant --auto > $dir/plant.log 2>&1 < /dev/null &' ; " +
                    "echo PLANT_STARTED", 30_000)
            if (!started.ok || !started.text.contains("PLANT_STARTED"))
                throw IOException("MAPLESU_93260_PLANT_START_FAILED")
            progress("内核 plant 已启动（${profile.runner} · ${profile.kmi}）")
            /*
             * The plant prints PLANT_CRED_OK after the fake cred landed; only then
             * can the batch inside the child make progress. There is no failure
             * receipt before that point, so this wait is bounded like the plant's own
             * 330 s cred window.
             */
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(330)
            var credits = false
            while (!credits) {
                if (cancelled() || Thread.currentThread().isInterrupted)
                    throw IOException("JAILBREAK_CANCELLED")
                val tail = shell.exec("tail -n 60 $dir/plant.log 2>/dev/null", 10_000).stdout
                if (tail.contains("PLANT_CRED_OK")) {
                    credits = true
                    onCredits()
                    progress("plant 提权上下文已建立；开始共享接管")
                    break
                }
                if (tail.contains("PLANT_FAIL") || tail.contains("FAIL=") ||
                    tail.contains("cred leak failed")) {
                    throw IOException("MAPLESU_93260_PLANT_CRED_FAILED")
                }
                val alive = shell.exec(
                    "ps -A -o NAME 2>/dev/null | " +
                        "grep -Eq 'plant|t98260-hold|child-(load|hold)' && echo ALIVE || echo GONE",
                    10_000).stdout
                if (alive.contains("GONE") && !tail.contains("PLANT_CRED_OK"))
                    throw IOException("MAPLESU_93260_PLANT_EXITED")
                if (System.nanoTime() >= deadline) throw IOException("MAPLESU_93260_PLANT_TIMEOUT")
                kotlinx.coroutines.delay(1_000)
            }
            awaitHandover(context, request, receipt, entry, cancelled,
                AtomicReference<String?>(null), progress)
        } finally {
            batchFile.delete()
            wrapperFile.delete()
        }
    }

    /**
     * Executed by the plant's fake-cred child instead of ksud. Both call shapes
     * (`late-load ...` and `debug extract-binary ...`) are the same root context;
     * the batch ignores the arguments, and it deliberately never creates the
     * extracted-KO path, so a hooks-gated plant skips its own load step.
     *
     * The retained engine ships a per-build symbol snapshot; a plant profile does
     * not. This wrapper therefore dumps `/proc/kallsyms` *from the root context*
     * and hands it to the patched ksud only when the dump proves readable. When
     * the vendor still hides addresses (`kptr_restrict=2`), nothing is exported:
     * the ksud keeps its own `/proc/kallsyms` fallback and the handover fails with
     * its normal token instead of being fed an all-zero table.
     */
    private val PLANT_WRAPPER = """
        #!/system/bin/sh
        export PATH=/system/bin:/system/xbin:/vendor/bin
        rm -f ${Device.KALL}
        cat /proc/kallsyms > ${Device.KALL} 2>/dev/null
        if grep -Eq '^[1-9a-f][0-9a-f]{15} [Tt] _text$' ${Device.KALL} 2>/dev/null; then
            export MAPLESU_KALLSYMS_PATH=${Device.KALL}
        else
            rm -f ${Device.KALL}
        fi
        exec /system/bin/sh __BATCH__ "${'$'}@"
    """.trimIndent() + "\n"

    internal fun awaitSourceReceipt(file: File, request: JailbreakRequest, entry: Int,
                                    cancelled: () -> Boolean, launchFailure: AtomicReference<String?>,
                                    timeoutMillis: Long = 300_000,
                                    readNormalHandover: (() -> String?)? = null,
                                    restoreNormal: () -> Boolean = { false },
                                    progress: (String) -> Unit = {}) {
        val started = System.nanoTime()
        val deadline = started + TimeUnit.MILLISECONDS.toNanos(timeoutMillis)
        var nextProgress = started
        while (System.nanoTime() < deadline) {
            if (cancelled() || Thread.currentThread().isInterrupted) throw IOException("JAILBREAK_CANCELLED")
            val text = runCatching { file.readText() }.getOrNull()
            if (text != null && runCatching { JSONObject(text) }.isSuccess) {
                sourceRefusal(text, request, entry)?.let { throw IOException(it) }
                progress("来源收尾回执已收到；SELinux=$entry；耗时=${TimeUnit.NANOSECONDS.toSeconds(System.nanoTime() - started)}s")
                return
            }
            // Normal's late-load may finish before the source dispatcher returns.
            // Its bound shared receipt plus a real KSU restore replaces that exit wait;
            // the Provider still proves SU and persists DAEMON_READY afterwards.
            if (request.rootBackend == JailbreakRequest.BACKEND_KSU && readNormalHandover != null) {
                val shared = readNormalHandover()
                if (shared != null && runCatching { JSONObject(shared) }.isSuccess) {
                    GhostlockHandover.refusal(shared, request)?.let { throw IOException(it) }
                    if (restoreNormal()) {
                        if (cancelled() || Thread.currentThread().isInterrupted)
                            throw IOException("JAILBREAK_CANCELLED")
                        val finalSource = runCatching { file.readText() }.getOrNull()
                        if (finalSource != null && runCatching { JSONObject(finalSource) }.isSuccess)
                            sourceRefusal(finalSource, request, entry)?.let { throw IOException(it) }
                        progress("Normal 共享接管与 SELinux 恢复已确认，继续管理器接管校验")
                        return
                    }
                }
            }
            val now = System.nanoTime()
            if (now >= nextProgress) {
                if (request.rootBackend == JailbreakRequest.BACKEND_KSU && readNormalHandover != null)
                    progress("正在完成 Normal 接管；将重启管理器以激活模式")
                else progress("等待来源收尾回执：${TimeUnit.NANOSECONDS.toSeconds(now - started)}s；文件=${text?.toByteArray()?.size ?: -1} bytes")
                nextProgress = now + TimeUnit.SECONDS.toNanos(5)
            }
            try { Thread.sleep(100) } catch (error: InterruptedException) {
                Thread.currentThread().interrupt()
                throw IOException("JAILBREAK_CANCELLED", error)
            }
        }
        progress("来源收尾回执等待超时；派发=${launchFailure.get() ?: "未报告错误"}")
        throw IOException(launchFailure.get()?.let { "MAPLESU_93260_DISPATCH_FAILED:$it" }
            ?: "MAPLESU_93260_HANDOVER_TIMEOUT")
    }

    internal fun sourceRefusal(text: String, request: JailbreakRequest, entry: Int): String? = runCatching {
        val result = JSONObject(text)
        when {
            result.getString("schema") != "maplesu.93260.source.v1" ||
                result.getString("provider") != request.method ||
                result.getString("bootId") != request.bootId ||
                result.getString("attempt") != request.attemptId -> "MAPLESU_93260_SOURCE_BINDING_MISMATCH"
            result.getInt("enforcingBefore") != entry || result.getInt("enforcingFinal") !=
                (if (request.rootBackend == JailbreakRequest.BACKEND_KSU && result.getInt("exitCode") == 0) 1 else entry) ->
                "MAPLESU_93260_RESTORE_FAILED"
            result.getInt("exitCode") != 0 -> "MAPLESU_93260_HANDOVER_FAILED:${result.getInt("exitCode")}"
            else -> null
        }
    }.getOrElse { "MAPLESU_93260_SOURCE_EVIDENCE_INVALID" }

    internal fun batch(context: Context, request: JailbreakRequest, receipt: File, entry: Int,
                       kallsymsEnv: Boolean = true): String {
        return batch(context.filesDir.parentFile!!, request, receipt, entry, kallsymsEnv)
    }

    internal fun batch(home: File, request: JailbreakRequest, receipt: File, entry: Int,
                       kallsymsEnv: Boolean = true): String {
        fun quote(value: String) = "'" + value.replace("'", "'\\''") + "'"
        val helper = quote(File(home, "bs").path)
        val ksud = quote(File(home, "ksud").path)
        val target = if (request.rootBackend == JailbreakRequest.BACKEND_HOOK) "ultra" else "normal"
        /*
         * The retained engine always has its snapshot. The plant engine does not:
         * its wrapper dumps /proc/kallsyms from the fake-cred root context and
         * exports this same variable only when the dump proves readable, so the
         * patched ksud keeps its own /proc/kallsyms fallback otherwise.
         */
        val kallsyms = if (kallsymsEnv) "export MAPLESU_KALLSYMS_PATH=${Device.KALL}\n" else ""
        return """
            #!/system/bin/sh
            export PATH=/system/bin:/system/xbin
            export ANDROID_DATA=/data ANDROID_ROOT=/system ANDROID_RUNTIME_ROOT=/apex/com.android.runtime
            DISPATCHER=${'$'}PPID
            ENTRY=$entry
            FINAL=-1
            WINDOW=0
            RECEIPT_OPEN=0
            finish() {
                CODE=${'$'}?
                trap - EXIT HUP INT TERM
                if [ "${'$'}WINDOW" = 1 ]; then
                    RESTORE=${'$'}ENTRY
                    # Successful Normal late-load ends enforcing, as KernelSU does.
                    if [ '$target' = normal ] && [ "${'$'}CODE" = 0 ]; then RESTORE=1; fi
                    # Android mksh has an echo builtin, but printf is an external
                    # program. No new executable may be needed after restoration.
                    echo "${'$'}RESTORE" >&8
                    # selinuxfs returns one byte without a newline. read can set
                    # FINAL and return 1 at EOF; validate its value separately.
                    IFS= read -r FINAL <&9 || :
                    case "${'$'}FINAL" in 0|1) ;; *) FINAL=-1 ;; esac
                fi
                if [ "${'$'}RECEIPT_OPEN" = 1 ]; then
                    echo '{"schema":"maplesu.93260.source.v1","provider":"maplesu_93260","bootId":"${request.bootId}","attempt":"${request.attemptId}","exitCode":'"${'$'}CODE"',"enforcingBefore":'"${'$'}ENTRY"',"enforcingFinal":'"${'$'}FINAL"'}' >&7
                    exec 7>&-
                fi
                kill -STOP "${'$'}DISPATCHER"
            }
            trap finish EXIT
            trap 'exit 130' HUP INT TERM
            [ "${'$'}(cat /proc/sys/kernel/random/boot_id)" = '${request.bootId}' ] || exit 64
            CURRENT=${'$'}(cat /sys/fs/selinux/enforce)
            case "${'$'}CURRENT" in 0|1) ;; *) exit 64 ;; esac
            exec 8>/sys/fs/selinux/enforce || exit 67
            exec 9</sys/fs/selinux/enforce || exit 67
            WINDOW=1
            printf 0 >&8 || exit 67
            # Open App data while the source's kernel domain has access. The
            # descriptor remains open through the shared helper's restoration.
            exec 7>${quote(receipt.path)} || exit 68
            RECEIPT_OPEN=1
            [ "${'$'}(cat /sys/fs/selinux/enforce)" = 0 ] || exit 67
            id
            grep -E '^(Uid|Gid|Cap|Seccomp)' /proc/self/status
            cat /proc/self/attr/current
            $kallsyms            $helper --handover --target $target --phase pre --attempt '${request.attemptId}' --boot '${request.bootId}' --entry-enforcing $entry --ksud $ksud
            exit ${'$'}?
        """.trimIndent() + "\n"
    }
}
