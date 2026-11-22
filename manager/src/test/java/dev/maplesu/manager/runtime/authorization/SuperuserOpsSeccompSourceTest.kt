package dev.maplesu.manager.runtime.authorization

import java.io.File
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Static guard for the P0 seccomp fix (2026-10-31).
 *
 * <p>The crash was not a logic bug in the transaction; it was the root tool creating a
 * system `Context`. `ActivityThread.systemMain()` builds `Resources`, which makes the
 * framework fork `idmap2` through `ExecuteBinary`; that child calls `setgid`, and the
 * App's inherited seccomp filter kills it with `SIGSYS` (`syscall 144`). The App forks
 * every privileged child, so the filter cannot be removed there. The only durable fix on
 * this route is to keep that initialization out of the tool.
 *
 * <p>These tests are source-level because the failure is a dynamic one: a host unit test
 * cannot run `app_process`, and a device test would only prove today's device. A source
 * scan fails the build if the context-creation code comes back, exactly like
 * `L3AbiSourceTest` guards the native gate.
 */
class SuperuserOpsSeccompSourceTest {

    private val managerDir: File = sequenceOf(
        File("."), File("manager"), File("../manager"),
    ).map { it.absoluteFile.normalize() }
        .firstOrNull { File(it, "src/main/java").isDirectory }
        ?: error("cannot locate the manager module from " + File(".").absolutePath)

    private val authorization = File(
        managerDir,
        "src/main/java/dev/maplesu/manager/runtime/authorization",
    )
    private val rootOps = File(authorization, "SuperuserOps.kt")
    private val tool = File(authorization, "AuthorizationTool.kt")
    private val control = File(authorization, "SuperuserControl.kt")
    private val direct = File(authorization, "DirectPolicy.kt")
    private val identities = File(authorization, "PackageIdentityReader.kt")
    private val native = File(managerDir, "src/main/cpp/maplesu_su.c")

    private fun text(file: File): String = file.readText(Charsets.UTF_8)

    /**
     * Remove block and line comments so the guard checks executable references, not the
     * explanatory text that has to name the old crash. The sources here contain no
     * string literal containing a comment marker, so this is exact for the files under
     * test.
     */
    private fun codeOnly(body: String): String = body
        .replace(Regex("/\\*.*?\\*/", RegexOption.DOT_MATCHES_ALL), "")
        .lineSequence()
        .joinToString("\n") { line -> line.substringBefore("//") }

    // --- the root tool itself ------------------------------------------------

    @Test
    fun `the root tool has no executable reference to a system context`() {
        for (file in listOf(rootOps, tool)) {
            val code = codeOnly(text(file))
            for (forbidden in listOf(
                "systemContext",
                "ActivityThread",
                "android.content.Context",
                "createDeviceProtectedStorageContext",
                "Looper.prepareMainLooper",
            )) {
                assertFalse(
                    "${file.name} must not execute $forbidden; that is the path that " +
                        "forks idmap and dies on seccomp",
                    code.contains(forbidden),
                )
            }
        }
    }

    @Test
    fun `the root tool reads identities and audit through context-free seams`() {
        val code = codeOnly(text(rootOps))
        assertTrue(
            "identities must come from the package service, not a Context-bound PackageManager",
            code.contains("SystemPackageSnapshotSource"),
        )
        assertTrue(
            "the shared identity rule must be reused, not re-implemented",
            code.contains("PackageIdentityReader"),
        )
        assertTrue(
            "the audit append must take the caller's explicit path",
            code.contains("SuAuditLog.write("),
        )
        assertTrue("the audit path is the tool's third argument", code.contains("auditFile"))
    }

    @Test
    fun `the root tool reports its inherited seccomp mode for device evidence`() {
        val code = codeOnly(text(rootOps))
        assertTrue(
            "status must carry the /proc/self/status Seccomp value so acceptance can " +
                "show the filter is still inherited",
            code.contains("/proc/self/status") && code.contains("Seccomp:"),
        )
    }

    // --- both command builders ----------------------------------------------

    @Test
    fun `both command builders pass a device-protected audit path explicitly`() {
        for (file in listOf(control)) {
            val code = codeOnly(text(file))
            assertTrue(
                "${file.name} must bind the audit file with SuAuditLog.file(application)",
                code.contains("SuAuditLog.file(application).absolutePath"),
            )
            assertTrue(
                "${file.name} must pass the audit path after the legacy path",
                code.contains("append(quote(legacy)).append(' ')") &&
                    code.contains("append(quote(audit)).append(' ')"),
            )
        }
        val compatibility = codeOnly(text(direct))
        assertTrue("DirectPolicy must share the transport and command builder",
            compatibility.contains("SuperuserControl.runTool(context, *arguments)"))
        assertFalse("DirectPolicy must not create a second direct-only path",
            compatibility.contains("DirectRoot.run("))
    }

    @Test
    fun `the control path maps a SIGSYS death to the named code`() {
        val code = codeOnly(text(control))
        assertTrue(
            "SuperuserControl must classify the child result through RootToolOutcome",
            code.contains("RootToolOutcome.parse("),
        )
        assertTrue(
            "the named seccomp failure must reach the Result code",
            code.contains("outcome.code") &&
                code.contains("Result.failure(outcome.code)"),
        )
        assertTrue(
            "SU_PRIVILEGED_PATH_SECCOMP_BLOCKED must stay in the source of truth",
            codeOnly(text(File(authorization, "RootToolOutcome.kt")))
                .contains("SuCodes.SU_PRIVILEGED_PATH_SECCOMP_BLOCKED"),
        )
    }

    // --- the native contract that produces 128+signal -----------------------

    @Test
    fun `the native client reports signal deaths as 128 plus the signal`() {
        val body = text(native)
        assertTrue("a signalled child must never look like exit 0",
            body.contains("WIFSIGNALED(status)"))
        assertTrue("the Kotlin 159 classification depends on this exact spelling",
            body.contains("128 + WTERMSIG(status)"))
        assertTrue("the streaming reaper is the Ultra transport's only exit source",
            body.contains("Java_dev_maplesu_manager_runtime_NativeSu_reapStreaming"))
    }

    @Test
    fun `the tool usage documents the audit argument`() {
        val body = text(tool)
        assertTrue(
            "the usage comment must match the argv the builders emit",
            body.contains("<managerUid> <legacyFile> <auditFile> <op>"),
        )
    }
}
