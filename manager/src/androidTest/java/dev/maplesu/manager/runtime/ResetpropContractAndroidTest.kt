package dev.maplesu.manager.runtime

import android.os.Bundle
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.util.concurrent.TimeUnit

/**
 * Real-device contract checks for MapleSU's bundled module tools.
 *
 * Shape mirrors the pinned KSU userspace, and each assertion below states which
 * upstream fact it is holding:
 *
 * - one host executable in `BINARY_DIR` (defs.rs:15)
 * - the host is written with ensure_binary semantics: unlink, write, chmod 0755
 *   (utils.rs ensure_binary)
 * - `resetprop` is a **symlink** to that host, republished every deploy
 *   (assets.rs:26-28)
 * - the host dispatches on `arg0.ends_with("resetprop")` (cli.rs:521-524)
 *
 * The resetprop CLI cases then exercise the reused upstream implementation, so a
 * flag or exit-code divergence is reported instead of normalized away. Every
 * written property is deleted at the end; no `persist.*` value is ever set.
 */
class ResetpropContractAndroidTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext

    /** Host entry packaged into the APK; tool names are symlinks to it. */
    private val hostSource get() = File(context.applicationInfo.nativeLibraryDir, "libmaplesu_tools.so")

    /**
     * Declared literally rather than imported from the main source set: the
     * instrumented APK does not receive main-set Kotlin symbols, so duplicating
     * the literal makes a production layout change fail this fixture loudly
     * instead of silently agreeing with itself.
     */
    private val binaryDir get() = "/data/adb/maplesu/bin"
    private val deployedProperty get() = File(binaryDir, "resetprop")

    private fun requireOptIn() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyMapleSuBoot") == "true")
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyResetprop") == "true")
    }

    private class Outcome(val code: Int, val out: List<String>, val err: List<String>) {
        val stdout get() = out.joinToString("\n")
        val stderr get() = err.joinToString("\n")
    }

    private fun run(vararg commands: String): Outcome {
        val result = MapleSuRuntime.openShell(context).use { shell ->
            shell.newJob().add(*commands).to(ArrayList<String>(), ArrayList<String>())
                .enqueue().get(60, TimeUnit.SECONDS)
        }
        return Outcome(result.code, result.out, result.err)
    }

    /**
     * Publishes the tools exactly the way the production path does: host written
     * by ensure_binary order, then `resetprop` symlinked to it. Kept as an explicit
     * Root script (not a call into main-set Kotlin) so this fixture also proves the
     * on-device result rather than trusting the production code to agree with itself.
     */
    private fun ensureDeployment() {
        val script = """
            set -eu
            test "${'$'}(/system/bin/id -u)" = 0
            base='$binaryDir'
            test ! -L "${'$'}base"
            /system/bin/mkdir -p "${'$'}base"
            /system/bin/chown 0:0 "${'$'}base"
            /system/bin/chmod 0755 "${'$'}base"
            host="${'$'}base/maplesu-tools"
            source='${hostSource.absolutePath}'
            test -f "${'$'}source"
            expected="${'$'}(/system/bin/sha256sum "${'$'}source" | /system/bin/cut -d ' ' -f 1)"
            current=none
            if [ -f "${'$'}host" ] && [ ! -L "${'$'}host" ]; then
                current="${'$'}(/system/bin/sha256sum "${'$'}host" | /system/bin/cut -d ' ' -f 1)"
            fi
            if [ "${'$'}current" != "${'$'}expected" ]; then
                /system/bin/rm -f "${'$'}host"
                /system/bin/cat "${'$'}source" > "${'$'}host"
                /system/bin/chown 0:0 "${'$'}host"
                /system/bin/chmod 0755 "${'$'}host"
                /system/bin/chcon u:object_r:system_file:s0 "${'$'}host"
            fi
            test "${'$'}(/system/bin/sha256sum "${'$'}host" | /system/bin/cut -d ' ' -f 1)" = "${'$'}expected"
            tool="${'$'}base/resetprop"
            /system/bin/rm -f "${'$'}tool"
            /system/bin/ln -s "${'$'}host" "${'$'}tool"
            test -L "${'$'}tool"
            /system/bin/printf 'HOST:%s\n' "${'$'}expected"
            /system/bin/printf 'LINK:%s\n' "${'$'}(/system/bin/readlink "${'$'}tool")"
            /system/bin/printf 'TOOL:%s\n' "${'$'}tool"
        """.trimIndent()
        val result = run(script)
        assertTrue("tool deployment failed: ${result.stderr}", result.code == 0)
    }

    /** Each case is a separate Root shell so one failure cannot mask the next. */
    private fun probe(name: String, vararg commands: String): JSONObject {
        val outcome = run(*commands)
        return JSONObject()
            .put("case", name)
            .put("code", outcome.code)
            .put("stdout", outcome.stdout)
            .put("stderr", outcome.stderr)
    }

    @Test(timeout = 300_000) fun bundledToolsUseKsuHostAndSymlinkShape() {
        requireOptIn()
        ensureDeployment()
        // Assertions run inside the Root shell, not through java.io.File: the test
        // process is an ordinary app UID and /data/adb is 0700 root, so a Java-side
        // stat would fail for reasons unrelated to the contract under test.
        val result = run(
            "set -eu",
            "test \"\$(/system/bin/id -u)\" = 0",
            "test -L '${deployedProperty.path}'",
            "/system/bin/printf 'SOURCE_SHA:%s\\n' \"\$(/system/bin/sha256sum '${hostSource.absolutePath}' | /system/bin/cut -d ' ' -f 1)\"",
            "/system/bin/printf 'HOST_PATH:%s\\n' '$binaryDir/maplesu-tools'",
            "/system/bin/printf 'HOST_SHA:%s\\n' \"\$(/system/bin/sha256sum '$binaryDir/maplesu-tools' | /system/bin/cut -d ' ' -f 1)\"",
            "/system/bin/printf 'LINK_TARGET:%s\\n' \"\$(/system/bin/readlink '${deployedProperty.path}')\"",
            "/system/bin/printf 'TOOL_MODE:%s\\n' \"\$(/system/bin/stat -c '%u:%g:%a' '$binaryDir/maplesu-tools')\"",
            "/system/bin/printf 'VERSION:%s\\n' \"\$('${deployedProperty.path}' --version 2>&1)\"",
            // The host must reject an unrecognized invocation name instead of
            // silently doing nothing.
            "set +e",
            "'$binaryDir/maplesu-tools' maplesu-unknown-tool >/dev/null 2>&1",
            "/system/bin/printf 'UNKNOWN_NAME_CODE:%s\\n' \"\$?\""
        )
        assertTrue(result.stderr, result.code == 0)
        fun field(name: String) = result.out.single { it.startsWith("$name:") }.substringAfter(':').trim()
        // Host bytes are the packaged APK entry, so the recorded build input also
        // identifies what the device runs.
        assertEquals(field("SOURCE_SHA"), field("HOST_SHA"))
        assertEquals("KSU publishes resetprop as a symlink to the host",
            field("HOST_PATH"), field("LINK_TARGET"))
        // stat -c '%u:%g:%a' -> "0:0:755"; compare the mode field only.
        assertEquals("755", field("TOOL_MODE").substringAfterLast(':'))
        assertTrue(field("VERSION"), field("VERSION").startsWith("resetprop"))
        assertNotEquals("an unknown tool name must not exit 0", 0, field("UNKNOWN_NAME_CODE").toInt())
        instrumentation.sendStatus(2, Bundle().apply {
            putString("resetpropDeployment", result.out.joinToString("\n"))
        })
    }

    @Test(timeout = 300_000) fun toolsAreNotObservableOutsideRootDataAdb() {
        requireOptIn()
        ensureDeployment()
        // Minimum-detection-point check: the tool tree must live where KSU keeps
        // its own, and nothing may be published under a world-traversable path.
        val result = run(
            "set -eu",
            "test \"\$(/system/bin/id -u)\" = 0",
            "/system/bin/printf 'BIN_DIR:%s\\n' '$binaryDir'",
            "/system/bin/printf 'BIN_OWNER:%s\\n' \"\$(/system/bin/stat -c '%u:%g:%a' '$binaryDir')\"",
            "/system/bin/printf 'WORK_OWNER:%s\\n' \"\$(/system/bin/stat -c '%u:%g:%a' '/data/adb/maplesu')\"",
            "set +e",
            "/system/bin/ls -d /dev/maplesu >/dev/null 2>&1",
            "/system/bin/printf 'DEV_MAPLESU_EXISTS:%s\\n' \"\$?\""
        )
        assertTrue(result.stderr, result.code == 0)
        fun field(name: String) = result.out.single { it.startsWith("$name:") }.substringAfter(':').trim()
        assertEquals("/data/adb/maplesu/bin", field("BIN_DIR"))
        // Root-only tree: 0700 on the parent is what makes the bin dir invisible
        // to non-Root callers even by absolute path.
        assertEquals("0:0:700", field("WORK_OWNER"))
        assertEquals("0:0:755", field("BIN_OWNER"))
        // The former /dev publication is gone: no product-named path remains there.
        assertEquals("1", field("DEV_MAPLESU_EXISTS"))
        instrumentation.sendStatus(2, Bundle().apply {
            putString("resetpropFootprint", result.out.joinToString("\n"))
        })
    }

    @Test(timeout = 600_000) fun cliContractMatchesPinnedReference() {
        requireOptIn()
        ensureDeployment()
        val tool = deployedProperty.path
        val cases = JSONArray()

        cases.put(probe("get-existing", "$tool ro.build.version.sdk"))
        cases.put(probe("get-missing", "$tool maplesu.absent.property.zz"))
        cases.put(probe("list", "$tool | /system/bin/head -3"))
        // Writes use `-n` (skip property_service). That is the upstream path module
        // `system.prop` loading uses (`load_system_prop_file` == `resetprop -n -f`),
        // because an arbitrary property name has no property_contexts entry and the
        // service therefore rejects it with -1. Verified on device: the plain form
        // fails with "__system_property_set failed: -1", which is correct upstream
        // behaviour and must not be papered over by a more permissive name.
        cases.put(probe("set-get-delete",
            "set +e",
            "$tool -n maplesu.resetprop.probe alpha",
            "/system/bin/printf 'SET_CODE:%s\\n' \"\$?\"",
            "/system/bin/printf 'GET:%s\\n' \"\$($tool maplesu.resetprop.probe 2>&1)\"",
            "$tool -d maplesu.resetprop.probe",
            "/system/bin/printf 'DELETE_CODE:%s\\n' \"\$?\"",
            "set +e",
            "$tool maplesu.resetprop.probe >/dev/null 2>&1",
            "/system/bin/printf 'AFTER_CODE:%s\\n' \"\$?\""))
        // The service-path write must fail this way rather than silently succeed.
        cases.put(probe("set-service-denied",
            "set +e",
            "$tool maplesu.resetprop.service alpha >/dev/null 2>&1",
            "/system/bin/printf 'SERVICE_SET_CODE:%s\\n' \"\$?\""))
        cases.put(probe("delete-missing", "$tool -d maplesu.absent.property.zz"))
        cases.put(probe("skip-svc-set",
            "set +e",
            "$tool -n maplesu.resetprop.skipsvc beta",
            "/system/bin/printf 'SKIPSVC_CODE:%s\\n' \"\$?\"",
            "/system/bin/printf 'SKIPSVC_GET:%s\\n' \"\$($tool maplesu.resetprop.skipsvc 2>&1)\"",
            "$tool -d maplesu.resetprop.skipsvc"))
        val propFile = File(context.noBackupFilesDir, "resetprop-fixture.prop")
        propFile.writeText("# comment line\n\nmaplesu.resetprop.file = delta \n")
        // `-n -f` is exactly what `load_system_prop_file` does for module
        // system.prop, so this case exercises the real module path.
        cases.put(probe("file-load",
            "set +e",
            "$tool -n -f '${propFile.absolutePath}'",
            "/system/bin/printf 'FILE_CODE:%s\\n' \"\$?\"",
            "/system/bin/printf 'FILE_GET:%s\\n' \"\$($tool maplesu.resetprop.file 2>&1)\"",
            "$tool -d maplesu.resetprop.file"))
        cases.put(probe("file-missing", "$tool -f '${context.noBackupFilesDir.absolutePath}/maplesu-no-such.prop'"))
        cases.put(probe("wait-present", "$tool -w ro.build.version.sdk"))
        cases.put(probe("wait-timeout",
            "set +e",
            // Options must precede positionals: the CLI sets trailing_var_arg, so
            // anything after the first positional argument becomes positional too.
            "$tool -w --timeout 0.2 maplesu.absent.property.zz",
            "/system/bin/printf 'TIMEOUT_CODE:%s\\n' \"\$?\""))
        cases.put(probe("wait-bad-timeout",
            "set +e",
            "$tool -w --timeout abc maplesu.absent.property.zz",
            "/system/bin/printf 'BAD_TIMEOUT_CODE:%s\\n' \"\$?\""))
        cases.put(probe("conflicting-modes",
            "set +e",
            "$tool -w -d ro.build.version.sdk",
            "/system/bin/printf 'CONFLICT_CODE:%s\\n' \"\$?\""))
        cases.put(probe("rebuild-with-set",
            "set +e",
            "$tool -c ro.build.version.sdk somevalue",
            "/system/bin/printf 'REBUILD_CONFLICT_CODE:%s\\n' \"\$?\""))
        cases.put(probe("persist-only",
            "set +e",
            "$tool -P ro.build.version.sdk >/dev/null 2>&1",
            "/system/bin/printf 'PERSIST_ONLY_CODE:%s\\n' \"\$?\""))
        cases.put(probe("help", "$tool --help | /system/bin/head -2"))
        cases.put(probe("version", "$tool --version"))
        cases.put(probe("unknown-flag",
            "set +e",
            "$tool --maplesu-unknown-flag ro.build.version.sdk >/dev/null 2>&1",
            "/system/bin/printf 'UNKNOWN_CODE:%s\\n' \"\$?\""))
        propFile.delete()
        // The probe properties must not survive this fixture.
        run("$tool -d maplesu.resetprop.probe", "$tool -d maplesu.resetprop.skipsvc",
            "$tool -d maplesu.resetprop.file")

        instrumentation.sendStatus(2, Bundle().apply {
            putString("resetpropContract", cases.toString())
        })

        fun get(name: String): JSONObject {
            for (index in 0 until cases.length()) {
                val item = cases.getJSONObject(index)
                if (item.getString("case") == name) return item
            }
            error("case $name was not recorded; recorded=$cases")
        }
        fun tail(name: String, code: String): Int {
            val line = get(name).getString("stdout").lineSequence().lastOrNull { it.startsWith("$code:") }
                ?: error("case $name produced no $code marker: ${get(name)}")
            return line.substringAfter(':').trim().toIntOrNull()
                ?: error("case $name produced unparsable $code: $line")
        }

        assertEquals("get-existing", 0, get("get-existing").getInt("code"))
        assertTrue("get-existing returned no value", get("get-existing").getString("stdout").isNotBlank())
        assertNotEquals("missing property must fail", 0, get("get-missing").getInt("code"))
        assertEquals("list", 0, get("list").getInt("code"))
        assertTrue("list form mismatch", get("list").getString("stdout").contains("]: ["))
        assertEquals("set must succeed through the direct-mmap path", 0, tail("set-get-delete", "SET_CODE"))
        assertTrue("set did not take effect",
            get("set-get-delete").getString("stdout").contains("GET:alpha"))
        assertEquals("delete must succeed", 0, tail("set-get-delete", "DELETE_CODE"))
        assertNotEquals("deleted property must not resolve", 0, tail("set-get-delete", "AFTER_CODE"))
        // A service-path write of an unregistered property name must be refused by
        // property_service, matching the observed upstream errno path.
        assertNotEquals("a service-path write of an unregistered name must fail", 0,
            tail("set-service-denied", "SERVICE_SET_CODE"))
        assertNotEquals("delete-missing must fail", 0, get("delete-missing").getInt("code"))
        assertEquals("skip-svc set must succeed", 0, tail("skip-svc-set", "SKIPSVC_CODE"))
        assertTrue("skip-svc value mismatch",
            get("skip-svc-set").getString("stdout").contains("SKIPSVC_GET:beta"))
        assertEquals("file load must succeed", 0, tail("file-load", "FILE_CODE"))
        assertTrue("file value mismatch",
            get("file-load").getString("stdout").contains("FILE_GET:delta"))
        assertNotEquals("missing file must fail", 0, get("file-missing").getInt("code"))
        assertEquals("wait-present", 0, get("wait-present").getInt("code"))
        assertEquals("wait timeout must be exit 2", 2, tail("wait-timeout", "TIMEOUT_CODE"))
        assertNotEquals("bad timeout must not be reported as a timeout", 2,
            tail("wait-bad-timeout", "BAD_TIMEOUT_CODE"))
        assertNotEquals("conflicting modes must fail", 0, tail("conflicting-modes", "CONFLICT_CODE"))
        assertNotEquals("rebuild with set must fail", 0, tail("rebuild-with-set", "REBUILD_CONFLICT_CODE"))
        assertNotEquals("persist-only must not read the live area", 0,
            tail("persist-only", "PERSIST_ONLY_CODE"))
        assertEquals("help", 0, get("help").getInt("code"))
        assertEquals("version", 0, get("version").getInt("code"))
        assertNotEquals("unknown flag must fail", 0, tail("unknown-flag", "UNKNOWN_CODE"))
    }
}
