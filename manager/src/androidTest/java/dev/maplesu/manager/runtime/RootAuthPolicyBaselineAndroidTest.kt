package dev.maplesu.manager.runtime

import android.os.Bundle
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.util.concurrent.TimeUnit

/** Read-only live-policy checks; never loads or restores a policy image. */
class RootAuthPolicyBaselineAndroidTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private val snapshot get() = File(context.noBackupFilesDir, "root-auth-policy-baseline.json")

    private fun observe(): JSONObject {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyMapleSuBoot") == "true")
        val marker = File(context.noBackupFilesDir, "root-auth-type-probe.rule")
        marker.writeText("allow maplesu_su_socket self unix_stream_socket getattr\n")
        val tool = File(context.applicationInfo.nativeLibraryDir, "libmaplesu_policy.so")
        val script = """
            set -eu
            test "${'$'}(/system/bin/id -u)" = 0
            test "${'$'}(/system/bin/getenforce)" = Enforcing
            /system/bin/printf 'BOOT_ID:'
            /system/bin/cat /proc/sys/kernel/random/boot_id
            /system/bin/printf 'POLICY_BEFORE:'
            /system/bin/sha256sum /sys/fs/selinux/policy
            /system/bin/printf 'ROOT_CONTEXT:'
            /system/bin/cat /proc/self/attr/current
            /system/bin/printf '\n'
            if '${tool.absolutePath}' check --rules '${marker.absolutePath}'; then
                /system/bin/printf 'DEDICATED_TYPE:present\n'
            else
                code=${'$'}?
                test "${'$'}code" -eq 2
                /system/bin/printf 'DEDICATED_TYPE:absent\n'
            fi
            /system/bin/printf 'POLICY_AFTER:'
            /system/bin/sha256sum /sys/fs/selinux/policy
            /system/bin/getenforce
        """.trimIndent()
        val result = try {
            MapleSuRuntime.openShell(context).use { shell ->
                shell.newJob().add(script).to(ArrayList<String>(), ArrayList<String>())
                    .enqueue().get(20, TimeUnit.SECONDS)
            }
        } finally { marker.delete() }
        assertTrue(result.err.joinToString("\n"), result.isSuccess)
        fun field(name: String) = result.out.single { it.startsWith("$name:") }.substringAfter(':').trim()
        val before = field("POLICY_BEFORE").substringBefore(' ')
        val after = field("POLICY_AFTER").substringBefore(' ')
        assertEquals("Policy changed during read-only admission capture", before, after)
        return JSONObject().put("bootId", field("BOOT_ID")).put("policySha256", before)
            .put("dedicatedType", field("DEDICATED_TYPE")).put("rootContext", field("ROOT_CONTEXT"))
            .put("enforcing", result.out.last() == "Enforcing").put("output", result.out.joinToString("\n"))
    }

    @Test fun recordCurrentPolicyWithoutMutation() {
        val result = observe()
        instrumentation.sendStatus(2, Bundle().apply { putString("rootAuthPolicy", result.toString()) })
    }

    @Test fun establishCleanPolicyBaseline() {
        val result = observe()
        assertEquals(result.toString(), "absent", result.getString("dedicatedType"))
        assertTrue(result.toString(), result.getString("output").contains("source type maplesu_su_socket does not exist"))
        snapshot.writeText(result.toString())
        instrumentation.sendStatus(2, Bundle().apply { putString("rootAuthPolicy", result.toString()) })
    }

    @Test fun policyIsUnchangedSinceCleanBaseline() {
        val before = JSONObject(snapshot.readText())
        val after = observe()
        assertEquals(before.getString("bootId"), after.getString("bootId"))
        assertEquals(before.getString("policySha256"), after.getString("policySha256"))
        assertEquals("absent", after.getString("dedicatedType"))
        assertTrue(after.getBoolean("enforcing"))
        instrumentation.sendStatus(2, Bundle().apply { putString("rootAuthPolicy", after.toString()) })
    }
}
