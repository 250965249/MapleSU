package dev.maplesu.manager.installer

import android.os.Bundle
import androidx.test.core.app.ActivityScenario
import androidx.test.platform.app.InstrumentationRegistry
import com.maplesu.core.ui.MainActivity
import dev.maplesu.manager.workmode.Hashes
import dev.maplesu.manager.workmode.control.ControlJsonCodec
import dev.maplesu.manager.workmode.control.ControlPaths
import dev.maplesu.manager.workmode.recovery.DiagnosticsExporter
import dev.maplesu.manager.workmode.recovery.DiagnosticsSnapshot
import dev.maplesu.manager.workmode.recovery.RootDiagnosticsReader
import java.nio.file.Files
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test

/** Explicit opt-in: reads the real diagnostic Root route and only writes its private export. */
class DiagnosticsRootAndroidTest {
    @Test fun diagnosticReadAndExportReflectTheActualRootResult() {
        val arguments = InstrumentationRegistry.getArguments()
        assumeTrue(arguments.getString("verifyDiagnosisRoot") == "true")
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        ActivityScenario.launch(MainActivity::class.java).use {
            val observed = runCatching {
                RootDiagnosticsReader(ControlPaths.ROOT_FILE, context.cacheDir).read("")
            }
            if (arguments.getString("expectDiagnosisRoot") == "false") {
                val failure = observed.exceptionOrNull()
                assertNotNull("Diagnostic reads must fail when no Root backend is available", failure)
                assertTrue(failure!!.message.orEmpty().startsWith("DIAGNOSTICS_ROOT_FAILED:"))
                instrumentation.sendStatus(2, Bundle().apply { putString("diagnosisFailure", failure.message) })
            } else {
                val snapshot = observed.getOrThrow()
                assertTrue(snapshot.notes.any { it.startsWith("ROOT_BACKEND:") })
                val directory = Files.createTempDirectory(context.cacheDir.toPath(), "diagnosis-test-").toFile()
                try {
                    val result = DiagnosticsExporter(ControlPaths.ROOT_FILE, directory).export(snapshot)
                    assertTrue(result.bytes > 0)
                    assertEquals(Hashes.sha256(result.file.readBytes()), result.sha256)
                    val exported = ControlJsonCodec.decodeOrNull<DiagnosticsSnapshot>(result.file.readText())!!
                    assertEquals(snapshot, exported)
                    instrumentation.sendStatus(2, Bundle().apply {
                        putString("diagnosisBackend", snapshot.notes.first { it.startsWith("ROOT_BACKEND:") })
                        putLong("diagnosisBytes", result.bytes)
                        putString("diagnosisSha256", result.sha256)
                    })
                } finally { directory.deleteRecursively() }
            }
        }
    }
}
