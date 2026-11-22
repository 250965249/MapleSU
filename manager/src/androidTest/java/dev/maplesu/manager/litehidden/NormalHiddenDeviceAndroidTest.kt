package dev.maplesu.manager.litehidden

import android.os.Bundle
import android.os.SystemClock
import androidx.test.core.app.ActivityScenario
import androidx.test.platform.app.InstrumentationRegistry
import com.maplesu.core.Natives
import com.maplesu.core.data.repository.SettingsRepositoryImpl
import com.maplesu.core.ui.MainActivity
import dev.maplesu.manager.runtime.RootExec
import dev.maplesu.manager.workmode.ModeRuntime
import dev.maplesu.manager.workmode.WorkMode
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File

/** Explicit opt-in; preparation does not enable stealth or remove the manager. */
class NormalHiddenDeviceAndroidTest {
    @Test(timeout = 180_000)
    fun prepareIndependentNormalRecovery() {
        val args = InstrumentationRegistry.getArguments()
        assumeTrue(args.getString("verifyNormalHidden") == "true")
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        fun report(stage: String, value: String) = instrumentation.sendStatus(2, Bundle().apply {
            putString("stage", stage); putString("value", value)
        })
        ActivityScenario.launch(MainActivity::class.java).use {
            val deadline = SystemClock.elapsedRealtime() + 60_000
            while (ModeRuntime.active == null && SystemClock.elapsedRealtime() < deadline) SystemClock.sleep(100)
            assertEquals(WorkMode.KSU, ModeRuntime.active)
            report("root", RootExec.capability().toString())
            if (args.getString("normalAction") == "stop-probe") {
                val result = RootExec.execute(ParasiteScripts.daemonStop())
                report("stop-probe", "code=${result.code} detail=${result.detail} output=${result.output}")
                val isolated = RootExec.execute("(\n" + ParasiteScripts.daemonStop() + "\n)")
                report("isolated-stop", "code=${isolated.code} detail=${isolated.detail} output=${isolated.output}")
                assertTrue(isolated.ok)
                assertTrue(result.ok)
                return@use
            }
            if (args.getString("normalAction") == "selinux") {
                val repo = SettingsRepositoryImpl()
                val expected = Natives.setSelinuxHideEnabled(true)
                val actual = repo.setSelinuxHideEnabled(true)
                report("selinux-write", "native=$expected repository=$actual enabled=${repo.isSelinuxHideEnabled()}")
                assertEquals("Repository discarded the native result", expected, actual)
                assertTrue(expected == 0 || expected == -11)
                repo.execKsudFeatureSave()
                return@use
            }
            val controller = requireNotNull(NormalHiddenEnv.create(context))
            val result = runBlocking(Dispatchers.IO) { controller.prepare(args.getString("normalPort", "18427").toInt()) }
            report("normal-prepare", "ok=${result.ok} code=${result.code}")
            assertTrue("Normal preparation: ${result.code}", result.ok)
            File(context.filesDir, "normal-hidden-url").writeText(result.recoveryUrl)
            assertEquals(0, Natives.stealthState())
            controller.cancel()
        }
    }
}
