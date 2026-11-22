package dev.maplesu.manager.runtime

import androidx.test.platform.app.InstrumentationRegistry
import com.maplesu.core.Natives
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * The superuser list must load without one root process per application.
 *
 * <p>Regression guard: `getAppProfile` is called once per installed application, so any
 * per-call root process turns opening the list into a hang. A stale grant record used to
 * make the shared snapshot fail, which fell back to exactly that per-application process -
 * the freeze users saw.
 */
class SuperuserListCostAndroidTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext

    @Test fun listLookupsAreBatched() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("verifyMapleSuBoot") == "true")

        val startCount = android.os.SystemClock.elapsedRealtime()
        val count = Natives.getSuperuserCount()
        val countMs = android.os.SystemClock.elapsedRealtime() - startCount

        // Twenty rows, which is enough to expose a per-row process spawn.
        val uids = context.packageManager.getInstalledApplications(0).map { it.uid }.take(20)
        val startRows = android.os.SystemClock.elapsedRealtime()
        val profiles = uids.mapNotNull { Natives.getAppProfile(null, it) }
        val rowsMs = android.os.SystemClock.elapsedRealtime() - startRows
        android.util.Log.i("MapleSU",
            "MAPLESU_EVIDENCE list_cost count=$count count_ms=$countMs rows=${uids.size} rows_ms=$rowsMs loaded=${profiles.size}")

        assertTrue("superuser count unavailable", count >= 0)
        assertTrue("counting took ${countMs}ms", countMs < 5_000)
        // A per-row root process costs ~200-400ms each; batching keeps 20 rows well under it.
        assertTrue("20 rows took ${rowsMs}ms - per-row process spawn is back", rowsMs < 6_000)
    }
}
