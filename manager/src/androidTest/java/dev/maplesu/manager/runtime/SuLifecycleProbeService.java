package dev.maplesu.manager.runtime;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/** Fixed read-only su commands in a real, independently started Android App process. */
public final class SuLifecycleProbeService extends Service {
    private final java.util.concurrent.ExecutorService worker = Executors.newSingleThreadExecutor();

    @Override public IBinder onBind(Intent intent) { return null; }

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        String mode = intent == null ? "" : intent.getStringExtra("mode");
        if (!"existing".equals(mode) && !"new".equals(mode) && !"denied".equals(mode)) {
            stopSelf(startId);
            return START_NOT_STICKY;
        }
        worker.execute(() -> {
            try { runProbe(mode); } finally { stopSelf(startId); }
        });
        return START_NOT_STICKY;
    }

    private void runProbe(String mode) {
        java.lang.Process child = null;
        try (PrintStream output = new PrintStream(new FileOutputStream(
                new File(getFilesDir(), "su-lifecycle-" + mode + ".log")), true, "UTF-8")) {
            output.println("FIXTURE_UID=" + android.os.Process.myUid());
            String command = "existing".equals(mode)
                    ? "test \"$(id -u)\" = 0 || exit 91; id -u; printf 'SESSION_STARTED\\n'; sleep 12; id -u; getenforce"
                    : "test \"$(id -u)\" = 0 || exit 91; id -u; getenforce; exit 37";
            child = new ProcessBuilder("/dev/maplesu/bin/su", "-c", command)
                    .redirectErrorStream(true).start();
            child.getOutputStream().close();
            // Destroying the client also exercises the production disconnect cleanup.
            java.lang.Process running = child;
            java.util.concurrent.ScheduledExecutorService timer = Executors.newSingleThreadScheduledExecutor();
            timer.schedule(running::destroyForcibly, 25, TimeUnit.SECONDS);
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                    child.getInputStream(), StandardCharsets.UTF_8))) {
                StringBuilder transcript = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    output.println(line);
                    transcript.append(line).append('\n');
                }
                int exit = child.waitFor();
                int expected = "denied".equals(mode) ? 77 : "existing".equals(mode) ? 0 : 37;
                if (exit != expected || (!"denied".equals(mode) &&
                        !transcript.toString().contains("Enforcing"))) {
                    output.println("FAILED exit=" + exit + " expected=" + expected);
                } else output.println("LIFECYCLE_PROBE_PASSED mode=" + mode + " exit=" + exit);
            } finally { timer.shutdownNow(); }
        } catch (Exception failure) {
            android.util.Log.e("MapleSUTest", "Lifecycle probe failed: " + mode, failure);
        } finally { if (child != null) child.destroyForcibly(); }
    }

    @Override public void onDestroy() { worker.shutdown(); super.onDestroy(); }
}
