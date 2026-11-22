package com.maplesu.core.ui.util;

import android.app.ActivityManager;
import android.app.ApplicationExitInfo;
import android.content.Context;
import android.os.Process;
import android.os.SystemClock;
import android.provider.Settings;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/** App-scoped exit history and boot timing, collected before privileged diagnostics. */
public final class ProcessExitDiagnostics {
    private ProcessExitDiagnostics() { }

    public static void collect(Context context, File destination) throws IOException {
        try {
            String packageName = context.getPackageName();
            JSONObject report = new JSONObject();
            report.put("schemaVersion", 1);
            report.put("capturedAtEpochMs", System.currentTimeMillis());
            report.put("packageName", packageName);
            report.put("uid", Process.myUid());
            report.put("pid", Process.myPid());
            report.put("elapsedRealtimeMs", SystemClock.elapsedRealtime());
            report.put("uptimeMs", SystemClock.uptimeMillis());
            try {
                report.put("bootCount", Settings.Global.getInt(context.getContentResolver(), Settings.Global.BOOT_COUNT, -1));
            } catch (RuntimeException error) {
                report.put("bootCountError", error.getClass().getSimpleName());
            }
            try (BufferedReader input = new BufferedReader(new InputStreamReader(
                    new FileInputStream("/proc/sys/kernel/random/boot_id"), StandardCharsets.UTF_8))) {
                String bootId = input.readLine();
                report.put("currentBootId", bootId == null ? JSONObject.NULL : bootId.trim());
            } catch (IOException | RuntimeException error) {
                report.put("bootIdError", error.getClass().getSimpleName());
            }

            JSONArray exits = new JSONArray();
            try {
                ActivityManager manager = context.getSystemService(ActivityManager.class);
                for (ApplicationExitInfo exit : manager.getHistoricalProcessExitReasons(packageName, 0, 32)) {
                    String name = exit.getProcessName();
                    if (!packageName.equals(name) && (name == null || !name.startsWith(packageName + ":"))) continue;
                    JSONObject item = new JSONObject();
                    item.put("processName", name);
                    item.put("timestampEpochMs", exit.getTimestamp());
                    item.put("pid", exit.getPid());
                    item.put("reasonCode", exit.getReason());
                    item.put("status", exit.getStatus());
                    item.put("importance", exit.getImportance());
                    item.put("pssKb", exit.getPss());
                    item.put("rssKb", exit.getRss());
                    item.put("description", exit.getDescription() == null ? JSONObject.NULL : exit.getDescription());
                    exits.put(item);
                }
            } catch (RuntimeException error) {
                report.put("historyError", error.getClass().getSimpleName());
            }
            report.put("exits", exits);
            File directory = new File(destination, "app-lifecycle");
            if (!directory.isDirectory() && !directory.mkdirs()) throw new IOException("PROCESS_EXIT_DIRECTORY_FAILED");
            try (OutputStreamWriter output = new OutputStreamWriter(
                    new FileOutputStream(new File(directory, "process-exits.json")), StandardCharsets.UTF_8)) {
                output.write(report.toString(2));
                output.write('\n');
            }
        } catch (JSONException error) {
            throw new IOException("PROCESS_EXIT_ENCODING_FAILED", error);
        }
    }
}
