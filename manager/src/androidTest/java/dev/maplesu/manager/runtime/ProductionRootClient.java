package dev.maplesu.manager.runtime;

import android.os.Binder;
import android.os.Bundle;
import android.os.ParcelFileDescriptor;
import android.os.Process;
import android.system.OsConstants;
import org.json.JSONObject;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/** Fresh app_process in the independent test APK's actual App domain, using production discovery. */
public final class ProductionRootClient {
    private ProductionRootClient() {}
    public static void main(String[] args) {
        JSONObject report = new JSONObject();
        Thread deadline = new Thread(() -> {
            try { Thread.sleep(25000); } catch (InterruptedException ignored) { }
            System.exit(70);
        }, "production-client-deadline");
        deadline.setDaemon(true); deadline.start();
        int exit = 1;
        try {
            require(args.length == 2, "PRODUCTION_ARGUMENTS");
            report.put("clientUid", Process.myUid()).put("clientPid", Process.myPid());
            try (InputStream context = new FileInputStream("/proc/self/attr/current")) {
                report.put("clientContext", read(context, null).replace("\u0000", "").trim());
            }
            INativeSuService service = INativeSuService.Stub.asInterface(NativeSuDiscovery.peek(Integer.parseInt(args[0])));
            report.put("discovery", "production_ams_peek").put("case", args[1]);
            run(service, args[1], report);
            report.put("status", "pass"); exit = 0;
        } catch (Throwable failure) {
            try { report.put("status", "failed").put("failure", failure.toString()); } catch (Exception ignored) { }
        }
        System.out.println(report.toString());
        System.exit(exit);
    }

    private static void run(INativeSuService service, String mode, JSONObject report) throws Exception {
        boolean pty = mode.equals("pty");
        require(mode.equals("denied") || mode.equals("stdio") || pty || mode.equals("signal") || mode.equals("cancel"),
            "PRODUCTION_CASE_INVALID");
        String command = pty
            ? "printf 'UID=%s\\n' \"$(id -u)\"; stty size; read -r next; stty size; exit 37"
            : mode.equals("signal") || mode.equals("cancel")
            ? "printf 'UID=%s\\nREADY\\n' \"$(id -u)\"; exec /system/bin/sleep 60"
            : "test \"$(id -u)\" = 0 || exit 91; read -r line; printf '%s' \"$line\"; " +
              "printf 'UID=%s\\nCWD=%s\\nENV=%s\\n' \"$(id -u)\" \"$PWD\" \"$MAPLESU_PRODUCTION_ENV\" >&2; exit 37";
        ParcelFileDescriptor[] input = ParcelFileDescriptor.createPipe();
        ParcelFileDescriptor[] output = null, error = null;
        INativeSuSession session = null;
        ExecutorService readers = Executors.newCachedThreadPool(runnable -> {
            Thread thread = new Thread(runnable, "production-client-read"); thread.setDaemon(true); return thread;
        });
        try {
            output = ParcelFileDescriptor.createPipe(); error = ParcelFileDescriptor.createPipe();
            try (OutputStream stream = new ParcelFileDescriptor.AutoCloseOutputStream(input[1])) {
                stream.write("production-stdio-marker\n".getBytes(StandardCharsets.UTF_8));
            }
            try {
                session = service.start(frame(command, pty), input[0], output[1], error[1], new Binder());
            } catch (SecurityException denied) {
                require(mode.equals("denied"), "AUTHORIZED_REQUEST_DENIED: " + denied);
                report.put("authorization", "denied"); return;
            }
            require(!mode.equals("denied"), "UNAUTHORIZED_SESSION_CREATED");
            input[0].close(); output[1].close(); error[1].close();
            final INativeSuSession active = session;
            Bundle result;
            if (pty) {
                ParcelFileDescriptor terminal = active.openTerminal();
                require(terminal != null, "PRODUCTION_PTY_MISSING");
                try (InputStream reader = new ParcelFileDescriptor.AutoCloseInputStream(terminal);
                     OutputStream writer = new ParcelFileDescriptor.AutoCloseOutputStream(ParcelFileDescriptor.dup(terminal.getFileDescriptor()))) {
                    String before = readers.submit(() -> read(reader, "25 80\n")).get(8, TimeUnit.SECONDS);
                    require(before.contains("UID=0\n"), "PTY_UID_MISSING");
                    active.resize(new int[]{35, 110, 0, 0});
                    writer.write("continue\n".getBytes(StandardCharsets.UTF_8)); writer.flush();
                    String after = readers.submit(() -> read(reader, "35 110\n")).get(8, TimeUnit.SECONDS);
                    result = active.awaitExit(7000);
                    report.put("initialPty", before).put("resizedPty", after);
                }
            } else if (mode.equals("signal") || mode.equals("cancel")) {
                try (InputStream reader = new ParcelFileDescriptor.AutoCloseInputStream(output[0])) {
                    String ready = readers.submit(() -> read(reader, "READY\n")).get(8, TimeUnit.SECONDS);
                    require(ready.contains("UID=0\n"), "SIGNAL_UID_MISSING");
                    if (mode.equals("signal")) active.signal(OsConstants.SIGINT); else active.cancel();
                    result = active.awaitExit(7000);
                    report.put("ready", ready);
                }
            } else {
                final ParcelFileDescriptor out = output[0], err = error[0];
                Future<String> stdout = readers.submit(() -> {
                    try (InputStream stream = new ParcelFileDescriptor.AutoCloseInputStream(out)) { return read(stream, null); }
                });
                Future<String> stderr = readers.submit(() -> {
                    try (InputStream stream = new ParcelFileDescriptor.AutoCloseInputStream(err)) { return read(stream, null); }
                });
                result = active.awaitExit(7000);
                String text = stdout.get(8, TimeUnit.SECONDS), diagnostic = stderr.get(8, TimeUnit.SECONDS);
                require(text.equals("production-stdio-marker"), "PRODUCTION_STDOUT: " + text);
                require(diagnostic.equals("UID=0\nCWD=/data/local/tmp\nENV=preserved\n"), "PRODUCTION_STDERR: " + diagnostic);
                report.put("stdout", text).put("stderr", diagnostic);
            }
            int expected = mode.equals("signal") ? 130 : mode.equals("cancel") ? 137 : 37;
            require(result.getBoolean("finished") && result.getInt("exitCode", -1) == expected,
                "PRODUCTION_EXIT: " + result);
            report.put("actualExitCode", result.getInt("exitCode")).put("exitSource", "production_session_wait");
        } finally {
            if (session != null) try { session.close(); } catch (Exception ignored) { }
            close(input); close(output); close(error); readers.shutdownNow();
        }
    }

    private static byte[] frame(String command, boolean terminal) throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        DataOutputStream output = new DataOutputStream(bytes);
        output.writeInt(0x4d535531); output.writeInt(terminal ? 7 : 0); output.writeInt(0); output.writeInt(0);
        for (int value : new int[]{25, 80, 0, 0}) output.writeInt(value);
        text(output, "/system/bin/sh"); text(output, "/data/local/tmp");
        output.writeInt(3); text(output, "sh"); text(output, "-c"); text(output, command);
        output.writeInt(2); text(output, "PATH=/system/bin"); text(output, "MAPLESU_PRODUCTION_ENV=preserved");
        output.flush(); return bytes.toByteArray();
    }
    private static void text(DataOutputStream output, String value) throws Exception {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8); output.writeInt(bytes.length); output.write(bytes);
    }
    private static String read(InputStream input, String marker) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        for (int value; (value = input.read()) != -1;) {
            require(output.size() < 8192, "PRODUCTION_OUTPUT_BOUND");
            if (value != '\r') output.write(value);
            if (marker != null && output.toString(StandardCharsets.UTF_8.name()).endsWith(marker)) break;
        }
        String result = output.toString(StandardCharsets.UTF_8.name());
        require(marker == null || result.endsWith(marker), "PRODUCTION_MARKER_MISSING"); return result;
    }
    private static void close(ParcelFileDescriptor[] descriptors) {
        if (descriptors != null) for (ParcelFileDescriptor descriptor : descriptors)
            try { descriptor.close(); } catch (Exception ignored) { }
    }
    private static void require(boolean condition, String message) {
        if (!condition) throw new IllegalStateException(message);
    }
}
