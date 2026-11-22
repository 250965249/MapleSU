package dev.maplesu.manager.runtime;

import android.os.Binder;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import android.os.ParcelFileDescriptor;
import android.os.Process;
import android.system.OsConstants;
import android.content.ComponentName;
import android.content.Intent;
import android.util.Log;
import org.json.JSONArray;
import org.json.JSONObject;
import org.lsposed.hiddenapibypass.HiddenApiBypass;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/** Real fixed-command admission subcases; caller supplies a directly discovered Root Binder. */
public final class BinderAdmissionRealSessionClient {
    private static final String ROOT = "dev.maplesu.manager.binderAdmissionRoot";
    private static final byte[] INPUT = "maplesu-real-stdio\n".getBytes(StandardCharsets.UTF_8);
    private BinderAdmissionRealSessionClient() {}

    public static void runExtended(IBinder root, JSONObject report) throws Exception {
        ExecutorService workers = workers();
        report.put("extendedSessionsStatus", "failed");
        try {
            Bundle before = timed(workers, () -> stats(root));
            int pid = before.getInt("rootPid", -1);
            identity(before, pid);
            require(before.getInt("active", -1) == 0, "EXTENDED_PREEXISTING_SESSIONS");
            report.put("extendedSessionStage", "two_concurrent_sessions");
            try (SleepSession first = sleeping(workers, root, pid);
                 SleepSession second = sleeping(workers, root, pid)) {
                Bundle live = timed(workers, () -> stats(root));
                identity(live, pid);
                require(live.getInt("active", -1) == 2, "CONCURRENT_SESSION_COUNT");
                first.requireRunning(); second.requireRunning();
                first.cancelAndWait(); second.cancelAndWait();
                report.put("concurrentSessions", "passed_two_live_sessions");
            }
            reclaimed(workers, root, before, pid, 2);
            report.put("extendedSessionStage", "owner_process_death");
            String classpath = System.getenv("CLASSPATH");
            require(classpath != null && !classpath.isEmpty(), "OWNER_CLASSPATH_MISSING");
            ProcessBuilder builder = new ProcessBuilder("/system/bin/app_process", "/system/bin",
                BinderAdmissionRealSessionClient.class.getName(), "owner", Integer.toString(pid)).redirectErrorStream(true);
            builder.environment().put("CLASSPATH", classpath);
            java.lang.Process child = builder.start();
            try {
                JSONObject ready = timed(workers, () -> ownerReady(child.getInputStream()));
                require(ready.getInt("clientUID") == Process.myUid() && ready.getInt("rootPID") == pid
                    && ready.getInt("callingUID") == Process.myUid() && ready.getInt("clientPID") > 1,
                    "OWNER_CHILD_IDENTITY_MISMATCH");
                Bundle live = timed(workers, () -> stats(root)); identity(live, pid);
                require(live.getInt("active", -1) == 1 && child.isAlive(), "OWNER_SESSION_NOT_LIVE");
                child.destroyForcibly();
                require(child.waitFor(5, TimeUnit.SECONDS) && !child.isAlive(), "OWNER_PROCESS_NOT_REAPED");
                Bundle after = reclaimed(workers, root, before, pid, 3);
                report.put("extendedRootFdsBefore", before.getInt("rootFdCount", -1))
                    .put("extendedRootFdsAfter", after.getInt("rootFdCount", -1));
                report.put("ownerDeath", "passed_real_process_death").put("ownerChild", ready);
            } finally {
                child.destroyForcibly();
                try { require(child.waitFor(5, TimeUnit.SECONDS), "OWNER_PROCESS_CLEANUP_TIMEOUT"); }
                finally { child.getInputStream().close(); child.getOutputStream().close(); child.getErrorStream().close(); }
            }
            report.put("extendedSessionsStatus", "passed").put("extendedSessionStage", "complete");
        } finally { workers.shutdownNow(); }
    }

    public static void runHold(IBinder root, JSONObject report) throws Exception {
        ExecutorService workers = workers();
        report.put("holdSessionStatus", "failed");
        try {
            Bundle before = timed(workers, () -> stats(root));
            int pid = before.getInt("rootPid", -1); identity(before, pid);
            require(before.getInt("active", -1) == 0, "HOLD_PREEXISTING_SESSIONS");
            try (SleepSession held = sleeping(workers, root, pid)) {
                held.requireRunning();
                JSONObject ready = new JSONObject().put("rootPID", pid).put("clientPID", Process.myPid())
                    .put("clientUID", Process.myUid()).put("callingUID", Process.myUid()).put("holdMillis", 15000);
                Log.i("MapleSUBinderAdmission", "REAL_SESSION_HOLD_READY " + ready);
                Thread.sleep(15000);
                held.requireRunning();
                held.cancelAndWait();
                report.put("holdSession", ready).put("holdActualExitCode", 137);
            }
            Bundle after = reclaimed(workers, root, before, pid, 1);
            report.put("holdRootFdsBefore", before.getInt("rootFdCount", -1))
                .put("holdRootFdsAfter", after.getInt("rootFdCount", -1));
            report.put("holdSessionStatus", "passed_same_root_after_15s");
        } finally { workers.shutdownNow(); }
    }

    /** A separate real same-UID process owns this Binder; host-side kill must trigger owner death. */
    public static void main(String[] args) {
        ExecutorService workers = workers();
        Thread deadline = new Thread(() -> {
            try { Thread.sleep(25000); } catch (InterruptedException ignored) { Thread.currentThread().interrupt(); }
            System.exit(70);
        }, "binder-owner-deadline");
        deadline.setDaemon(true); deadline.start();
        int exit = 1;
        try {
            require(args.length == 2 && args[0].equals("owner") && Process.myUid() >= 10000, "OWNER_ARGUMENTS");
            int pid = Integer.parseInt(args[1]);
            HiddenApiBypass.addHiddenApiExemptions("Landroid/app/ActivityManager;", "Landroid/app/IActivityManager;");
            Intent intent = new Intent("dev.maplesu.manager.debug.BINDER_ADMISSION_PEEK")
                .setComponent(new ComponentName("dev.maplesu.manager", "dev.maplesu.manager.runtime.BinderAdmissionBrokerService"));
            IBinder root = timed(workers, () -> {
                Object activity = Class.forName("android.app.ActivityManager").getDeclaredMethod("getService").invoke(null);
                return (IBinder) Class.forName("android.app.IActivityManager").getDeclaredMethod("peekService",
                    Intent.class, String.class, String.class).invoke(activity, intent, null, "dev.maplesu.manager.test");
            });
            require(root != null, "OWNER_ROOT_NOT_PUBLISHED");
            identity(timed(workers, () -> stats(root)), pid);
            try (SleepSession owned = sleeping(workers, root, pid)) {
                owned.requireRunning();
                System.out.println("OWNER_READY " + new JSONObject().put("clientPID", Process.myPid())
                    .put("clientUID", Process.myUid()).put("rootPID", pid).put("callingUID", Process.myUid()));
                System.out.flush();
                Thread.sleep(20000);
                throw new IOException("OWNER_NOT_KILLED_BY_PARENT");
            }
        } catch (Throwable error) {
            System.out.println("OWNER_FAILED " + error); System.out.flush();
        } finally { workers.shutdownNow(); }
        System.exit(exit);
    }

    private static ExecutorService workers() {
        return Executors.newCachedThreadPool(task -> {
            Thread thread = new Thread(task, "binder-real-extended-client"); thread.setDaemon(true); return thread;
        });
    }

    private static JSONObject ownerReady(InputStream input) throws Exception {
        int size = 0;
        while (size < 4096) {
            String line = until(input, "\n"); size += line.length();
            if (line.startsWith("OWNER_READY ")) return new JSONObject(line.substring("OWNER_READY ".length()));
            require(!line.startsWith("OWNER_FAILED "), line);
        }
        throw new IOException("OWNER_READY_OUTPUT_BOUND");
    }

    private static SleepSession sleeping(ExecutorService workers, IBinder root, int pid) throws Exception {
        SleepSession value = new SleepSession(workers, pid);
        try {
            value.input = ParcelFileDescriptor.createPipe(); value.output = ParcelFileDescriptor.createPipe();
            value.error = ParcelFileDescriptor.createPipe();
            ParcelFileDescriptor[] streams = {value.input[0], value.output[1], value.error[1]};
            value.session = timed(workers, () -> start(root, pid, 3, streams, value.owner));
            value.input[0].close(); value.output[1].close(); value.error[1].close();
            String ready = timed(workers, () -> readUntil(value.output[0], "READY\n"));
            require(ready.contains("UID=0\n"), "SLEEP_ROOT_UID_MISSING");
            return value;
        } catch (Exception failure) {
            try { value.close(); } catch (Exception cleanup) { failure.addSuppressed(cleanup); }
            throw failure;
        }
    }

    private static String readUntil(ParcelFileDescriptor descriptor, String marker) throws Exception {
        try (InputStream stream = new ParcelFileDescriptor.AutoCloseInputStream(descriptor)) { return until(stream, marker); }
    }

    private static final class SleepSession implements AutoCloseable {
        final ExecutorService workers; final int pid; final Binder owner = new Binder();
        ParcelFileDescriptor[] input, output, error;
        INativeSuSession session;
        SleepSession(ExecutorService workers, int pid) { this.workers = workers; this.pid = pid; }
        void requireRunning() throws Exception {
            Bundle live = timed(workers, () -> session.awaitExit(0)); identity(live, pid);
            require(!live.getBoolean("finished"), "SLEEP_SESSION_EXITED_EARLY");
        }
        void cancelAndWait() throws Exception {
            timed(workers, () -> { session.cancel(); return null; });
            Bundle exit = timed(workers, () -> session.awaitExit(7000)); identity(exit, pid);
            require(exit.getBoolean("finished") && exit.getInt("exitCode", -1) == 137, "SLEEP_CANCEL_EXIT_MISMATCH");
        }
        @Override public void close() throws Exception {
            try { if (session != null) timed(workers, () -> { session.close(); return null; }); }
            finally { BinderAdmissionRealSessionClient.close(input, output, error); }
        }
    }

    private static Bundle reclaimed(ExecutorService workers, IBinder root, Bundle before, int pid, int count) throws Exception {
        Bundle after;
        long deadline = android.os.SystemClock.elapsedRealtime() + 5000;
        do {
            after = timed(workers, () -> stats(root)); identity(after, pid);
            if (after.getInt("active", -1) == 0) break;
            Thread.sleep(50);
        } while (android.os.SystemClock.elapsedRealtime() < deadline);
        require(after.getInt("active", -1) == 0 && after.getInt("started", -1) - before.getInt("started", -1) == count
            && after.getInt("completed", -1) - before.getInt("completed", -1) == count, "EXTENDED_RECLAMATION_MISMATCH");
        int[] oldChildren = before.getIntArray("supervisorPids"), newChildren = after.getIntArray("supervisorPids");
        require(oldChildren != null && newChildren != null, "EXTENDED_CHILD_STATS_MISSING");
        Arrays.sort(oldChildren); Arrays.sort(newChildren);
        require(Arrays.equals(oldChildren, newChildren), "EXTENDED_SUPERVISOR_NOT_REAPED");
        require(before.getInt("rootFdCount", -1) >= 0
            && after.getInt("rootFdCount", -1) <= before.getInt("rootFdCount", -1), "EXTENDED_ROOT_FD_GROWTH");
        return after;
    }

    public static void run(IBinder root, JSONObject report) throws Exception {
        ExecutorService workers = Executors.newCachedThreadPool(task -> {
            Thread thread = new Thread(task, "binder-real-session-client");
            thread.setDaemon(true);
            return thread;
        });
        report.put("realSessionsStatus", "failed");
        report.put("ownerDeath", "NOT_RUN");
        report.put("concurrentSessions", "NOT_RUN");
        JSONArray cases = new JSONArray();
        report.put("realSessionCases", cases);
        try {
            report.put("realSessionStage", "baseline_stats");
            Bundle before = timed(workers, () -> stats(root));
            int rootPid = before.getInt("rootPid", -1);
            identity(before, rootPid);
            require(before.getInt("active", -1) == 0, "PREEXISTING_SESSIONS");
            for (int id = 0; id < 4; id++) {
                report.put("realSessionStage", "case_" + id);
                cases.put(runCase(workers, root, rootPid, id));
            }
            report.put("realSessionStage", "resource_reclamation");
            Bundle after;
            long deadline = android.os.SystemClock.elapsedRealtime() + 3000;
            do {
                after = timed(workers, () -> stats(root));
                identity(after, rootPid);
                if (after.getInt("active", -1) == 0) break;
                Thread.sleep(50);
            } while (android.os.SystemClock.elapsedRealtime() < deadline);
            report.put("rootFdsBefore", before.getInt("rootFdCount", -1));
            report.put("rootFdsAfter", after.getInt("rootFdCount", -1));
            require(after.getInt("active", -1) == 0, "SESSIONS_NOT_RECLAIMED");
            require(after.getInt("started", -1) - before.getInt("started", -1) == 4
                && after.getInt("completed", -1) - before.getInt("completed", -1) == 4,
                "SESSION_ACCOUNTING_MISMATCH");
            int[] oldChildren = before.getIntArray("supervisorPids"), newChildren = after.getIntArray("supervisorPids");
            require(oldChildren != null && newChildren != null, "CHILD_STATS_MISSING");
            Arrays.sort(oldChildren); Arrays.sort(newChildren);
            require(Arrays.equals(oldChildren, newChildren), "SUPERVISOR_NOT_REAPED");
            require(before.getInt("rootFdCount", -1) >= 0
                && after.getInt("rootFdCount", -1) <= before.getInt("rootFdCount", -1), "ROOT_FD_GROWTH");
            report.put("realSessionsStatus", "passed_fixed_subcases");
            report.put("realSessionStage", "complete");
        } finally { workers.shutdownNow(); }
    }

    private static JSONObject runCase(ExecutorService workers, IBinder root, int pid, int id) throws Exception {
        ParcelFileDescriptor[] input = ParcelFileDescriptor.createPipe();
        ParcelFileDescriptor[] output = null, error = null;
        INativeSuSession session = null;
        try {
            output = ParcelFileDescriptor.createPipe(); error = ParcelFileDescriptor.createPipe();
            if (id == 0) try (OutputStream stream = new ParcelFileDescriptor.AutoCloseOutputStream(input[1])) {
                stream.write(INPUT);
            }
            ParcelFileDescriptor[] send = {input[0], output[1], error[1]};
            Binder owner = new Binder();
            session = timed(workers, () -> start(root, pid, id, send, owner));
            input[0].close(); output[1].close(); error[1].close();
            JSONObject result = new JSONObject().put("caseId", id).put("callingUID", Process.myUid());
            final INativeSuSession active = session;
            Bundle exit = null;
            if (id == 1) {
                ParcelFileDescriptor terminal = timed(workers, active::openTerminal);
                require(terminal != null, "PTY_MISSING");
                try (InputStream reader = new ParcelFileDescriptor.AutoCloseInputStream(terminal);
                     OutputStream writer = new ParcelFileDescriptor.AutoCloseOutputStream(
                         ParcelFileDescriptor.dup(terminal.getFileDescriptor()))) {
                    String first = timed(workers, () -> until(reader, "25 80\n"));
                    require(first.contains("UID=0\n"), "PTY_ROOT_UID_MISSING");
                    timed(workers, () -> { active.resize(new int[]{35, 110, 0, 0}); return null; });
                    writer.write("continue\n".getBytes(StandardCharsets.UTF_8)); writer.flush();
                    String resized = timed(workers, () -> until(reader, "35 110\n"));
                    result.put("initialPty", first).put("resizedPty", resized);
                    // Keep the last master handles until real exit; early close could send SIGHUP.
                    exit = timed(workers, () -> active.awaitExit(7000));
                }
            } else if (id >= 2) {
                final ParcelFileDescriptor stdout = output[0];
                String ready = timed(workers, () -> {
                    try (InputStream reader = new ParcelFileDescriptor.AutoCloseInputStream(stdout)) {
                        return until(reader, "READY\n");
                    }
                });
                require(ready.contains("UID=0\n"), "SIGNAL_ROOT_UID_MISSING");
                result.put("ready", ready);
                timed(workers, () -> { if (id == 2) active.signal(OsConstants.SIGINT); else active.cancel(); return null; });
            }
            if (exit == null) exit = timed(workers, () -> active.awaitExit(7000));
            identity(exit, pid);
            int expected = id < 2 ? 37 : id == 2 ? 130 : 137;
            require(exit.getBoolean("finished") && exit.getInt("exitCode", -1) == expected, "REAL_EXIT_MISMATCH: " + exit);
            result.put("actualExitCode", exit.getInt("exitCode")).put("exitSource", "supervised_process_wait");
            if (id == 0) {
                final ParcelFileDescriptor stdout = output[0], stderr = error[0];
                String text = timed(workers, () -> readAll(stdout));
                String diagnostic = timed(workers, () -> readAll(stderr));
                require(text.equals(new String(INPUT, StandardCharsets.UTF_8)), "STDIO_CONTENT_MISMATCH");
                require(diagnostic.matches("(?s).*PID=[0-9]+\\nUID=0\\nCWD=/data/local/tmp\\nENV=fixture\\n.*"),
                    "STDIO_ENVIRONMENT_MISMATCH: " + diagnostic);
                result.put("stdout", text).put("stderr", diagnostic);
            }
            return result.put("status", "pass");
        } finally {
            try { if (session != null) { final INativeSuSession closing = session;
                timed(workers, () -> { closing.close(); return null; }); }
            } finally { close(input, output, error); }
        }
    }

    private static INativeSuSession start(IBinder root, int pid, int id, ParcelFileDescriptor[] streams, IBinder owner) throws Exception {
        Parcel request = Parcel.obtain(), reply = Parcel.obtain();
        try {
            request.writeInterfaceToken(ROOT); request.writeInt(id);
            for (ParcelFileDescriptor stream : streams) request.writeTypedObject(stream, 0);
            request.writeStrongBinder(owner);
            require(root.transact(IBinder.FIRST_CALL_TRANSACTION + 2, request, reply, 0), "START_UNHANDLED");
            reply.readException(); identity(reply.readTypedObject(Bundle.CREATOR), pid);
            INativeSuSession session = INativeSuSession.Stub.asInterface(reply.readStrongBinder());
            require(session != null && reply.dataAvail() == 0, "SESSION_REPLY_INVALID");
            return session;
        } finally { request.recycle(); reply.recycle(); }
    }

    private static Bundle stats(IBinder root) throws Exception {
        Parcel request = Parcel.obtain(), reply = Parcel.obtain();
        try {
            request.writeInterfaceToken(ROOT);
            require(root.transact(IBinder.FIRST_CALL_TRANSACTION + 3, request, reply, 0), "STATS_UNHANDLED");
            reply.readException(); Bundle stats = reply.readTypedObject(Bundle.CREATOR);
            require(reply.dataAvail() == 0, "STATS_TRAILING_DATA"); return stats;
        } finally { request.recycle(); reply.recycle(); }
    }

    private static void identity(Bundle value, int pid) throws IOException {
        require(value != null && value.getInt("callingUid", -1) == Process.myUid()
            && value.getInt("rootUid", -1) == 0 && pid > 1 && value.getInt("rootPid", -1) == pid,
            "REAL_SESSION_IDENTITY_MISMATCH");
    }

    private static String readAll(ParcelFileDescriptor descriptor) throws Exception {
        try (InputStream input = new ParcelFileDescriptor.AutoCloseInputStream(descriptor)) { return until(input, null); }
    }

    private static String until(InputStream input, String marker) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        for (int value; (value = input.read()) != -1;) {
            if (bytes.size() >= 4096) throw new IOException("REAL_SESSION_OUTPUT_BOUND");
            if (value != '\r') bytes.write(value);
            if (marker != null && bytes.toString(StandardCharsets.UTF_8.name()).endsWith(marker)) break;
        }
        String result = bytes.toString(StandardCharsets.UTF_8.name());
        require(marker == null || result.endsWith(marker), "REAL_SESSION_MARKER_MISSING"); return result;
    }

    private static <T> T timed(ExecutorService workers, Callable<T> task) throws Exception {
        Future<T> future = workers.submit(task);
        try { return future.get(9, TimeUnit.SECONDS); } finally { future.cancel(true); }
    }

    private static void require(boolean condition, String message) throws IOException {
        if (!condition) throw new IOException(message);
    }

    private static void close(ParcelFileDescriptor[]... groups) throws IOException {
        IOException failure = null;
        for (ParcelFileDescriptor[] descriptors : groups) {
            if (descriptors == null) continue;
            for (ParcelFileDescriptor descriptor : descriptors) try { descriptor.close(); }
            catch (IOException error) { if (failure == null) failure = error; else failure.addSuppressed(error); }
        }
        if (failure != null) throw failure;
    }
}
