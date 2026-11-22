package dev.maplesu.manager.jailbreak;

import android.content.Context;
import android.system.ErrnoException;
import android.system.Os;
import android.util.Log;

import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/** Independent provider attempt. Never starts a daemon or changes Manager readiness. */
public final class GhostlockAttempt implements Closeable {
    public interface Progress {
        void onStep(String step, String status);
    }

    private static final String TAG = "MapleSU-Ghostlock";

    private final RootShellLease.PendingLease pending;
    private final Process provider;
    private final AtomicBoolean closed = new AtomicBoolean();
    private volatile IOException channelFailure;
    private final GhostlockProcessState processState = new GhostlockProcessState();
    private File nativeLog;
    private File workerResult;

    private GhostlockAttempt(RootShellLease.PendingLease pending, Process provider) {
        this.pending = pending;
        this.provider = provider;
    }

    /**
     * IO-thread entry only. The native decoder independently checks every
     * resolved section and its exact running release before any native stages.
     * Progress is optional, runs on the reader thread and is never readiness.
     */
    public static GhostlockAttempt start(Context context, byte[] resolvedProfile, Progress progress)
            throws IOException {
        return start(context, resolvedProfile, null, progress);
    }

    /**
     * Same attempt, plus the profile it was resolved from.
     *
     * <p>A template-derived profile (see
     * {@link GhostlockProfiles#resolveForAttempt}) is logged with its one
     * machine-readable prefix and every failure is labelled with it, so an App,
     * a bug report or a reviewer can tell an exact hit from a KMI-template
     * inference. The wire still carries the running release: the marker travels
     * beside the document, never inside it.
     */
    public static GhostlockAttempt start(Context context, byte[] resolvedProfile,
                                        GhostlockProfiles.Profile profile, Progress progress)
            throws IOException {
        String marker = assumptionMarker(profile);
        if (marker != null) {
            Log.i(TAG, marker);
            Log.i(TAG, "GHOSTLOCK_PROFILE_ASSUMED_DETAIL:template=" + profile.file()
                    + " declared=" + profile.assumedFrom() + " release=" + profile.release());
        }
        try {
            return begin(context, resolvedProfile, progress, null, null);
        } catch (IOException error) {
            throw assumptionFailure(profile, error);
        }
    }

    public static GhostlockAttempt start(Context context, byte[] resolvedProfile,
                                        GhostlockProfiles.Profile profile, JailbreakRequest request)
            throws IOException {
        return start(context, resolvedProfile, profile, request, null);
    }

    public static GhostlockAttempt start(Context context, byte[] resolvedProfile,
                                        GhostlockProfiles.Profile profile, JailbreakRequest request,
                                        Progress progress) throws IOException {
        try {
            String target = GhostlockHandover.INSTANCE.target(request.getRootBackend());
            return begin(context, resolvedProfile, progress, target, request.getAttemptId());
        } catch (IOException error) {
            throw assumptionFailure(profile, error);
        }
    }

    /** The {@code GHOSTLOCK_PROFILE_ASSUMED:...} prefix, or null for an exact profile. */
    public static String assumptionMarker(GhostlockProfiles.Profile profile) {
        return profile == null ? null : profile.assumptionMarker();
    }

    /**
     * Prefixes a failure code with the assumption marker, so "template inferred"
     * is never reported as "exact profile failed". An exact profile's failure and
     * an already-prefixed one are returned unchanged.
     */
    public static IOException assumptionFailure(GhostlockProfiles.Profile profile, IOException error) {
        String marker = assumptionMarker(profile);
        String message = error.getMessage();
        if (marker == null || message == null || message.startsWith(marker)) return error;
        return new IOException(marker + ":" + message, error);
    }

    private static GhostlockAttempt begin(Context context, byte[] resolvedProfile, Progress progress,
                                           String target, String attemptId)
            throws IOException {
        if (context == null) throw new NullPointerException("context");
        String release = Os.uname().release;
        // Validate and snapshot the document before creating a process.
        byte[] snapshot = resolvedProfile == null ? null : resolvedProfile.clone();
        new GhostlockWire(snapshot, release, new java.io.ByteArrayOutputStream());
        String nativeDir = context.getApplicationInfo().nativeLibraryDir;
        if (nativeDir == null) throw new IOException("GHOSTLOCK_NATIVE_DIRECTORY_MISSING");
        File binary = new File(nativeDir, "libmaplesu_ghostlock_provider.so").getCanonicalFile();
        File consumer = new File(nativeDir, "libmaplesu_root_consumer.so").getCanonicalFile();
        if (!binary.isFile() || !binary.canExecute() || !consumer.isFile() || !consumer.canExecute() ||
                !binary.getParentFile().equals(consumer.getParentFile()))
            throw new IOException("GHOSTLOCK_PACKAGED_ENTRIES_MISSING");
        String logAttempt = attemptId != null ? attemptId : "ghostlock-" + java.util.UUID.randomUUID();
        File diagnostics = JailbreakDiagnostics.attemptDirectory(context.getFilesDir(), logAttempt);
        File home = Files.createTempDirectory(diagnostics.toPath(), "ghostlock-")
                .toFile().getCanonicalFile();
        try { Os.chmod(home.getPath(), 0700); }
        catch (ErrnoException error) {
            Files.deleteIfExists(home.toPath());
            throw new IOException("GHOSTLOCK_PRIVATE_HOME_FAILED", error);
        }
        // Upstream copies this path into a fixed 320-byte buffer before fork.
        if (home.getPath().getBytes(StandardCharsets.UTF_8).length > 255 ||
                (home.getPath() + "/.ghostlock_root.sh").getBytes(StandardCharsets.UTF_8).length >= 300) {
            Files.deleteIfExists(home.toPath());
            throw new IOException("GHOSTLOCK_HOME_PATH_TOO_LONG");
        }
        RootShellLease.PendingLease pending = null;
        Process provider = null;
        try {
            File workerLog = new File(home, "root-worker.log");
            if (!workerLog.createNewFile()) throw new IOException("GHOSTLOCK_LOG_EXISTS");
            try { Os.chmod(workerLog.getPath(), 0600); }
            catch (ErrnoException error) { throw new IOException("GHOSTLOCK_LOG_MODE_FAILED", error); }
            File workerResult = null;
            if ("ultra".equals(target)) {
                workerResult = new File(home, "root-worker-result.json");
                if (!workerResult.createNewFile()) throw new IOException("GHOSTLOCK_WORKER_RESULT_EXISTS");
                try { Os.chmod(workerResult.getPath(), 0600); }
                catch (ErrnoException error) { throw new IOException("GHOSTLOCK_WORKER_RESULT_MODE_FAILED", error); }
            }
            pending = RootShellLease.prepare(LeaseProtocol.Provider.GHOSTLOCK);
            List<String> argv = new ArrayList<>();
            argv.add(binary.getPath());
            argv.add("--maplesu-lease");
            argv.addAll(pending.consumerArguments());
            argv.add("--ghostlock-app-call");
            argv.add("--enable-status-record");
            if (target != null) {
                argv.add("--target"); argv.add(target);
                argv.add("--attempt"); argv.add(attemptId);
            }
            ProcessBuilder builder = new ProcessBuilder(argv);
            builder.environment().put("GHOSTLOCK_HOME", home.getPath());
            builder.environment().remove("GHOSTLOCK_KSUD");
            builder.environment().remove("GHOSTLOCK_KSU_LOG");
            builder.redirectErrorStream(true);
            DirtyfragAttempt.requireUnusedKernelWindow(context);
            provider = builder.start();
            DirtyfragAttempt.markKernelWindow(context, DirtyfragAttempt.readBootId());
            GhostlockWire wire = new GhostlockWire(snapshot, release, provider.getOutputStream());
            GhostlockAttempt attempt = new GhostlockAttempt(pending, provider);
            attempt.nativeLog = new File(diagnostics, "ghostlock-native.log");
            attempt.workerResult = workerResult;
            Thread reader = new Thread(() -> attempt.readProvider(wire, progress), "maplesu-ghostlock-status");
            reader.setDaemon(true);
            wire.writeProfile();
            reader.start();
            return attempt;
        } catch (IOException | RuntimeException error) {
            if (pending != null) pending.close();
            if (provider != null) {
                // The process owns only the ordinary-App parent. Do not signal
                // the upstream parked anchor or the detached worker's group.
                provider.destroy();
                closeQuietly(provider.getOutputStream());
                closeQuietly(provider.getInputStream());
                closeQuietly(provider.getErrorStream());
            }
            throw error;
        }
    }

    private void readProvider(GhostlockWire wire, Progress progress) {
        try (Reader reader = new InputStreamReader(provider.getInputStream(), StandardCharsets.UTF_8)) {
            ProviderOutputReader.read(reader, this::persist, value -> {
                // Store before ACK: the native parent can return immediately
                // after the dispatch transition is acknowledged.
                processState.observe(value);
                if (wire.acknowledge(value) && progress != null) {
                    String[] fields = value.split(" ");
                    try { progress.onStep(fields[1], fields[2]); }
                    catch (RuntimeException ignored) { /* UI observers do not own provider transport. */ }
                }
            });
            // Native parent EOF is expected after dispatch; detached worker may
            // still be restoring before it connects. Do not cancel on log EOF.
        } catch (IOException error) {
            if (!closed.get()) {
                channelFailure = error;
                persist("\nmaplesu-ghostlock: status channel failed: " + error + "\n");
                pending.close();
            }
        }
    }

    private void persist(String text) {
        if (nativeLog == null) return;
        try (java.io.FileOutputStream out = new java.io.FileOutputStream(nativeLog, true)) {
            out.write(text.getBytes(StandardCharsets.UTF_8));
        } catch (IOException error) { Log.w(TAG, "Writing native diagnostics failed", error); }
    }

    /** App-owned terminal record, separate from the shared backend's readiness receipt. */
    public File workerResult() { return workerResult; }

    public String providerStage() { return processState.stage(); }

    /** An exited parent before dispatch cannot produce a new worker receipt. */
    public String failureBeforeHandover() {
        try { return processState.failure(provider.exitValue()); }
        catch (IllegalThreadStateException running) { return null; }
    }

    /** Authenticated Process ownership transfers to caller; stage is RAW_ROOT_LEASE. */
    public RootShellLease await(long timeout, TimeUnit unit) throws IOException {
        try { return pending.await(timeout, unit); }
        catch (IOException error) {
            IOException failure = channelFailure;
            if (failure != null) error.addSuppressed(failure);
            throw error;
        }
    }

    /** Cancels the lease transport only; the provider owns its own restoration. */
    public void cancelPending() { pending.close(); }

    /**
     * Closes admission and provider pipes only. A returned lease belongs to its
     * caller and is not closed here. No process-tree/group kill and no removal
     * of a script that a detached worker may not yet have opened.
     */
    @Override public void close() {
        if (!closed.compareAndSet(false, true)) return;
        pending.close();
        provider.destroy();
        closeQuietly(provider.getOutputStream());
        closeQuietly(provider.getInputStream());
        closeQuietly(provider.getErrorStream());
    }

    private static void closeQuietly(Closeable stream) {
        try { stream.close(); } catch (IOException ignored) { }
    }
}
