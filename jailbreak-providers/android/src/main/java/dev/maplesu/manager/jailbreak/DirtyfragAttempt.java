package dev.maplesu.manager.jailbreak;

import android.content.Context;
import android.util.Log;
import android.os.Build;
import android.system.ErrnoException;
import android.system.Os;

import java.io.Closeable;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Ordinary-App DirtyFrag attempt: artifact verification, private staging, the
 * App-side IpSec frame, the pinned native first stage and the authenticated
 * lease. Nothing here starts a daemon, marks the App installed or restores
 * policy: the privileged consumer restores and reports on the lease transport.
 */
public final class DirtyfragAttempt implements Closeable {
    private static final String TAG = "MapleSuDirtyfrag";
    public interface Progress {
        void onStep(String step, String status);
    }

    /** Exact target and artifact identity used for this attempt. */
    public record Admission(String kernelRelease, String kmi, String androidRelease,
                            String koVariant, String koSha256, String firstStageSha256,
                            String bootstrapSha256, String consumerSha256,
                            int enforcingBefore, String bootId, String targetId,
                            String fingerprint, String soc, String securityPatch,
                            String verdict) {
        /**
         * Pre-entry enforcing value as far as an ordinary App can observe it.
         * {@code -1} means selinuxfs is not readable from this domain; the
         * privileged consumer then applies the documented release baseline, labels
         * it as a baseline and keeps it distinguishable from the observed value.
         */
        public String enforcingField() { return enforcingBefore < 0 ? "u" : Integer.toString(enforcingBefore); }
    }

    static final String DIRECTORY = "maplesu-dirtyfrag.attempt";
    /** Published by the native stage only after it verified every restore. */
    static final String DISARM = "maplesu-disarmed";
    /**
     * Route marker for the KernelSU (Normal) handoff.
     *
     * The privileged helper already implements the reference sequence - switch to
     * {@code u:r:init:s0} while SELinux is still permissive, run
     * {@code ksud late-load --package-name <manager>}, wait for the detached daemon,
     * then {@code ksud soft-reboot} in {@code u:r:ksu:s0}. What was missing is only
     * this marker: the daemon path and the eighth attempt field were already staged
     * on every attempt, so the route existed but could never be selected.
     */
    static final String USE_KSU = "use-ksu";
    /**
     * The manager the KernelSU kernel module must recognise. It is this app: the
     * module we ship was built with this package and checks this APK signature, so
     * root is granted to MapleSU's own manager and to nothing else. A foreign
     * manager's ksud would be refused by the module, which is why the daemon is
     * staged from our own native library instead.
     */
    public static final String KSU_MANAGER_PACKAGE = "dev.maplesu.manager";
    /** Our own KernelSU daemon, staged as {@code ksud}; never another app's. */
    static final String KSU_DAEMON_LIBRARY = "libksud_ksu.so";
    private static final Pattern MAJOR_MINOR = Pattern.compile("^(\\d+)\\.(\\d+)");
    private static final Pattern ANDROID = Pattern.compile("android(\\d+)");
    private static final int LOG_LIMIT = 64 * 1024;

    private final RootShellLease.PendingLease pending;
    private final Process provider;
    private final DirtyfragIpSecSession session;
    private final File config;
    private final List<String> log = new ArrayList<>();
    private final AtomicBoolean closed = new AtomicBoolean();
    private volatile IOException channelFailure;

    private DirtyfragAttempt(RootShellLease.PendingLease pending, Process provider,
                            DirtyfragIpSecSession session, File config) {
        this.pending = pending;
        this.provider = provider;
        this.session = session;
        this.config = config;
    }

    /**
     * Exact KMI observation for the pinned module set. A missing match is recorded
     * as unknown; the native worker retains the reference family fallback and
     * reports which module it actually selects.
     */
    static String exactKmi(String release) throws IOException {
        Matcher versions = MAJOR_MINOR.matcher(release);
        Matcher android = ANDROID.matcher(release);
        if (!versions.find()) throw new IOException("DIRTYFRAG_KERNEL_VERSION_UNPARSABLE");
        if (!android.find()) throw new IOException("DIRTYFRAG_KERNEL_ANDROID_RELEASE_MISSING");
        int major = Integer.parseInt(versions.group(1));
        int minor = Integer.parseInt(versions.group(2));
        int api = Integer.parseInt(android.group(1));
        String[][] table = {
                {"12", "5", "10", "android12-5.10"}, {"13", "5", "10", "android13-5.10"},
                {"13", "5", "15", "android13-5.15"}, {"14", "5", "15", "android14-5.15"},
                {"14", "6", "1", "android14-6.1"}, {"15", "6", "6", "android15-6.6"},
                {"16", "6", "12", "android16-6.12"}, {"17", "6", "18", "android17-6.18"},
        };
        for (String[] row : table) {
            if (Integer.parseInt(row[0]) == api && Integer.parseInt(row[1]) == major &&
                    Integer.parseInt(row[2]) == minor) return row[3];
        }
        throw new IOException("DIRTYFRAG_EXACT_KMI_UNSUPPORTED:" + api + "-" + major + "." + minor);
    }

    static int readEnforcing() {
        try (InputStream input = Files.newInputStream(new File("/sys/fs/selinux/enforce").toPath())) {
            int value = input.read();
            return value == '0' ? 0 : value == '1' ? 1 : -1;
        } catch (IOException error) {
            return -1;
        }
    }


    /** Boot id that already spent this boot's kernel-side attempt, or null. */
    private static String readKernelWindow(Context context) {
        File file = new File(context.getFilesDir(), "jailbreak-kernel-window");
        if (!file.isFile()) return null;
        try {
            return new String(Files.readAllBytes(file.toPath()), StandardCharsets.US_ASCII).trim();
        } catch (IOException error) {
            return null;
        }
    }

    /** Records that this boot's kernel-side attempt has been spent. */
    static void markKernelWindow(Context context, String bootId) {
        File file = new File(context.getFilesDir(), "jailbreak-kernel-window");
        try {
            Files.write(file.toPath(), bootId.getBytes(StandardCharsets.US_ASCII));
        } catch (IOException ignored) {
            // Best effort: the guard still protects the common path.
        }
    }

    /** Public so the provider can refuse to resume a claim from another boot. */
    static void requireUnusedKernelWindow(Context context) throws IOException {
        String boot = readBootId();
        if (boot == null) throw new IOException("GHOSTLOCK_BOOT_ID_MISSING");
        if (boot.equals(readKernelWindow(context)))
            throw new IOException("DIRTYFRAG_REBOOT_REQUIRED_AFTER_ATTEMPT");
    }

    public static String readBootId() {
        try {
            String value = new String(Files.readAllBytes(new File("/proc/sys/kernel/random/boot_id").toPath()),
                    StandardCharsets.US_ASCII).trim();
            return LeaseProtocol.validBootId(value) ? value : null;
        } catch (IOException error) {
            return null;
        }
    }

    /** IO thread only. Refuses any target whose packaged artifacts are not the admitted ones. */
    public static Admission admit(Context context) throws IOException {
        if (context == null) throw new NullPointerException("context");
        // The provider helper path, its configuration file and the privileged log
        // are all bound to user 0. A secondary or work-profile copy is not this
        // target and must be refused before a transient exists, not after a
        // timeout with the device already permissive.
        final int userId = android.os.Process.myUid() / 100000;
        if (userId != 0)
            throw new IOException("DIRTYFRAG_SECONDARY_USER_UNSUPPORTED:" + userId);
        String release = Os.uname().release;
        boolean kmiPackaged;
        String kmi;
        try {
            kmi = exactKmi(release);
            kmiPackaged = true;
        } catch (IOException error) {
            kmi = "";
            kmiPackaged = false;
        }
        String abi = Build.SUPPORTED_ABIS.length == 0 ? "" : Build.SUPPORTED_ABIS[0];
        if (!"arm64-v8a".equals(abi)) throw new IOException("DIRTYFRAG_ABI_UNSUPPORTED:" + abi);
        /*
         * /dev/df is the hook's one-shot re-entry guard. Only the privileged side can
         * remove it, so an attempt that ended without a verified restore leaves it in
         * place and every later attempt would silently never fire the hook. Refuse
         * with a named reason instead of walking into that dead end.
         */
        if (new File("/dev/df").exists())
            throw new IOException("DIRTYFRAG_GUARD_PRESENT_REBOOT_REQUIRED");
        String fingerprint = Build.FINGERPRINT == null ? "" : Build.FINGERPRINT;
        String soc = Build.SOC_MODEL == null ? "" : Build.SOC_MODEL;
        String patch = Build.VERSION.SECURITY_PATCH == null ? "" : Build.VERSION.SECURITY_PATCH;
        JailbreakTargets.Verdict verdict = JailbreakTargets.verdict(
                JailbreakTargets.PROVIDER_DIRTYFRAG, release, fingerprint, soc, patch, kmiPackaged);
        String targetId = JailbreakTargets.targetId(
                JailbreakTargets.PROVIDER_DIRTYFRAG, release, fingerprint, soc, patch);
        // Product policy: an unmeasured build is a warning, not a refusal. The
        // provider runs and reports its own outcome, which is what keeps these
        // providers attemptable on a device the table does not list yet.
        if (verdict != JailbreakTargets.Verdict.VERIFIED_TARGET)
            Log.w(TAG, "unmeasured build, attempting anyway: " + targetId + " kmi=" + kmi);
        JailbreakArtifacts.Entry first = JailbreakArtifacts.require(context, "libdfroot.so");
        JailbreakArtifacts.Entry bootstrap =
                JailbreakArtifacts.require(context, "libmaplesu_dirtyfrag_bootstrap.so");
        JailbreakArtifacts.Entry consumer =
                JailbreakArtifacts.require(context, "libmaplesu_root_consumer.so");
        String bootId = readBootId();
        if (bootId == null) throw new IOException("DIRTYFRAG_BOOT_ID_UNAVAILABLE");
        /*
         * The kernel-side work of one attempt is not fully reversible: the module
         * patches kernel text for its own dispatch path and unloads itself, so the
         * patches stay for the rest of this boot. Measured on this device: the first
         * attempt after a boot completes, later ones destabilise the kernel and the
         * device reboots. Refuse a second attempt in the same boot with a named
         * reason instead of walking into that.
         */
        String used = readKernelWindow(context);
        if (bootId.equals(used))
            throw new IOException("DIRTYFRAG_REBOOT_REQUIRED_AFTER_ATTEMPT");
        // The ordinary App is not allowed to read selinuxfs, so an unreadable
        // value is a documented observation gap, not an admission failure: the
        // consumer applies the release baseline and reports that it assumed it.
        int enforcing = readEnforcing();
        return new Admission(release, kmi, Build.VERSION.RELEASE, first.koVariant(), first.koSha256(kmi),
                first.sha256(), bootstrap.sha256(), consumer.sha256(), enforcing, bootId, targetId,
                fingerprint, soc, patch, verdict.name());
    }

    /** Publishes the two ART variables the launcher needs, without any secret. */
    static void writeRuntimeEnvironment(File directory) throws IOException {
        String boot = System.getenv("BOOTCLASSPATH");
        String dex = System.getenv("DEX2OATBOOTCLASSPATH");
        if (boot == null || boot.isEmpty()) return;
        File file = new File(directory, "maplesu-env");
        String content = "BOOTCLASSPATH=" + boot + "\n"
                + "DEX2OATBOOTCLASSPATH=" + (dex == null ? "" : dex) + "\n";
        try (FileOutputStream output = new FileOutputStream(file)) {
            output.write(content.getBytes(StandardCharsets.UTF_8));
        }
        if (!file.setReadable(true, false)) throw new IOException("DIRTYFRAG_ENV_UNREADABLE");
    }

    static File attemptDirectory(Context context) throws IOException {
        File directory = context.createDeviceProtectedStorageContext().getDataDir();
        if (!directory.isDirectory() && !directory.mkdirs() && !directory.isDirectory())
            throw new IOException("DIRTYFRAG_ATTEMPT_DIRECTORY_MISSING");
        try { Os.chmod(directory.getPath(), 0700); }
        catch (ErrnoException error) { throw new IOException("DIRTYFRAG_ATTEMPT_DIRECTORY_MODE", error); }
        return directory;
    }

    /**
     * Stages the privileged bootstrap where the committed module dispatches it.
     * The module carries that path in a fixed-width array, so the staged name is
     * the bounded one recorded in the overlay manifest ("bs"), never a renamed
     * equivalent of another package's directory.
     */
    /** The staged one-shot bootstrap, or null when this attempt never staged one. */
    private static volatile File stagedBootstrap;

    static void stageBootstrap(Context context, File directory) throws IOException {
        File source = new File(context.getApplicationInfo().nativeLibraryDir,
                "libmaplesu_dirtyfrag_bootstrap.so");
        if (!source.isFile()) throw new IOException("DIRTYFRAG_BOOTSTRAP_MISSING");
        File home = context.getFilesDir().getParentFile();
        if (home == null) throw new IOException("DIRTYFRAG_DATA_DIRECTORY_MISSING");
        File target = new File(home, "bs");
        Files.copy(source.toPath(), target.toPath(), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        try { Os.chmod(target.getPath(), 0700); }
        catch (ErrnoException error) { throw new IOException("DIRTYFRAG_BOOTSTRAP_MODE", error); }
        stagedBootstrap = target;
    }


    /**
     * Stages <b>our own</b> KernelSU daemon ({@code libksud_ksu.so}) as the ksud the
     * helper runs.
     *
     * <p>Borrowing another manager's ksud is deliberately not done: the kernel module
     * we load was built for this product, checks this app's package and signature, and
     * would refuse to serve a different manager. "Who gets root" has to be MapleSU, so
     * the daemon, the package name and the module must all agree.
     *
     * <p>Returns null when the packaged daemon is missing; the KSU route turns that
     * into a named failure instead of falling back to another route.
     */
    static String stageKernelSuDaemon(Context context) {
        String nativeDir = context.getApplicationInfo().nativeLibraryDir;
        if (nativeDir == null) return null;
        File source = new File(nativeDir, KSU_DAEMON_LIBRARY);
        if (!source.isFile() || !source.canExecute()) return null;
        File home = context.getFilesDir().getParentFile();
        if (home == null) return null;
        File target = new File(home, "ksud");
        try {
            Files.copy(source.toPath(), target.toPath(),
                    java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            Os.chmod(target.getPath(), 0700);
            return target.getPath();
        } catch (Exception error) {
            return null;
        }
    }

    private static void publishConfig(File directory, List<String> lines) throws IOException {
        StringBuilder text = new StringBuilder();
        for (String line : lines) {
            if (line == null || line.isEmpty() || line.indexOf('\n') >= 0 || line.indexOf('\r') >= 0)
                throw new IOException("DIRTYFRAG_CONFIG_FIELD_INVALID");
            text.append(line).append('\n');
        }
        // The privileged launcher is a child of a kernel helper, so it inherits no
        // Android runtime environment at all. app_process64 aborts with
        // "BOOTCLASSPATH and DEX2OATBOOTCLASSPATH must not be empty" unless these
        // are provided; the App process still has them from zygote.
        writeRuntimeEnvironment(directory);
        File config = new File(directory, DIRECTORY);
        Files.deleteIfExists(config.toPath());
        try (OutputStream output = new FileOutputStream(config, false)) {
            output.write(text.toString().getBytes(StandardCharsets.UTF_8));
        }
        try { Os.chmod(config.getPath(), 0600); }
        catch (ErrnoException error) {
            Files.deleteIfExists(config.toPath());
            throw new IOException("DIRTYFRAG_CONFIG_MODE", error);
        }
    }

    /**
     * IO thread only. Creates the lease endpoint first, then the one-shot
     * privileged input, then the App IpSec frame and the native process, so the
     * kernel helper can never run without an endpoint to authenticate against.
     */
    public static DirtyfragAttempt start(Context context, Admission admission, Progress progress)
            throws IOException {
        return start(context, admission, progress, false);
    }

    /**
     * IO thread only, in-kernel root (IR) route.
     *
     * <p>Same attempt document and same first stage; the difference is what is
     * staged beside the bootstrap. With {@code irRoute} the App publishes the
     * module and this release's spec plus the {@code use-ir} marker, and the
     * bootstrap loads the module instead of exec'ing the consumer. The lease
     * endpoint is still created because the attempt document carries its fields and
     * the bootstrap validates them before it looks at any route marker; on this
     * route nobody ever claims it and the executor closes it with the attempt.
     *
     * <p>{@code IrImages.stage} throws {@code MAPLESU_IR_UNSUPPORTED:<release>} when
     * the build carries no spec for this kernel, which is what the caller must
     * surface before a single kernel-side action happens.
     */
    public static DirtyfragAttempt start(Context context, Admission admission, Progress progress,
                                         boolean irRoute) throws IOException {
        return start(context, admission, progress, irRoute, false);
    }

    /**
     * As above, plus the W0 switch: {@code irNoReboot} keeps the device in the
     * current boot after the patches land, so a caller can probe ART in exactly
     * that kernel state. It exists for the W0 decision experiment and must never be
     * set by a product path.
     */
    public static DirtyfragAttempt start(Context context, Admission admission, Progress progress,
                                         boolean irRoute, boolean irNoReboot) throws IOException {
        return start(context, admission, progress, irRoute, irNoReboot, null);
    }

    /**
     * Step-4 (D2, design §3.5 item 22): the hook route's pre-entry baseline.
     *
     * <p>{@code hookAttemptId} is the hook marker - <b>not</b> {@code irRoute}, which both
     * the in-kernel route and the hook route set - and when it is non-null this method
     * writes {@code <DE>/maplesu-hook-env} <em>after</em> {@code publishConfig} and
     * <em>before</em> the provider process starts. That ordering is load-bearing: the
     * kernel helper only runs after the provider starts, so the env has to be on disk by
     * then, and the staging calls above must not be able to overwrite it.
     *
     * <p>Failure to write is fatal for the attempt: without an env the helper has no
     * target, and a target it guessed could leave the device permissive.
     */
    public static DirtyfragAttempt start(Context context, Admission admission, Progress progress,
                                         boolean irRoute, boolean irNoReboot,
                                         String hookAttemptId) throws IOException {
        return start(context, admission, progress, irRoute, irNoReboot, hookAttemptId, false);
    }

    /**
     * Normal (KernelSU) route: the reference DirtyFragX handoff, unchanged in shape.
     *
     * <p>The kernel helper performs it; this method only makes the route selectable
     * and refuses to start when there is nothing to hand over to. Borrowing the
     * installed KernelSU manager's own {@code ksud} is deliberate and matches the
     * reference: that binary carries the {@code <kmi>_kernelsu.ko} asset for its KMI,
     * while our own fork's ksud does not embed one yet, and the kernel module
     * identity ({@code --package-name}) must be the manager whose signature the
     * kernel checks.
     *
     * <p>Fails closed with {@code MAPLESU_KSU_DAEMON_MISSING} when no KernelSU manager
     * is installed, rather than silently running the consumer route: a caller that
     * asked for Normal must never be given Ultra's installation.
     */
    public static DirtyfragAttempt startKernelSu(Context context, Admission admission,
                                                 Progress progress) throws IOException {
        return start(context, admission, progress, false, false, null, true);
    }

    private static DirtyfragAttempt start(Context context, Admission admission, Progress progress,
                                          boolean irRoute, boolean irNoReboot,
                                          String hookAttemptId, boolean ksuRoute)
            throws IOException {
        if (context == null || admission == null) throw new NullPointerException("context");
        if (!Os.uname().release.equals(admission.kernelRelease()))
            throw new IOException("DIRTYFRAG_KERNEL_CHANGED_SINCE_ADMISSION");
        String nativeDir = context.getApplicationInfo().nativeLibraryDir;
        if (nativeDir == null) throw new IOException("DIRTYFRAG_NATIVE_DIRECTORY_MISSING");
        File first = new File(nativeDir, "libdfroot.so").getCanonicalFile();
        File consumer = new File(nativeDir, "libmaplesu_root_consumer.so").getCanonicalFile();
        if (!first.isFile() || !first.canExecute() || !consumer.isFile() || !consumer.canExecute())
            throw new IOException("DIRTYFRAG_PACKAGED_ENTRIES_MISSING");
        File directory = attemptDirectory(context);
        /*
         * Route inputs before anything is dispatched. A stale marker from an earlier
         * attempt would silently select the previous route, so the non-IR path clears
         * the IR inputs and the IR path rewrites all three files itself.
         *
         * Step-3 ordering is load-bearing: IrImages.stage() may remove the stale
         * step-2 canary helper name, and stageBootstrap() (below, on every route) is
         * what writes the `<CE>/bs` the module execs with --umh. Staging the bootstrap
         * first and the route inputs second would let that cleanup delete the handover
         * target. Never swap these two calls.
         */
        // Step-4 (item 24/Q-D6): this attempt's hook artifacts must not be able to speak
        // for a previous one. Best effort, and before any staging: the App owns this
        // directory, the socket name is attempt-prefixed so a survivor cannot collide
        // anyway, and a failure here must not abort an attempt.
        if (hookAttemptId != null) clearStaleHookArtifacts(directory);
        if (hookAttemptId != null) IrImages.stageForHook(context, directory, admission.kernelRelease());
        else if (irRoute) IrImages.stage(context, directory, admission.kernelRelease(), irNoReboot);
        else IrImages.clear(directory);
        /*
         * Hook route (Ultra): the UMH helper loads its module from the attempt
         * directory under a fixed name. Nothing staged that file before, so the route
         * could never load anything even when every other check passed. A build that
         * packages no root module refuses here rather than half-way through.
         */
        if (hookAttemptId != null && IrImages.stageHookModule(context, directory) == null)
            throw new IOException("MAPLESU_HOOK_NOT_PACKAGED");
        /*
         * The worker cannot listen (its socket would keep the kernel sid, DEV-174) and it
         * outlives this process, so the listener has to exist before the attempt starts.
         * It records what the worker proves; the claim reads that record.
         */
        if (hookAttemptId != null)
            dev.maplesu.manager.jailbreak.HookAttestServer.listen(
                context, hookAttemptId, readBootId(), 300000);
        stageBootstrap(context, directory);
        File stageLog = new File(directory, "native-stage.log");
        if (stageLog.exists() && !stageLog.delete())
            throw new IOException("DIRTYFRAG_STAGE_LOG_UNWRITABLE");
        // A teardown record from an earlier attempt must not be read as this one's.
        File staleTeardown = new File(directory, "maplesu-teardown");
        if (staleTeardown.exists() && !staleTeardown.delete())
            throw new IOException("DIRTYFRAG_TEARDOWN_RECORD_UNWRITABLE");
        nativeLog = stageLog;
        // A stale disarm proof from an earlier attempt would let the privileged
        // side remove the re-entry guard before this attempt disarmed its own hook.
        // S08: the consumer uses <device-protected data dir>/maplesu-disarmed - this
        // directory, not its parent. The wrong level left a stale proof that a later
        // attempt could accept before its own stage disarmed.
        File disarm = new File(directory, DISARM);
        if (!disarm.delete() && disarm.exists())
            throw new IOException("DIRTYFRAG_DISARM_STATE_UNWRITABLE");

        RootShellLease.PendingLease pending = null;
        DirtyfragIpSecSession session = null;
        Process provider = null;
        File config = new File(directory, DIRECTORY);
        try {
            pending = RootShellLease.prepare(LeaseProtocol.Provider.DIRTYFRAG);
            List<String> fields = new ArrayList<>();
            fields.add(consumer.getPath());
            fields.addAll(pending.consumerArguments());
            fields.add(admission.enforcingField());
            /*
             * Reference parity: stage the installed KernelSU daemon and hand the
             * escalation to it, so a kernel-side SU owns root after the reboot. Absent
             * KernelSU, the field is omitted and the consumer fallback is used.
             */
            String ksud = stageKernelSuDaemon(context);
            if (ksud != null) fields.add(ksud);
            publishConfig(directory, fields);
            /*
             * Route marker, written only after the document that carries the daemon
             * path exists. Both directions matter: without it the helper falls through
             * to the consumer route (KernelSU never runs), and a stale one from an
             * earlier attempt would hijack a later Ultra attempt into the KSU route.
             */
            File ksuMarker = new File(directory, USE_KSU);
            if (ksuRoute) {
                if (ksud == null) throw new IOException("MAPLESU_KSU_DAEMON_MISSING");
                if (!ksuMarker.isFile() && !ksuMarker.createNewFile())
                    throw new IOException("MAPLESU_KSU_MARKER_UNWRITABLE");
            } else if (ksuMarker.exists() && !ksuMarker.delete()) {
                throw new IOException("MAPLESU_KSU_MARKER_UNWRITABLE");
            }
            /*
             * Step-4 (D2): the App is the only subject that was alive before the kernel
             * window opened, so it is the only one that can name the restore target - and
             * it reports a target *plus its provenance*, not an observation (an ordinary
             * App cannot read selinuxfs either; R3 recorded enforcingBefore = -1).
             */
            if (hookAttemptId != null) {
                String bootId = admission.bootId();
                if (bootId == null || bootId.isEmpty()
                        || !HookEnv.write(directory, hookAttemptId, bootId, readEnforcing()))
                    throw new IOException("DIRTYFRAG_HOOK_ENV_UNWRITABLE");
            }
            if (progress != null) progress.onStep("staged", "config=" + DIRECTORY + " kmi=" + admission.kmi());

            try {
                session = DirtyfragIpSecSession.open(context);
            } catch (IOException error) {
                throw error;
            } catch (Exception error) {
                throw new IOException("DIRTYFRAG_IPSEC_SETUP_FAILED", error);
            }
            List<String> argv = new ArrayList<>();
            argv.add(first.getPath());
            argv.addAll(session.nativeArguments());
            argv.add("--expect-release");
            argv.add(admission.kernelRelease());
            ProcessBuilder builder = new ProcessBuilder(argv);
            builder.environment().remove("LD_PRELOAD");
            builder.redirectErrorStream(true);
            provider = builder.start();
            DirtyfragAttempt attempt = new DirtyfragAttempt(pending, provider, session, config);
            JailbreakStatus status = JailbreakStatus.Companion.read(context);
            if (status != null && status.getAttemptId() != null) {
                attempt.attemptLog = new File(JailbreakDiagnostics.attemptDirectory(
                        context.getFilesDir(), status.getAttemptId()), "dirtyfrag-native.log");
            }
            Thread reader = new Thread(() -> attempt.readProvider(progress), "maplesu-dirtyfrag-stage");
            reader.setDaemon(true);
            reader.start();
            if (progress != null) progress.onStep("native", "first stage started");
            return attempt;
        } catch (IOException | RuntimeException error) {
            if (pending != null) pending.close();
            if (session != null) try { session.close(); } catch (IOException ignored) { }
            if (provider != null) {
                provider.destroy();
                closeQuietly(provider.getOutputStream());
                closeQuietly(provider.getInputStream());
                closeQuietly(provider.getErrorStream());
            } else {
                Files.deleteIfExists(config.toPath());
            }
            // The staged one-shot bootstrap must not survive a failed start either.
            File staged = stagedBootstrap;
            if (staged != null) {
                try { Files.deleteIfExists(staged.toPath()); } catch (IOException ignored) { }
                stagedBootstrap = null;
            }
            throw error;
        }
    }

    private void readProvider(Progress progress) {
        try (Reader reader = new InputStreamReader(provider.getInputStream(), StandardCharsets.UTF_8)) {
            ProviderOutputReader.read(reader, this::persist, value -> record(value, progress));
        } catch (IOException error) {
            if (!closed.get()) { channelFailure = error; pending.close(); }
        }
    }

    private void record(String value, Progress progress) {
        synchronized (log) {
            if (log.size() < 512) log.add(value);
            else if (log.size() == 512) log.add("[truncated]");
        }
        if (progress != null) try { progress.onStep("native", value); }
        catch (RuntimeException ignored) { /* observers never own the transport */ }
    }

    /** Diagnostics of the native first stage only; never a readiness proof. */
    public List<String> log() {
        synchronized (log) { return List.copyOf(log); }
    }

    /** Last attempt's native output, for the caller to read after the stage ends. */
    private static volatile File nativeLog;
    private File attemptLog;

    private void persist(String value) {
        persistTo(nativeLog, value);
        persistTo(attemptLog, value);
    }

    private static void persistTo(File target, String value) {
        if (target == null) return;
        try (java.io.FileOutputStream out = new java.io.FileOutputStream(target, true)) {
            out.write(value.getBytes(StandardCharsets.UTF_8));
        } catch (IOException ignored) {
            // Diagnostics must never break the attempt.
        }
    }

    /**
     * Waits for the native first stage to finish. Its verified-restoration report
     * is written last, so the process must be allowed to reach its own exit; the
     * caller must never destroy it first, or the device keeps the modified pages.
     */
    public boolean awaitStageExit(long timeout, TimeUnit unit) {
        try { return provider.waitFor(timeout, unit); }
        catch (InterruptedException error) { Thread.currentThread().interrupt(); return false; }
    }

    /** Authenticated Process ownership transfers to the caller; stage is RAW_ROOT_LEASE. */
    public RootShellLease await(long timeout, TimeUnit unit) throws IOException {
        try { return pending.await(timeout, unit); }
        catch (IOException error) {
            IOException failure = channelFailure;
            if (failure != null) error.addSuppressed(failure);
            throw error;
        }
    }

    /**
     * Cancels the lease transport only. The native stage is left alone on purpose:
     * its restoration report is the cleanup proof, so destroying it here would
     * keep the modified pages on the device.
     */
    public void cancelPending() { pending.close(); }

    /** Closes admission, the App IpSec frame and the process pipes; a lease is not closed here. */
    @Override public void close() {
        if (!closed.compareAndSet(false, true)) return;
        pending.close();
        try { session.close(); } catch (IOException ignored) { }
        provider.destroy();
        closeQuietly(provider.getOutputStream());
        closeQuietly(provider.getInputStream());
        closeQuietly(provider.getErrorStream());
        try { Files.deleteIfExists(config.toPath()); } catch (IOException ignored) { }
        /*
         * The staged bootstrap is a one-shot artifact: leaving an executable copy
         * behind is both a hygiene problem and an extra detection surface.
         */
        File staged = stagedBootstrap;
        if (staged != null) {
            try {
                java.nio.file.Files.deleteIfExists(staged.toPath());
            } catch (IOException | RuntimeException ignored) {
                // Best effort: the next attempt overwrites it anyway.
            }
            stagedBootstrap = null;
        }
}

    private static void closeQuietly(Closeable stream) {
        try { stream.close(); } catch (IOException ignored) { }
    }

    /** Reads the privileged-half log through an established root shell. */
    public static List<String> privilegedLog(RootShellLease lease, int limit) {
        File log = new File(attemptDirectoryUnchecked(), "maplesu-provider.log");
        List<String> lines = new ArrayList<>();
        String command = "/system/bin/cat " + log.getPath() + " 2>/dev/null; "
                + "/system/bin/cat /dev/maplesu-provider.log 2>/dev/null";
        try {
            OutputStream input = lease.getOutputStream();
            input.write((command + "\n").getBytes(StandardCharsets.UTF_8));
            input.flush();
            lines.add("requested: " + command);
        } catch (IOException error) {
            lines.add("request failed: " + error.getMessage());
        }
        return lines;
    }

    private static File attemptDirectoryUnchecked() {
        return new File("/data/user_de/0/" + "dev.maplesu.manager");
    }

    /**
     * The device-protected attempt directory the privileged half writes its evidence
     * into. Step-3 adds two files here (design §5.4): {@code maplesu-hook.json} from
     * the UMH helper's parent process and {@code maplesu-hook-unload.json} from its
     * forked unload child. The executor and the androidTest trigger both read them
     * through this one accessor, so "where the evidence lives" has a single answer.
     *
     * <p>Read-only with respect to the attempt: this never creates or cleans the
     * directory, and it is deliberately not part of {@link #close()} - the evidence has
     * to survive the attempt object.
     */
    public static File hookEvidence(Context context) {
        return context.createDeviceProtectedStorageContext().getDataDir();
    }

    /**
     * Step-4 (item 23): the pre-entry baseline file, in the same directory as the
     * evidence. Single answer to "where does the App's hook input live", so the helper's
     * constant and this accessor cannot drift.
     */
    public static File hookEnvFile(Context context) {
        return new File(hookEvidence(context), "maplesu-hook-env");
    }

    /**
     * Step-4 (item 24): removes last attempt's daemon document and any attempt-prefixed
     * sockets. Never fatal: the socket name carries the new attempt's prefix, so a
     * survivor cannot be mistaken for this attempt's worker - deleting only makes the
     * directory readable.
     */
    static void clearStaleHookArtifacts(File directory) {
        try {
            File document = new File(directory, "maplesu-hook-daemon.json");
            if (document.exists()) document.delete();
            File[] sockets = directory.listFiles((dir, name) ->
                    name.startsWith("maplesu-hook-") && name.endsWith(".sock"));
            if (sockets == null) return;
            for (File socket : sockets) socket.delete();
        } catch (RuntimeException ignored) {
            // Diagnostics never break an attempt; the attempt-prefixed name prevents reuse.
        }
    }
}
