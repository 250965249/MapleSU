package dev.maplesu.manager.jailbreak;

import android.net.Credentials;
import android.net.LocalServerSocket;
import android.net.LocalSocket;
import android.os.Process;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructPollfd;

import java.io.Closeable;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/** Authenticated raw shell only. Policy restoration and daemon handoff remain separate gates. */
public final class RootShellLease extends java.lang.Process implements Closeable {
    public static final String STAGE = "RAW_ROOT_LEASE";
    private static final ScheduledExecutorService TIMEOUTS = Executors.newSingleThreadScheduledExecutor(task -> {
        Thread thread = new Thread(task, "maplesu-lease-timeout");
        thread.setDaemon(true);
        return thread;
    });

    private final LeaseProtocol.Identity identity;
    private final LeaseProtocol.Restore restore;
    private final LocalSocket control;
    private final InputStream stdout;
    private final InputStream stderr;
    private final OutputStream stdin;
    private final int shellPid;
    private final CountDownLatch finished = new CountDownLatch(1);
    private final AtomicBoolean closed = new AtomicBoolean();
    private final AtomicBoolean handedOver = new AtomicBoolean();
    private volatile IOException failure;
    private volatile int code;

    private RootShellLease(LeaseProtocol.Identity identity, LeaseProtocol.Restore restore,
                           LocalSocket control, Pipes pipes, int shellPid) {
        this.identity = identity;
        this.restore = restore;
        this.control = control;
        this.stdin = pipes.stdin;
        this.stdout = pipes.stdout;
        this.stderr = pipes.stderr;
        this.shellPid = shellPid;
        Thread monitor = new Thread(() -> {
            try { complete(LeaseProtocol.readExit(control.getInputStream()), null); }
            catch (IOException error) { complete(0, error); close(); }
            finally { closeQuietly(control); }
        }, "maplesu-lease-control");
        monitor.setDaemon(true);
        monitor.start();
    }

    public LeaseProtocol.Identity identity() { return identity; }
    /** Restoration observed by the consumer before the shell was confirmed. */
    public LeaseProtocol.Restore restore() { return restore; }
    @Override public OutputStream getOutputStream() { return stdin; }
    @Override public InputStream getInputStream() { return stdout; }
    @Override public InputStream getErrorStream() { return stderr; }
    /** Shell pid; android.jar's Process has no pid(), so this is not an override. */
    public int shellPid() { return shellPid; }
    @Override public boolean isAlive() { return finished.getCount() != 0; }

    @Override public int waitFor() throws InterruptedException {
        finished.await();
        return completedCode();
    }

    @Override public boolean waitFor(long timeout, TimeUnit unit) throws InterruptedException {
        if (!finished.await(timeout, unit)) return false;
        completedCode();
        return true;
    }

    @Override public int exitValue() {
        if (isAlive()) throw new IllegalThreadStateException("LEASE_SHELL_RUNNING");
        return completedCode();
    }

    private int completedCode() {
        if (failure != null) throw new IllegalStateException("LEASE_CONTROL_FAILED", failure);
        return code;
    }

    private synchronized void complete(int exitCode, IOException error) {
        if (finished.getCount() == 0) return;
        code = exitCode;
        failure = error;
        finished.countDown();
    }

    /**
     * Hands the lease over to the Root executor that was just bound.
     *
     * S04 (review 2026-10-26): closing the transport right after a successful bind
     * used to make the privileged consumer treat the closure as a cancellation and
     * reap the executor it had just started. The frame is sent while the launcher
     * shell still exists and before any close, and it only tells the consumer not
     * to kill the detached executor.
     */
    public void confirmHandover() {
        if (closed.get()) return;
        if (!handedOver.compareAndSet(false, true)) return;
        synchronized (this) {
            try {
                control.getOutputStream().write('D');
                control.getOutputStream().flush();
            } catch (IOException ignored) {
                // The consumer keeps its conservative behaviour when the frame
                // cannot be delivered.
                handedOver.set(false);
            }
        }
    }

    public boolean handedOver() { return handedOver.get(); }

    /** Closing control cancels the native process group; no bytes enter the shell/profile channels. */
    @Override public void destroy() { close(); }
    @Override public RootShellLease destroyForcibly() { close(); return this; }
    @Override public void close() {
        if (!closed.compareAndSet(false, true)) return;
        // Process waiters must finish even if platform socket shutdown does not
        // immediately unblock the monitor thread. Cancellation is not exit 0.
        complete(0, new IOException("LEASE_CANCELLED"));
        closeQuietly(control);
        closeQuietly(stdin);
        closeQuietly(stdout);
        closeQuietly(stderr);
    }

    /** Create before launching a provider; no provider is invoked by this class. */
    public static PendingLease prepare(LeaseProtocol.Provider provider) throws IOException {
        if (provider == null) throw new NullPointerException("provider");
        int managerUid = Process.myUid();
        if (managerUid < 10000) throw new IOException("LEASE_ORDINARY_APP_UID_REQUIRED");
        byte[] bootBytes = new byte[129];
        int length = 0;
        try (InputStream input = new FileInputStream("/proc/sys/kernel/random/boot_id")) {
            while (length < bootBytes.length) {
                int count = input.read(bootBytes, length, bootBytes.length - length);
                if (count < 0) break;
                length += count;
            }
        }
        String boot = new String(bootBytes, 0, length, StandardCharsets.US_ASCII).trim();
        if (length > 128 || !LeaseProtocol.validBootId(boot))
            throw new IOException("LEASE_BOOT_ID_UNAVAILABLE");
        byte[] nonce = new byte[32];
        new SecureRandom().nextBytes(nonce);
        String endpoint = "maplesu-jb-" + UUID.randomUUID();
        return new PendingLease(provider, managerUid, boot, nonce, endpoint, new LocalServerSocket(endpoint));
    }

    public static final class PendingLease implements Closeable {
        private final LeaseProtocol.Provider provider;
        private final String bootId;
        private final byte[] nonce;
        private final LocalServerSocket server;
        private final List<String> arguments;
        private final AtomicBoolean awaiting = new AtomicBoolean();
        private LocalSocket accepted;
        private boolean closed;
        private boolean transferred;
        private boolean timedOut;

        private PendingLease(LeaseProtocol.Provider provider, int managerUid, String bootId, byte[] nonce,
                             String endpoint, LocalServerSocket server) {
            this.provider = provider;
            this.bootId = bootId;
            this.nonce = nonce;
            this.server = server;
            StringBuilder hex = new StringBuilder(64);
            for (byte value : nonce) hex.append(Character.forDigit((value >>> 4) & 15, 16))
                    .append(Character.forDigit(value & 15, 16));
            this.arguments = List.of(endpoint, hex.toString(), Integer.toString(managerUid), bootId, provider.argument);
        }

        /** Five arguments after the executable; nonce-bearing argv must not be logged. */
        public List<String> consumerArguments() { return arguments; }

        public List<String> consumerArgv(String consumerExecutable) {
            if (consumerExecutable == null || consumerExecutable.trim().isEmpty())
                throw new IllegalArgumentException("LEASE_CONSUMER_PATH_REQUIRED");
            List<String> argv = new ArrayList<>();
            argv.add(consumerExecutable);
            argv.addAll(arguments);
            return List.copyOf(argv);
        }

        /** Timeout covers accept, identity, ancillary transfer and actual shell-exec acknowledgement. */
        public RootShellLease await(long timeout, TimeUnit unit) throws IOException {
            if (timeout <= 0 || unit == null) throw new IllegalArgumentException("LEASE_TIMEOUT_INVALID");
            if (!awaiting.compareAndSet(false, true)) throw new IllegalStateException("LEASE_AWAIT_ALREADY_USED");
            ScheduledFuture<?> deadline = TIMEOUTS.schedule(() -> {
                synchronized (this) {
                    if (!transferred && !closed) { timedOut = true; close(); }
                }
            }, timeout, unit);
            Pipes pipes = null;
            boolean success = false;
            try {
                awaitConnection();
                LocalSocket socket = server.accept();
                synchronized (this) {
                    if (closed) { closeQuietly(socket); throw closedError(); }
                    accepted = socket;
                }
                closeQuietly(server);
                Credentials peer = socket.getPeerCredentials();
                LeaseProtocol.Identity identity = LeaseProtocol.readIdentity(socket.getInputStream(), provider,
                        nonce, bootId, peer.getPid(), peer.getUid());
                pipes = new Pipes();
                socket.setFileDescriptorsForSend(pipes.remote);
                try { socket.getOutputStream().write('A'); socket.getOutputStream().flush(); }
                finally { socket.setFileDescriptorsForSend(null); pipes.closeRemote(); }
                // Exec confirmation first: the shell must exist before the
                // consumer restores the entry policy, so a lease is never
                // reported for a shell that the restored policy refused. The
                // observation frame follows on the same transport.
                int child = LeaseProtocol.readReady(socket.getInputStream());
                LeaseProtocol.Restore restore = LeaseProtocol.readRestore(socket.getInputStream());
                synchronized (this) {
                    if (closed) throw closedError();
                    RootShellLease lease = new RootShellLease(identity, restore, socket, pipes, child);
                    transferred = true;
                    accepted = null;
                    Arrays.fill(nonce, (byte) 0);
                    success = true;
                    return lease;
                }
            } catch (IOException error) {
                synchronized (this) { if (timedOut) throw new SocketTimeoutException("LEASE_TIMEOUT"); }
                throw error;
            } finally {
                deadline.cancel(false);
                if (!success && pipes != null) pipes.close();
                close();
            }
        }

        private void awaitConnection() throws IOException {
            StructPollfd event = new StructPollfd();
            event.fd = server.getFileDescriptor();
            event.events = (short) OsConstants.POLLIN;
            while (true) {
                synchronized (this) { if (closed) throw closedError(); }
                try {
                    if (Os.poll(new StructPollfd[]{event}, 100) == 0) continue;
                } catch (ErrnoException error) {
                    if (error.errno == OsConstants.EINTR) continue;
                    throw new IOException("LEASE_ACCEPT_POLL_FAILED", error);
                }
                if ((event.revents & OsConstants.POLLIN) != 0) return;
                throw new IOException("LEASE_LISTENER_CLOSED");
            }
        }

        private IOException closedError() {
            return timedOut ? new SocketTimeoutException("LEASE_TIMEOUT") : new IOException("LEASE_PENDING_CLOSED");
        }

        @Override public synchronized void close() {
            if (closed) return;
            closed = true;
            closeQuietly(server);
            closeQuietly(accepted);
            accepted = null;
            Arrays.fill(nonce, (byte) 0);
        }
    }

    private static final class Pipes implements Closeable {
        final FileDescriptor[] remote = new FileDescriptor[3];
        OutputStream stdin;
        InputStream stdout;
        InputStream stderr;

        Pipes() throws IOException {
            try {
                FileDescriptor[] pair = pipe(); remote[0] = pair[0]; stdin = output(pair[1]);
                pair = pipe(); remote[1] = pair[1]; stdout = input(pair[0]);
                pair = pipe(); remote[2] = pair[1]; stderr = input(pair[0]);
            } catch (IOException | RuntimeException error) { close(); throw error; }
        }

        private static InputStream input(FileDescriptor fd) {
            try { return new FileInputStream(fd); }
            catch (RuntimeException error) { closeFd(fd); throw error; }
        }

        private static OutputStream output(FileDescriptor fd) {
            try { return new FileOutputStream(fd); }
            catch (RuntimeException error) { closeFd(fd); throw error; }
        }

        private static FileDescriptor[] pipe() throws IOException {
            FileDescriptor[] pair = null;
            try {
                pair = Os.pipe();
                for (FileDescriptor fd : pair) Os.fcntlInt(fd, OsConstants.F_SETFD, OsConstants.FD_CLOEXEC);
                return pair;
            } catch (ErrnoException error) {
                if (pair != null) for (FileDescriptor fd : pair) closeFd(fd);
                throw new IOException("LEASE_PIPE_FAILED", error);
            }
        }

        void closeRemote() {
            for (int i = 0; i < remote.length; i++) { closeFd(remote[i]); remote[i] = null; }
        }
        @Override public void close() {
            closeRemote(); closeQuietly(stdin); closeQuietly(stdout); closeQuietly(stderr);
        }
    }

    private static void closeQuietly(Closeable value) {
        if (value != null) try { value.close(); } catch (IOException ignored) { }
    }

    private static void closeQuietly(LocalSocket value) {
        if (value == null) return;
        try { value.shutdownOutput(); } catch (IOException ignored) { }
        try { value.shutdownInput(); } catch (IOException ignored) { }
        closeQuietly((Closeable) value);
    }

    private static void closeFd(FileDescriptor fd) {
        if (fd != null) try { Os.close(fd); } catch (ErrnoException ignored) { }
    }
}
