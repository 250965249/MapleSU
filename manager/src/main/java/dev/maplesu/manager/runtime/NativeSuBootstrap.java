package dev.maplesu.manager.runtime;

import android.os.Binder;
import android.os.Bundle;
import android.os.ParcelFileDescriptor;
import android.os.Process;
import android.util.Log;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.concurrent.atomic.AtomicBoolean;

/** Same-UID app_process companion. The authenticated broker decides whether this UID may execute. */
public final class NativeSuBootstrap {
    private NativeSuBootstrap() {}
    private static native void sendTerminal(int control, int terminal) throws IOException;

    private static INativeSuService discover(int callerUid) throws Exception {
        return INativeSuService.Stub.asInterface(NativeSuDiscovery.peek(callerUid));
    }
    public static void main(String[] args) {
        int status = 69;
        if (args.length != 6) System.exit(status);
        try {
            System.load(args[5]);
            // The published client passes the UID it is running as, which is the
            // calling application's real UID. It must match this process: the Root
            // endpoint authorizes exactly that installation, so a helper that ran
            // under a different identity would be asking for someone else's grant.
            int callerUid = Integer.parseInt(args[4]);
            if (callerUid != Process.myUid()) throw new IOException("SU_CALLER_IDENTITY_MISMATCH");
            try (ParcelFileDescriptor control = ParcelFileDescriptor.adoptFd(Integer.parseInt(args[0]));
                 ParcelFileDescriptor stdin = ParcelFileDescriptor.adoptFd(Integer.parseInt(args[1]));
                 ParcelFileDescriptor stdout = ParcelFileDescriptor.adoptFd(Integer.parseInt(args[2]));
                 ParcelFileDescriptor stderr = ParcelFileDescriptor.adoptFd(Integer.parseInt(args[3]))) {
                DataInputStream input = new DataInputStream(new FileInputStream(control.getFileDescriptor()));
                DataOutputStream output = new DataOutputStream(new FileOutputStream(control.getFileDescriptor()));
                INativeSuSession session = null;
                try {
                    int length = input.readInt();
                    if (length < 48 || length > 140000) throw new IOException("SU_REQUEST_SIZE_INVALID");
                    byte[] request = new byte[length];
                    input.readFully(request);
                    session = discover(callerUid).start(request, stdin, stdout, stderr, new Binder());
                    INativeSuSession running = session;
                    try (ParcelFileDescriptor terminal = running.openTerminal()) {
                        output.writeByte('R');
                        output.flush();
                        if (terminal != null) sendTerminal(control.getFd(), terminal.getFd());
                    }
                    AtomicBoolean disconnected = new AtomicBoolean();
                    Thread commands = new Thread(() -> {
                        try {
                            while (true) {
                                int command = input.readUnsignedByte();
                                if (command == 'S') running.signal(input.readInt());
                                else if (command == 'W') running.resize(new int[] {
                                    input.readInt(), input.readInt(), input.readInt(), input.readInt() });
                                else throw new IOException("SU_CONTROL_INVALID");
                            }
                        } catch (Exception ignored) {
                            disconnected.set(true);
                            try { running.cancel(); } catch (Exception ignoredCancel) { }
                        }
                    }, "maplesu-su-control");
                    commands.setDaemon(true);
                    commands.start();
                    while (!disconnected.get()) {
                        Bundle result = running.awaitExit(1000);
                        if (!result.getBoolean("finished")) continue;
                        int exit = result.getInt("exitCode", 69);
                        output.writeByte('E');
                        output.writeInt(exit >= 0 && exit <= 255 ? exit : 69);
                        output.flush();
                        status = 0;
                        break;
                    }
                } catch (Exception error) {
                    Log.w("MapleSU", "Native su session failed", error);
                    try { output.writeByte(error instanceof SecurityException ? 'D' : 'U'); output.flush(); }
                    catch (IOException ignored) { }
                } finally {
                    if (session != null) try { session.close(); } catch (Exception ignored) { }
                }
            }
        } catch (Exception | LinkageError error) {
            Log.w("MapleSU", "Native su bootstrap failed", error);
        }
        // Binder's pool must not keep this short-lived owner alive after native su closes.
        System.exit(status);
    }
}
