package dev.maplesu.manager.runtime;

import android.app.Service;
import android.content.Intent;
import android.os.Binder;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import android.os.ParcelFileDescriptor;
import android.os.Process;
import android.os.RemoteException;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/** Test-only independent APK launches a real App-domain process, never run-as. */
public final class ProductionRootPeerService extends Service {
    public static final String DESCRIPTOR = "dev.maplesu.manager.productionRootPeer";
    private final Binder endpoint = new Binder() {
        @Override protected boolean onTransact(int code, Parcel data, Parcel reply, int flags) throws RemoteException {
            if (code < FIRST_CALL_TRANSACTION || code > FIRST_CALL_TRANSACTION + 1 || reply == null)
                return super.onTransact(code, data, reply, flags);
            data.enforceInterface(DESCRIPTOR);
            try {
                int manager = getPackageManager().getApplicationInfo("dev.maplesu.manager", 0).uid;
                if (Binder.getCallingUid() != manager) throw new SecurityException("PRODUCTION_FIXTURE_CALLER");
                Bundle result;
                if (code == FIRST_CALL_TRANSACTION) {
                    String mode = data.readString();
                    if (data.dataAvail() != 0) throw new IllegalArgumentException("PRODUCTION_FIXTURE_TRAILING_DATA");
                    long token = Binder.clearCallingIdentity();
                    try { result = launch(manager, mode); } finally { Binder.restoreCallingIdentity(token); }
                } else {
                    IBinder management = data.readStrongBinder();
                    if (management == null || data.dataAvail() != 0) throw new IllegalArgumentException("PRODUCTION_MANAGEMENT_BINDER");
                    result = new Bundle(); result.putInt("fixtureUid", Process.myUid());
                    long token = Binder.clearCallingIdentity();
                    Parcel change = Parcel.obtain(), response = Parcel.obtain();
                    try {
                        // The separate test APK's Service classloader has no target-package classes.
                        change.writeInterfaceToken("dev.maplesu.manager.runtime.IRootManagementService");
                        change.writeInt(Process.myUid());
                        if (!management.transact(IBinder.FIRST_CALL_TRANSACTION + 4, change, response, 0))
                            throw new IllegalStateException("PRODUCTION_MANAGEMENT_TRANSACTION");
                        response.readException();
                        result.putBoolean("rejected", false);
                    } catch (SecurityException expected) {
                        result.putBoolean("rejected", true); result.putString("failure", expected.toString());
                    } finally { change.recycle(); response.recycle(); Binder.restoreCallingIdentity(token); }
                }
                reply.writeNoException(); reply.writeTypedObject(result, 0); return true;
            } catch (Exception error) { throw new IllegalStateException("Production fixture failed", error); }
        }
    };
    @Override public IBinder onBind(Intent intent) { return endpoint; }

    private Bundle launch(int manager, String mode) throws Exception {
        if (!"denied".equals(mode) && !"stdio".equals(mode) && !"pty".equals(mode) &&
            !"signal".equals(mode) && !"cancel".equals(mode)) throw new IllegalArgumentException("PRODUCTION_FIXTURE_MODE");
        String classpath = getApplicationInfo().sourceDir + ":" +
            getPackageManager().getApplicationInfo("dev.maplesu.manager", 0).sourceDir;
        ProcessBuilder builder = new ProcessBuilder("/system/bin/app_process", "/system/bin",
            ProductionRootClient.class.getName(), Integer.toString(manager), mode);
        builder.environment().put("CLASSPATH", classpath);
        java.lang.Process client = builder.start();
        ExecutorService readers = Executors.newFixedThreadPool(2);
        try {
            client.getOutputStream().close();
            Future<String> stdout = readers.submit(() -> read(client.getInputStream()));
            Future<String> stderr = readers.submit(() -> read(client.getErrorStream()));
            if (!client.waitFor(28, TimeUnit.SECONDS)) throw new IllegalStateException("PRODUCTION_CLIENT_TIMEOUT");
            Bundle result = new Bundle();
            result.putInt("fixtureUid", Process.myUid()); result.putInt("exitCode", client.exitValue());
            result.putString("stdout", stdout.get(3, TimeUnit.SECONDS));
            result.putString("stderr", stderr.get(3, TimeUnit.SECONDS));
            return result;
        } finally {
            client.destroyForcibly();
            try { client.waitFor(3, TimeUnit.SECONDS); } finally {
                client.getInputStream().close(); client.getOutputStream().close(); client.getErrorStream().close();
                readers.shutdownNow();
            }
        }
    }
    private static String read(InputStream stream) throws Exception {
        try (InputStream input = stream; ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] bytes = new byte[1024];
            for (int size; (size = input.read(bytes)) != -1;) {
                if (output.size() + size > 16384) throw new IllegalStateException("PRODUCTION_FIXTURE_OUTPUT_BOUND");
                output.write(bytes, 0, size);
            }
            return output.toString(StandardCharsets.UTF_8.name());
        }
    }
}
