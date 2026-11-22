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

/** Separate test APK process owns every transaction and stdio operation sent to Root. */
public final class BinderAdmissionPeerService extends Service {
    public static final String DESCRIPTOR = "dev.maplesu.manager.binderAdmissionPeer";
    private static final String ROOT = "dev.maplesu.manager.binderAdmissionRoot";
    private static final byte[] INPUT = "maplesu-binder-admission\n".getBytes(StandardCharsets.UTF_8);
    private IBinder root;

    private final Binder endpoint = new Binder() {
        @Override protected boolean onTransact(int code, Parcel data, Parcel reply, int flags) throws RemoteException {
            if (code < FIRST_CALL_TRANSACTION || code > FIRST_CALL_TRANSACTION + 1 || reply == null)
                return super.onTransact(code, data, reply, flags);
            data.enforceInterface(DESCRIPTOR);
            int manager;
            try { manager = getPackageManager().getApplicationInfo("dev.maplesu.manager", 0).uid; }
            catch (Exception error) { throw new IllegalStateException(error); }
            int caller = Binder.getCallingUid();
            if (caller != manager && caller != Process.myUid()) throw new SecurityException("BINDER_ADMISSION_PEER_CALLER");
            if (code == FIRST_CALL_TRANSACTION) root = data.readStrongBinder();
            Bundle result = probe();
            reply.writeNoException();
            reply.writeTypedObject(result, 0);
            return true;
        }
    };

    @Override public IBinder onBind(Intent intent) { return endpoint; }

    private Bundle probe() {
        Bundle result = new Bundle();
        result.putInt("peerUid", Process.myUid());
        result.putInt("peerPid", Process.myPid());
        String stage = "cached_handle";
        ParcelFileDescriptor[] stdin = null, stdout = null, stderr = null;
        try {
            IBinder target = root;
            if (target == null) throw new IllegalStateException("No cached Root Binder; cold discovery is not implemented");
            stage = "direct_root_identity";
            result.putBundle("identity", transact(target, 0, null));
            stage = "create_peer_fds";
            stdin = ParcelFileDescriptor.createPipe();
            stdout = ParcelFileDescriptor.createPipe();
            stderr = ParcelFileDescriptor.createPipe();
            try (ParcelFileDescriptor.AutoCloseOutputStream input = new ParcelFileDescriptor.AutoCloseOutputStream(stdin[1])) {
                input.write(INPUT);
            }
            stage = "direct_root_stdio";
            result.putBundle("stdio", transact(target, 1, new ParcelFileDescriptor[]{stdin[0], stdout[1], stderr[1]}));
            stdout[1].close(); stderr[1].close();
            stage = "read_peer_fds";
            result.putByteArray("stdout", read(stdout[0]));
            result.putByteArray("stderr", read(stderr[0]));
            stage = "complete";
        } catch (Exception error) {
            result.putString("failure", error.toString());
        } finally {
            close(stdin); close(stdout); close(stderr);
            result.putString("stage", stage);
            result.putString("discovery", "cached_root_handle_only; fresh-client discovery remains unproved");
        }
        return result;
    }

    private static Bundle transact(IBinder target, int operation, ParcelFileDescriptor[] streams) throws RemoteException {
        Parcel request = Parcel.obtain(), response = Parcel.obtain();
        try {
            request.writeInterfaceToken(ROOT);
            if (streams != null) for (ParcelFileDescriptor stream : streams) request.writeTypedObject(stream, 0);
            if (!target.transact(IBinder.FIRST_CALL_TRANSACTION + operation, request, response, 0))
                throw new IllegalStateException("Root fixture transaction not handled");
            response.readException();
            Bundle result = response.readTypedObject(Bundle.CREATOR);
            if (result == null) throw new IllegalStateException("Root fixture reply missing");
            return result;
        } finally { request.recycle(); response.recycle(); }
    }

    private static byte[] read(ParcelFileDescriptor descriptor) throws Exception {
        try (InputStream input = new ParcelFileDescriptor.AutoCloseInputStream(descriptor);
             ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] bytes = new byte[128];
            int size;
            while ((size = input.read(bytes)) != -1) {
                if (output.size() + size > 128) throw new IllegalStateException("Root fixture output exceeds bound");
                output.write(bytes, 0, size);
            }
            return output.toByteArray();
        }
    }

    private static void close(ParcelFileDescriptor[] descriptors) {
        if (descriptors != null) for (ParcelFileDescriptor descriptor : descriptors)
            try { descriptor.close(); } catch (Exception ignored) { }
    }
}
