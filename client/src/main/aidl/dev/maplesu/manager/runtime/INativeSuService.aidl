package dev.maplesu.manager.runtime;

import android.os.IBinder;
import android.os.ParcelFileDescriptor;
import dev.maplesu.manager.runtime.INativeSuSession;

/** Request identity comes from Binder, never from the serialized execution request. */
interface INativeSuService {
    INativeSuSession start(in byte[] request, in ParcelFileDescriptor stdin,
        in ParcelFileDescriptor stdout, in ParcelFileDescriptor stderr, IBinder owner);
}
