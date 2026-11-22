package dev.maplesu.manager.runtime;

import android.os.ParcelFileDescriptor;
import android.os.Bundle;

/** Each stdio endpoint can be claimed once, by the same complete Android UID as start(). */
interface IRootTask {
    ParcelFileDescriptor openStdin();
    ParcelFileDescriptor openStdout();
    ParcelFileDescriptor openStderr();
    Bundle awaitExit(int timeoutMillis);
    void cancel();
    void close();
}
