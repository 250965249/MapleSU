package dev.maplesu.manager.runtime;

import android.os.Bundle;
import android.os.ParcelFileDescriptor;

interface INativeSuSession {
    ParcelFileDescriptor openTerminal();
    Bundle awaitExit(int timeoutMillis);
    void signal(int signal);
    void resize(in int[] window);
    void cancel();
    void close();
}
