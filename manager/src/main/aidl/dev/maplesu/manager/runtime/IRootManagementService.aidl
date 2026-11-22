package dev.maplesu.manager.runtime;

import android.os.Bundle;
import android.os.IBinder;
import dev.maplesu.manager.runtime.IRootTask;

/** Trusted Manager control plane. Every operation must verify the real Binder caller. */
interface IRootManagementService {
    Bundle status();
    boolean isEnabled();
    void setEnabled(boolean enabled);
    boolean hasGrant(int uid);
    void grant(int uid);
    void revoke(int uid);
    int grantCount();
    IRootTask start(in String[] argv, IBinder owner, boolean globalMnt);
}
