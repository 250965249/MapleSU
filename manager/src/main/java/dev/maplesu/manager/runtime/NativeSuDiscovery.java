package dev.maplesu.manager.runtime;

import android.annotation.SuppressLint;
import android.content.ComponentName;
import android.content.Intent;
import android.os.IBinder;
import android.os.Process;
import org.lsposed.hiddenapibypass.HiddenApiBypass;
import java.io.IOException;

/** AMS discovers a stable broker; authorized handover returns the original Root endpoint. */
public final class NativeSuDiscovery {
    private NativeSuDiscovery() {}
    /**
     * Resolves the published restricted Root endpoint for this process.
     *
     * <p>{@code callerUid} must be this process's own real UID. It is used for two
     * things only: the request is scoped to the caller's own Android user, and AMS
     * resolves the caller's package name from it. It is not an authorization
     * decision — the endpoint itself judges the Binder-supplied caller UID against
     * the single authorization owner's table.
     */
    @SuppressLint("SoonBlockedPrivateApi")
    public static IBinder peek(int callerUid) throws Exception {
        HiddenApiBypass.addHiddenApiExemptions("Landroid/app/ActivityManager;", "Landroid/app/IActivityManager;",
            "Landroid/app/AppGlobals;", "Landroid/content/pm/IPackageManager;");
        if (Process.myUid() != callerUid) throw new IOException("SU_CALLER_IDENTITY_MISMATCH");
        if (Process.myUid() / 100000 != callerUid / 100000) throw new IOException("SU_MANAGER_USER_MISMATCH");
        Object packages = Class.forName("android.app.AppGlobals").getDeclaredMethod("getPackageManager").invoke(null);
        String[] names = (String[]) Class.forName("android.content.pm.IPackageManager")
            .getDeclaredMethod("getPackagesForUid", int.class).invoke(packages, Process.myUid());
        if (names == null || names.length == 0) throw new IOException("SU_CALLER_PACKAGE_UNAVAILABLE");
        Intent intent = new Intent("dev.maplesu.manager.action.NATIVE_SU_PEEK")
            .setComponent(new ComponentName("dev.maplesu.manager", "dev.maplesu.manager.runtime.NativeSuBrokerService"));
        Object activity = Class.forName("android.app.ActivityManager").getDeclaredMethod("getService").invoke(null);
        IBinder root = (IBinder) Class.forName("android.app.IActivityManager").getDeclaredMethod("peekService",
            Intent.class, String.class, String.class).invoke(activity, intent, null, names[0]);
        if (root == null || !root.isBinderAlive()) throw new IOException("SU_EXECUTOR_NOT_PUBLISHED");
        IBinder endpoint = INativeSuDiscovery.Stub.asInterface(root).getEndpoint();
        if (endpoint == null || !endpoint.isBinderAlive()) throw new IOException("SU_EXECUTOR_NOT_PUBLISHED");
        return endpoint;
    }
}
