package dev.maplesu.manager.runtime;

import android.os.IBinder;
import dev.maplesu.manager.runtime.IRootTask;

/** Caller identity comes exclusively from Binder. No credentials or caller UID in the request. */
interface IRootRequestService {
    IRootTask start(in String[] argv, IBinder owner);
}
