package dev.maplesu.manager.runtime;

import android.os.IBinder;
import dev.maplesu.manager.runtime.IRootTask;

/** Manager-only streaming tasks; does not publish an application su endpoint. */
interface IRootShellService {
    IRootTask start(in String[] argv, IBinder owner, boolean globalMnt);
    IRootTask startModule(in String[] argv, IBinder owner, in String[] environment);
}
