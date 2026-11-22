package dev.maplesu.manager.runtime;

/** Stable discovery. The returned endpoint receives the original caller directly. */
interface INativeSuDiscovery {
    IBinder getEndpoint();
}
