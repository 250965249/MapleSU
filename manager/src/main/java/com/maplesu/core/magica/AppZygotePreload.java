package com.maplesu.core.magica;

import android.app.ZygotePreload;
import android.content.pm.ApplicationInfo;
import android.util.Log;

import androidx.annotation.NonNull;

import java.io.File;

public class AppZygotePreload implements ZygotePreload {
    public static final String TAG = "KernelSUMagica";

    @Override
    public void doPreload(@NonNull ApplicationInfo appInfo) {
        // MapleSU uses MapleSU; KSU late-load is not an available backend operation.
        Log.i(TAG, "MAPLESU_LATE_LOAD_NOT_IMPLEMENTED");
    }
}
