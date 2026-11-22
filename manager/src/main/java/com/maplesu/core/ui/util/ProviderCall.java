package com.maplesu.core.ui.util;

import android.content.ContentProviderClient;
import android.content.ContentResolver;
import android.net.Uri;
import android.os.Bundle;
import android.os.RemoteException;

/** Directory process death must fail its RPC without ending the manager process. */
public final class ProviderCall {
    private ProviderCall() { }

    public static Bundle call(ContentResolver resolver, Uri uri, String method, String arg, Bundle extras)
            throws RemoteException {
        try (ContentProviderClient client = resolver.acquireUnstableContentProviderClient(uri)) {
            if (client == null) throw new IllegalArgumentException("Unknown URI " + uri);
            // A provider may have performed work before dying; never replay the request.
            return client.call(method, arg, extras);
        }
    }
}
