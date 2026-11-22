package dev.maplesu.manager.runtime.authorization

import android.content.Context

/**
 * Service-side package snapshots for the supplied Context's Android user.
 * The caller UID must be captured by a Binder/peer-credential adapter before clearing its identity.
 * This provider resolves that UID; it does not authenticate a UID supplied in a client request.
 *
 * <p>The validation lives in [PackageIdentityReader] so the one-shot root tool - which
 * must not create a `Context` - uses exactly the same rule through
 * [SystemPackageSnapshotSource]. This class is now only the App-side source binding.
 */
internal class AndroidApplicationIdentities(context: Context) :
    AuthorizationPolicy.TrustedIdentityProvider by
    PackageIdentityReader(ContextPackageSnapshotSource(context))
