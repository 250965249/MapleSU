/* Copyright 2026 MapleSU contributors. SPDX-License-Identifier: Apache-2.0 */
package com.topjohnwu.superuser.internal;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.function.BooleanSupplier;

/** Main-thread startup routing, not authentication or a replacement for Binder caller UID. */
final class RootServiceRouting<C> {
    static final String ORIGIN_ENV = "MAPLESU_LIBSU_ORIGIN";
    static final String ORIGIN_EXTRA = "dev.maplesu.libsu.extra.ORIGIN";

    private final String origin = UUID.randomUUID().toString();
    private final List<Pending<C>> pending = new ArrayList<>();

    String origin() { return origin; }

    boolean matchesOrigin(boolean daemon, String received) {
        // Shared daemon discovery has independent upstream lifecycle limitations.
        return daemon || origin.equals(received);
    }

    void add(boolean daemon, C connection, BooleanSupplier action) {
        pending.add(new Pending<>(daemon, connection, action));
    }

    void cancel(C connection) {
        pending.removeIf(request -> request.connection.equals(connection));
    }

    boolean hasPending(boolean daemon) {
        for (Pending<C> request : pending) if (request.daemon == daemon) return true;
        return false;
    }

    void runPending(boolean daemon) {
        // Snapshot: completion callbacks can cancel or enqueue another request.
        List<Pending<C>> snapshot = new ArrayList<>(pending);
        for (int i = snapshot.size() - 1; i >= 0; --i) {
            Pending<C> request = snapshot.get(i);
            if (request.daemon == daemon && pending.contains(request) && request.action.getAsBoolean())
                pending.remove(request);
        }
    }

    private static final class Pending<C> {
        final boolean daemon;
        final C connection;
        final BooleanSupplier action;

        Pending(boolean daemon, C connection, BooleanSupplier action) {
            this.daemon = daemon;
            this.connection = connection;
            this.action = action;
        }
    }
}
