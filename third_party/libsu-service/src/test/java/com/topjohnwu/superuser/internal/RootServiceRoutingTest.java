/* Copyright 2026 MapleSU contributors. SPDX-License-Identifier: Apache-2.0 */
package com.topjohnwu.superuser.internal;

/** Dependency-free host checks. Android receiver/owner lifetime still needs device coverage. */
public final class RootServiceRoutingTest {
    private static int checks;

    private static void check(boolean result, String message) {
        checks++;
        if (!result) throw new AssertionError(message);
    }

    private static boolean deliver(RootServiceRouting<Object> routing, boolean daemon, String origin) {
        if (!routing.matchesOrigin(daemon, origin) || !routing.hasPending(daemon)) return false;
        routing.runPending(daemon);
        return true;
    }

    public static void main(String[] ignored) {
        RootServiceRouting<Object> first = new RootServiceRouting<>();
        RootServiceRouting<Object> second = new RootServiceRouting<>();
        check(!first.origin().equals(second.origin()), "process instances must differ");
        check(first.origin().matches("[0-9a-f-]{36}"), "origin must be a shell-safe UUID");
        int[] firstRuns = {0};
        int[] secondRuns = {0};
        Object firstConnection = new Object();
        Object secondConnection = new Object();
        first.add(false, firstConnection, () -> { firstRuns[0]++; return true; });
        second.add(false, secondConnection, () -> { secondRuns[0]++; return true; });
        check(!deliver(first, false, null), "missing ordinary origin must be ignored");
        check(!deliver(first, false, "not-the-origin"), "wrong ordinary origin must be ignored");
        check(!deliver(second, false, first.origin()), "other process must not claim first startup");
        check(firstRuns[0] == 0 && secondRuns[0] == 0, "mismatch must not run any pending action");
        check(deliver(first, false, first.origin()), "own startup must be accepted");
        check(firstRuns[0] == 1 && secondRuns[0] == 0, "only own process must bind");
        check(!deliver(first, false, first.origin()), "repeated reply with no demand must be ignored");
        check(firstRuns[0] == 1, "duplicate broadcast must not rerun completed work");
        check(deliver(second, false, second.origin()), "second startup must be separately accepted");
        check(secondRuns[0] == 1, "second process action count");

        RootServiceRouting<Object> mixed = new RootServiceRouting<>();
        int[] modes = {0, 0};
        Object ordinary = new Object();
        Object daemon = new Object();
        mixed.add(false, ordinary, () -> { modes[0]++; return true; });
        mixed.add(true, daemon, () -> { modes[1]++; return true; });
        check(deliver(mixed, true, null), "shared daemon need not match startup origin");
        check(modes[0] == 0 && modes[1] == 1, "daemon response must not drain ordinary pending");
        check(mixed.hasPending(false) && !mixed.hasPending(true), "mode-separated pending state");
        check(deliver(mixed, false, mixed.origin()), "ordinary pending survives daemon response");
        check(modes[0] == 1 && modes[1] == 1, "each mode ran once");

        Object cancelled = new Object();
        mixed.add(false, cancelled, () -> { throw new AssertionError("cancelled action ran"); });
        mixed.cancel(cancelled);
        check(!deliver(mixed, false, mixed.origin()), "cancelled startup must not be claimed");
        check(!deliver(mixed, true, null), "no daemon demand must not be claimed");

        int[] retries = {0};
        mixed.add(false, new Object(), () -> ++retries[0] == 2);
        check(deliver(mixed, false, mixed.origin()) && mixed.hasPending(false), "incomplete bind stays pending");
        check(deliver(mixed, false, mixed.origin()) && !mixed.hasPending(false), "retry completes once");

        Object cancelDuringCallback = new Object();
        mixed.add(false, cancelDuringCallback, () -> { throw new AssertionError("callback-cancelled action ran"); });
        mixed.add(false, new Object(), () -> { mixed.cancel(cancelDuringCallback); return true; });
        check(deliver(mixed, false, mixed.origin()) && !mixed.hasPending(false), "callback cancellation uses live membership");

        System.out.println("PASS RootServiceRoutingTest checks=" + checks);
    }
}
