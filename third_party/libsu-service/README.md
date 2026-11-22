# libsu service 6.0.0, bounded startup-routing derivative

This Android library replaces only `com.github.topjohnwu.libsu:service:6.0.0`.
It retains the official `core:6.0.0` dependency. It must not be packaged beside
the original service AAR because both define the same classes.

## Provenance and retained binary asset

- Repository: `https://github.com/topjohnwu/libsu`.
- Tag: `6.0.0`, fixed commit `8c3e80ffe466b89ff875471e542d77e6a1b480c5`.
- `upstream/service/` contains the unmodified complete service module.
- `upstream-6.0.0.zip` is the fixed-commit source archive.
- `SOURCE.json` records original per-file SHA-256, archive hash and asset provenance.
- The Apache-2.0 license is retained as `LICENSE`; upstream file headers are retained.
- `src/main/assets/main.jar` is the **unchanged official binary trampoline**,
  not a newly rebuilt artifact. Its SHA-256 is
  `ae7fdb8b70bd2c1cc2c27043e985f8dc5cfff2cb9142a1576dcdbc889763ef7b`.
  It is byte-identical to the fixed-tag source asset and the cached official
  `service:6.0.0` AAR asset (AAR SHA-256 in `SOURCE.json`).

No AIDL or `RootServerMain` source changes are made. The official trampoline
loads the server from the installed APK in the same `app_process`, so the server
can read the inherited launch environment. The build does not regenerate
`main.jar`; its original source remains present for review.

## Scope of derivative changes

`upstream-diff.patch` contains the changes to the two upstream source files:

1. Ordinary launch commands set `MAPLESU_LIBSU_ORIGIN` to a process-local UUID.
2. Ordinary server startup broadcasts echo that value in an Intent extra.
3. Before calling `connect`, the client checks its own origin and actual pending
   mode. Missing or foreign ordinary origins are ignored.
4. Pending bindings retain their mode and connection, are cancellable, and only
   run for the matching reply mode. Repeated broadcasts do not create a second
   holder for the same connected Binder.

`RootServiceRouting.java` is a new dependency-free helper used by the actual
client code, not an independent test model. The UUID routes startup replies;
it is not authentication, a privilege credential, a claimed UID, or a new IPC
endpoint. Existing receiver restrictions and real Binder caller UID remain in
force. The server's upstream UID-keyed client lifecycle is unchanged.

Daemon mode remains shared upstream discovery. It filters by actual pending
mode but does not require the original startup UUID. This change **does not
resolve multiple same-UID daemon owners** or establish daemon cold discovery.
Existing ordinary launch timeouts and app-update termination semantics remain.

## Verification

Run `python third_party/libsu-service/run-routing-tests.py` from the workspace,
or invoke it by absolute path. It compiles the actual helper and a dependency-free
test with Java 8 language/API compatibility, then saves command exits, input
hashes and output under `host-test-results/`.

Host checks cover absent/foreign origins, two simultaneous same-mode process
instances, mode isolation, cancellation, repeated replies, incomplete binding
retry, and cancellation during callbacks. They do not validate Android receiver
delivery, inherited environment on a device, Binder UID, child process ownership,
FD use, or application lifecycle. Those require the main thread's integrated
APK and separate device evidence.

Integration requires a settings entry for this directory and replacing the
Manager service AAR dependency with the project dependency. This subtask does
not modify those shared integration files or run Gradle/ADB.
