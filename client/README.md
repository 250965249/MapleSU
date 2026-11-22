# client/

`:maplesu-client`, the cooperative Binder SDK for apps that want a root session from an installed MapleSU Manager: `CooperativeSuClient`, `SuRequest`, `SuSession` and the shared AIDL. It builds on its own as an AAR and depends on nothing.

It deliberately carries no credential, native library, permission, component or hidden API. The client verifies the Manager's signing certificate before it binds, and receives session handles only; backend credentials stay with the Manager and the runtime.

```shell
./gradlew :maplesu-client:assembleRelease
```

The AAR is written to `client/build/outputs/aar/`. [SDK guide](../docs/SDK.md) covers integration, and [`consumer/`](../consumer/README.md) is a working example.

## Rules

- The AIDL package stays `dev.maplesu.manager.runtime`: a Binder descriptor is derived from the AIDL package and name, so the client and the Manager must agree on it exactly.
- Mirror every AIDL change in `manager/src/main/aidl`. The Manager does not depend on this module, so `python tools/check_architecture.py` (`aidl-parity`) keeps the two copies byte-identical.
- Stay out of Manager internals: only the three Binder interfaces in `dev.maplesu.manager.runtime` are shared (`app-facing-modules`).
