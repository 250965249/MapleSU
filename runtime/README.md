# runtime/

The native side of MapleSU's root path: SU execution, supervised sessions, the JNI glue and the Ultra SDK adapters. The Manager's Gradle build compiles it with CMake and the NDK (`runtime/CMakeLists.txt`), and the Ultra SDK is linked from the pinned input named by `upstream-pro/SDK-IDENTITY.cmake`.

| Path | Content | Origin |
| --- | --- | --- |
| `src/` | The SU runtime: `su_main`, `su_session`, `session_process`, `exec_main`, `block_partition_access`, `module_owner` and the socket probe | MapleSU |
| `pro/` | MapleSU's Ultra Pro adapters, one directory per concern: `authorization`, `boot`, `bridge`, `identity`, `modules`, `panic`, `parasite`, `policy`, `probe`, `upgrade` | MapleSU, over pinned inputs |
| `upstream/`, `upstream-pro/` | Pinned Lite and Pro SDK inputs: headers, libraries and the paired policy backend. The active identity is `upstream-pro/SDK-RELEASE.json` | Third party, pinned; see [Native dependencies](../docs/NATIVE_DEPENDENCIES.md) |
| `pro/third_party/`, `pro/reference/` | Pinned library sources with their `PROVENANCE.json` | Third party |
| `tests/` | Native host tests; most are compiled and run by the scripts in [`scripts/tests/`](../scripts/tests/) | MapleSU |

## Rules

- Ultra reaches the SDK only through `pro/bridge/` here and `manager/src/main/java/dev/maplesu/manager/runtime/pro/bridge/NativeBridge.java` on the Manager side (`native-boundary`). Add an SDK call there, never beside it.
- Never edit a pinned input in place. A new SDK generation is a new pinned input with a manifest and paired identity; follow [Update the policy backend](../docs/NATIVE_DEPENDENCIES.md#update-the-policy-backend) in Native dependencies and run `python scripts/sync-pro-sdk-identity.py --check`.
- `scripts/` files named in `SDK-RELEASE.json` are part of the provenance chain; see [`scripts/README.md`](../scripts/README.md).
