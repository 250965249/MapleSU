# consumer/

`:maplesu-consumer`, the example app that uses [`client/`](../client/README.md). It runs in its own UID, the same situation as any integrating app, and depends only on `:maplesu-client`.

| Path | Content |
| --- | --- |
| `src/main/` | `MainActivity`, a manual demonstration surface: each button performs a real bind and Binder request against the installed Manager and shows exactly what came back |
| `src/androidTest/` | `CooperativeSuClientTest`, the instrumentation test of the client against an installed Manager. It needs a device |

```shell
./gradlew :maplesu-consumer:assembleDebug
```

The APK is written to `consumer/build/outputs/apk/debug/`. Read the [SDK guide](../docs/SDK.md) first; this module is where a change to the client API gets exercised end to end. Keep it free of Manager internals (`app-facing-modules`).
