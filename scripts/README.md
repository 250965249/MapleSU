# scripts/

The build, identity and regression toolchain for the **Ultra backend**: the Pro SDK adapters, the policy backend and the native runtime. Repository-wide entry points (host checks, input preparation, release audit) live in [`tools/`](../tools/README.md).

## Read this before moving or editing a file here

Some files in this directory are part of the SDK's provenance chain. `runtime/upstream-pro/SDK-RELEASE.json` and the delivery manifests under `work/` record their **paths and SHA-256 digests**, and `scripts/sync-pro-sdk-identity.py --check` and the release gates rely on those records. Renaming, moving or reformatting such a file, or editing it without re-pinning, breaks the chain without any compile error. `python tools/check_architecture.py` (rule `pinned-scripts`) fails when a recorded script is missing or no longer matches its record. If a change is intended, regenerate the SDK record in the same commit and say so in the pull request.

Files that are not named in those records, and everything in [`tests/`](tests/), can be changed freely.

## Layout

| Files | Purpose |
| --- | --- |
| `build-pro-*.py`, `build-ultra-policy-*.py`, `build-ultra-vr-filter.py`, `build-*.ps1` | Build SDK candidates, policy bundles, layout and compatibility contracts, the module filter and the native runtime |
| `policy_*.py`, `policy-kernel-clang.py`, `ar_archive.py`, `verify_sdk_member_diff.py` | Shared helpers: backend identity and delivery checks, BTF ABI, payload inspection, `ar` member parsing and the SDK member-diff gate |
| `sync-pro-sdk-identity.py`, `rebind-pro-policy-backend.py`, `install-pro-*.py` | Generate and check the build identity, pair a rebuilt policy backend with its helper, install verified SDK extensions |
| `repair-pro-*.py`, `stamp-pro-*.py`, `import-pro-sdk-505.ps1` | One-time SDK member repairs, version stamps and the 5.0.5 import. They remain as implementation records; reproduce an older SDK generation with their explicit version and digest preconditions |
| `check-*.ps1`, `check-*.sh`, `verify-*.py`, `verify-*.sh` | Gates for a built Manager, packaged native pages, vivo artifacts and Normal-module parity |
| [`tests/`](tests/) | Host regression tests for the Ultra backend and the Manager's restore wiring |

## Running the regression tests

Run them from the repository root, so the relative defaults resolve:

```shell
python -m pip install -r requirements-native.txt
python scripts/tests/test-pro-policy-entry.py --help
```

Each script documents its own inputs in `--help`. Tools are found through the environment variables in the [build guide](../docs/BUILD.md#locating-tools): `ANDROID_HOME`, `JAVA_HOME`, `MAPLESU_PROVIDER_NDK` and, for the few device checks, `ANDROID_SERIAL`. Tests that compile native code expect the NDK, Docker or the retained SDK inputs described in [Development](../docs/DEVELOPMENT.md) and [Native dependencies](../docs/NATIVE_DEPENDENCIES.md). The `.cjs` tests run with Node.js and the `.sh` test runs inside an isolated container. Tests that need an input that is not present exit with an error that names it. Every test runs on the host except `test-parasite-loader.py` and `test-parasite-startup.py --device`, which drive a connected device through adb and need `ANDROID_SERIAL` or `--serial`.

Scripts locate the repository with `Path(__file__).resolve().parents[N]`. A test in `tests/` uses `parents[2]`, and it adds `scripts/` to `sys.path` before importing a helper from this directory.
