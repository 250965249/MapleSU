# Native build inputs

This directory contains the kernel and policy inputs consumed by the complete Manager build. Files are retained byte for byte from the development baseline and are indexed by size and SHA-256 in `release/native-inputs.json`.

| Directory | Contents | Consumer |
| --- | --- | --- |
| `kernels/` | Kernel Images and symbol tables | `jailbreak-providers/root-loader/contracts/*.json` and provider builders |
| `policy/` | Six policy payloads, configurations, BTF, layouts and compatibility proofs | SDK delivery verification and policy bundle generation |

The Ultra SDK, headers, helper, paired backend and maintenance baseline live in `runtime/upstream-pro/`. Runtime inputs live in `runtime/upstream/`, patch-core source in `patch-engine/upstream/`, and the retained SELinux snapshot in `.deps/selinux/`.

## Check the checkout

```shell
python scripts/sync-pro-sdk-identity.py --check
python tools/prepare_native_inputs.py --check
```

## Regenerate the policy bundle

```shell
python scripts/build-ultra-policy-bundles.py native-inputs/policy/android12-5.10 native-inputs/policy/android13-5.15 native-inputs/policy/android14-6.1 native-inputs/policy/android15-6.6 native-inputs/policy/android16-6.12 native-inputs/policy/android17-6.18 --output build/policy-candidate/policy-bundles.cpp
```

The generated C++ payload must match the committed payload when its inputs are unchanged. Follow [Native dependencies](../docs/NATIVE_DEPENDENCIES.md) to build and pair a new policy backend. Component origins and acknowledgements are centralized in [Credits](../CREDITS.md).
