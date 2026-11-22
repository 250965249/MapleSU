# module-tools/

`maplesu-tools`, a multicall property-tool host for modules. It dispatches on `argv[0]`, the same shape as KernelSU's `ksud`, and `resetprop` is published as a link to it. The `resetprop` command line is reused unchanged from the pinned `ksu_props` library, so the contract a module sees is the upstream one.

| Path | Content |
| --- | --- |
| `src/main.rs` | The entry point and the `argv[0]` dispatch |
| `Cargo.toml`, `Cargo.lock` | The crate and its pinned dependencies; the property crates come from [`third_party/ksu_props`](../third_party/DEPENDENCIES.md) by path |

```shell
rustup toolchain install 1.99.1 --profile minimal
rustup target add --toolchain 1.99.1 aarch64-linux-android
python tools/build_module_tools.py --host-toolchain 1.99.1
```

See the [build guide](../docs/BUILD.md#toolchains) for the toolchain options on Windows. Do not copy code from `third_party/ksu_props` into this crate; extend the dispatch in `src/main.rs` and keep the library as a dependency.
