# image-core/

Boot and vendor_boot image handling in plain Java: inspection, kernel compression codecs, rebuilding, round-trip equivalence checks, AVB footers and Lenovo AVB signing. It imports only the JDK, so it runs on a bare JDK without Android or Gradle.

| Path | Content |
| --- | --- |
| `src/main/java/dev/maplesu/image/` | `BootImageInspector`, `BootImageRebuilder`, `BootImageEquivalence`, `RamdiskInspector`, `VendorBootInspector`, `AvbFooter`, `LenovoAvbSigner`, `KernelIdentity`, and the LZ4, XZ and Zstd codecs |
| `src/test/` | Synthetic suites and their resources, including the AOSP-compatible AVB fixtures |
| `profiles/` | Kernel profiles ([README](profiles/README.md)) |
| `tools/` | Python helpers: the kernel profile registry, patch-site derivation and the flashable-kernel build driven by a profile |

```shell
python tools/check_host.py
```

The command compiles the sources and runs every suite in an isolated work directory; it needs no real boot image and no device. The same sources are the `:image-core` Gradle module, which the Manager depends on.

## Rules

- Import only the JDK and `dev.maplesu.image.*` (`pure-java-modules` in `python tools/check_architecture.py`). Anything that needs an Android API or Manager state belongs in the Manager.
- Image code never opens a device partition; writes go through [`installer-core`](../installer-core/README.md).
- Format references and their provenance are listed in [`third_party/DEPENDENCIES.md`](../third_party/DEPENDENCIES.md). The AVB signing note for Lenovo devices is in [Lenovo AVB signing](../docs/LENOVO_AVB_SIGNING.md).
