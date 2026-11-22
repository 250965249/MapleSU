# Kernel profiles

One JSON file per kernel build. A profile is the only thing that changes when
the kernel changes; the tooling (`image-core/tools/build_flash_kernel.py`) and
the patch semantics do not.

| file | kernel | status |
|---|---|---|
| `6.6.89.json` | `6.6.89-android15-8-g7e1f3c083cc6-abogki467167594-4k` (`346d51ea…`, 36,661,760 B) | delivery - k7/k15/k17b/k18/k20/k21/k22 reproduce byte-identically |

## Build

Device profiles require the exact kernel and base boot inputs identified in their
JSON. Those device images are not distributed with the public source. The commands
below apply after supplying and verifying those inputs. For independent synthetic
checks, use `python tools/check_host.py` from the repository root.

```bash
python image-core/tools/build_flash_kernel.py --variant k7 --out build/flash
python image-core/tools/build_flash_kernel.py --list
python image-core/tools/build_flash_kernel.py --check
python image-core/tools/build_flash_kernel.py --self-test
```

Outputs `<variant>-kernel.bin`, `<variant>-boot.img`, `<variant>-spec.txt` and a
`<variant>-build.json` receipt. Nothing is written to a device.

## Add a kernel

1. Get the pristine kernel Image (or a boot image that carries it) and a base
   boot image with the vendor ramdisk.
2. Derive the sites and the cave room:
   `python image-core/tools/derive_sites.py --kernel <image> --caves --json d.json`
   Review the 12 candidates, then re-learn the signature pack with
   `--learn --offset <symbol>=<offset> ...`.
3. Re-encode the record payloads for the new layout. Offsets alone are not
   enough: every PC-relative word (`b/bl/b.cond/cbz/adr/adrp/movz+movk`) must be
   recomputed against the new site addresses. Verify the emitted instruction
   targets and the record's pristine byte window before accepting the profile.
4. Copy `6.6.89.json` and fill `kernel_version`, `boot_geometry`, `base_image`,
   `sites`, `caves`, `append`, `records`, `variants`, `avc_gate_variants`.
   Leave `validation.expected_artifacts` empty on the first pass.
5. Validate:
   ```bash
   python image-core/tools/build_flash_kernel.py --check --profile image-core/profiles/<v>.json
   python image-core/tools/derive_sites.py --kernel <image> --check
   python image-core/tools/build_flash_kernel.py --profile image-core/profiles/<v>.json \
          --variant k7 --out build/flash-<v> --no-expected
   ```
   `--check` fails closed on: schema, record lengths, site digests, cave bounds,
   boot geometry, base boot sha256, kernel sha256, and the presence of every
   record's `orig` in the pristine kernel.
6. Record the produced kernel/boot sha256 under `validation.expected_artifacts`.
   From then on `--self-test` is the regression gate.

## Conventions

* `records` are applied in `record_order`; later records override earlier ones
  (that is how the AVC gate variants sit on top of the 108 B island). Every
  record's `orig` is the *pristine* byte window, so `verifyraw` proves the
  target before anything is written.
* `append` has two forms: `8` (k7's short package) and `54` (the full envelope).
  A variant selects one with `overrides.append.form`.
* `status` values: `delivery`, `device-proven`, `build-proven`,
  `device-proven(debug-only)`, `candidate`. `candidate` cannot be built without
  `--allow-unverified`.
