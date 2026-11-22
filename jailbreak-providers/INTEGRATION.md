# Provider integration and acceptance

Manager includes the Android transport, profile parsing and provider adapters.
The native build and packaging tasks in `manager/build.gradle.kts` invoke this
directory's build tools and publish a digest manifest for runtime verification.
The [build guide](../docs/BUILD.md) records the public candidate's outstanding inputs.

## Integration path

1. Prepare one attempt with its method, target mode, boot identity and bounded
   lifetime. Stage only artifacts whose identities match the packaged manifest.
2. Select the exact kernel profile and matching module contract. A related kernel
   family or approximate KMI is insufficient evidence of compatibility.
3. Start the provider through its adapter. The Android transport authenticates
   the one-attempt root consumer using kernel peer credentials and a fresh nonce;
   log markers alone do not establish a working shell.
4. Verify restoration and handover for the same attempt and boot. Read-only
   observations, raw root access, restored policy and product readiness are
   separate results.
5. Pass the accepted process to the existing runtime owner. Authorization,
   lifecycle, cancellation and mode state remain owned by the Manager runtime.
6. Enforce partition-write policy in the trusted transaction layer. Module
   operations and boot/image installation keep their distinct gates.

## Source and artifact maintenance

Retain pinned upstream sources and notices. Apply MapleSU changes in the derived
source layer, verify the resulting artifact identities and keep the corresponding
source with each distributed version. Stock modules used for comparison require
their own provenance and distribution records; their presence does not establish
a source rebuild or device acceptance.

## Release checks

Host protocol checks cover framing, malformed input and process ownership.
Native builds cover the actual selected toolchain and inputs. Device checks must
separately cover Android socket/FD behavior, cancellation, restoration, runtime
handover and the capabilities exposed by each target mode. Record the exact
version and device/kernel combination with the result.

See the [transport contract](android/README.md), [native dependency guide](../docs/NATIVE_DEPENDENCIES.md)
and [release process](../docs/RELEASING.md).
