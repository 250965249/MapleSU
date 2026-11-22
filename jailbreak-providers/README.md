# MapleSU provider build and lease boundary

This directory contains pinned provider inputs, derived adapters and the MapleSU
root-shell consumer. Manager includes the Android adapter source set and uses
`checkProviderTracelessInvariants`, `buildJailbreakProviders` and
`packageJailbreakProviders` to verify, build and package the native artifacts.
Build integration and device acceptance are separate requirements.

## Layout

- `ghostlock/upstream`: pinned native/profile sources and original notices.
- `dirtyfrag/upstream`: pinned native/App sources, with stock KO files separated.
- `lease`: MapleSU-owned consumer and exact production argument tests.
- `android`: App-side lease adapter included by Manager.
- `root-loader`: kernel ABI contracts, module sources and handover checks.
- `maplesu-93260`: additional provider adapter and its separately recorded inputs.

Default CMake builds only `libmaplesu_root_consumer.so`. Configure
`MAPLESU_BUILD_UPSTREAM_REVIEW=ON` to make the two upstream targets available,
then explicitly request their target names. They retain original downstream
behavior and are build-review artifacts, not ready-to-package MapleSU providers.
No build obtains code, profiles, modules or binaries from `.research` or a network.

## Consumer channel (MJBL version 1)

A fresh provider worker execs the fixed native consumer with five arguments:
`ENDPOINT NONCE_HEX MANAGER_UID BOOT_ID ghostlock|dirtyfrag`.
The consumer does not create identity or grant privileges. It requires real UID,
effective UID, GID and effective GID zero. It reads its own boot ID, current
context and enforcing value and connects to a pending App listener. Peer UID
must match the expected Manager UID. The App independently checks kernel peer
credentials and the one-attempt nonce; announced PID/UID is not accepted alone.

All integers are 32-bit big-endian. Consumer sends:

```text
MJBL | version=1 | provider=1/2 | pid | uid | nonce[32]
     | boot_id_length | boot_id
     | context_length | context
     | enforcing | seccomp_mode
```

App accepts with one `A` byte and exactly three SCM_RIGHTS descriptors: stdin
read, stdout write and stderr write. Those pipes are independent of provider
profile/ACK stdin and provider logs. A fresh shell receives only these three
standard descriptors. Consumer sends `R | child_pid` only after shell exec has
completed successfully, then `X | exit_code` when the supervised shell ends.
EOF, malformed handshake or a dropped control channel is an error, not success.
Any inbound control byte or owner disconnect terminates the shell process group.

This result is only `RAW_ROOT_LEASE`. It is not policy restoration, daemon health,
authorization, PTY support, installation state or full-feature acceptance.
Final restoration is separately checked before enabling product capabilities.
No consumer code writes policy, changes enforcing/context, opens block devices,
loads an external downstream service, or invokes an installer transaction.

## Ownership

Pending listener and nonce: App, one attempt only. Connected control and three
local pipe ends: returned lease Process. Remote pipe ends: native supervisor
until fork, then closed; shell owns duplicated stdio. Native supervisor owns
shell group cancellation and reaping. The provider's raw-credential anchor is
outside this consumer and retains upstream lifetime semantics.

## Current verification limits

Native compilation and host validators do not exercise Android socket permissions,
FD transfer, restoration or runtime ownership. Each release must record its actual
device checks. A raw lease alone does not establish product readiness.

The public candidate excludes provider binaries whose distribution records are
incomplete. The current clean Manager build also requires those inputs; see the
[build guide](../docs/BUILD.md) and [integration contract](INTEGRATION.md).
Keep upstream notices and manifests with their corresponding sources.
