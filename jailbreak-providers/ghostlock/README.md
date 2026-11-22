# Ghostlock pinned upstream review input

The `upstream/` files are original Git blob bytes from Ghostlock commit
`b67359641c8663e5184abba73ecdf2c456dce3e7`. `upstream-manifest.json` binds every
copied file to its original path, byte size and SHA256. No build reads `.research`.

The offline `maplesu-ghostlock-upstream-review` target uses every production
translation unit in the upstream Makefile, not the incomplete IDE CMake list.
It emits an Android arm64 PIE named `libmaplesu_ghostlock.so`, not a JNI library.
It is `EXCLUDE_FROM_ALL` and must not be packaged as a product provider: its
original W1/W2/W3 and KSU consumer have not been adapted to MapleSU.

The preserved `profile-core` Kotlin sources and HOCON assets retain the real
profile resolver/serializer and the `com.typesafe:config:1.4.3` dependency
declaration. This CMake target does not build Kotlin, export profiles or package
that JVM dependency. Profile assets include templates, not only exact targets.

Licensing: preserve `upstream/LICENSE` (Apache-2.0) and the embedded third-party
credits/public-domain notice in `upstream/src/core/kernelsnitch/futex_hash.h`.
These notices are copied verbatim; no separate third-party LICENSE/NOTICE file
exists in the fixed upstream tree. Redistribution review of future dependencies
is separate from source/build verification.

An offline successful native build proves compilation only. It does not prove
provider execution, initial root, MapleSU daemon handoff, final policy equality,
SELinux S0, zero boot writes, or full feature parity. New user direction permits
temporary elevation-stage changes; final policy/enforcing equivalence still
requires before/after evidence rather than only a final Enforcing string.
