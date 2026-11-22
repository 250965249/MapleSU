// su -- the root key carried inside the installed image.
//
// The installer rewrites this 4096-byte feature token with the current module
// root key before publishing the program; at run time the array is the key the
// kernel handshake expects.  The placeholder below is the vendor constant from
// the open-edition su client, so an un-installed image behaves exactly like the
// reference image before its install-time rewrite.
//
#pragma once

#include <cstddef>
#include <cstring>

#include "feature_token.h"

namespace maplesu::payload::su {

extern "C" __attribute__((used, visibility("hidden")))
const char kSuRootKey[maplesu::payload::kFeatureTokenSize] =
    "ae40aa59c886d2c8762e849e9fa798155cd438a5faa748706084c6da3ca9add72a"
    "02c0128f6d56ba4a077a7bbd6ca8b6fa93b8c32e1ba5c2203e6e4c3cc24064";

inline const char* feature_key() { return kSuRootKey; }

}  // namespace maplesu::payload::su
