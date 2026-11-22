// webui_loader -- the root key carried inside the installed image.
//
// The installer rewrites the 4096-byte feature token with the current module
// root key before publishing the program.  Until then the placeholder below is
// what the image contains; at run time this array is the authoritative key, so
// nothing on the command line can substitute a different one.
//
#pragma once

#include <cstddef>
#include <cstring>

#include "feature_token.h"

namespace maplesu::payload::webui {

// 128-character placeholder + NUL padding to 4096 bytes.  The installer's
// in-place replacement keeps the array size, so the runtime accessor below
// always reads a NUL-terminated key of at most kFeatureKeyMaxSize characters.
extern "C" __attribute__((used, visibility("hidden")))
const char kWebuiLoaderRootKey[maplesu::payload::kFeatureTokenSize] =
    "8ba9d457344d22b85d3e7f7263c3dd04d9effeb1becb41a806eaaa9926087fae"
    "49c43c1c3d64c98333e8017195c6ab7bfe7e72a99c4530b267705824e5d6e700";

inline const char* feature_key() { return kWebuiLoaderRootKey; }

inline std::size_t feature_key_length() {
    return strnlen(kWebuiLoaderRootKey, maplesu::payload::kFeatureKeyMaxSize);
}

}  // namespace maplesu::payload::webui
