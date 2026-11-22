// Installer feature token.
//
// Three of the embedded programs are installed with an in-place root-key
// replacement: the installer byte-scans the program image for a 4096-byte token
// (128 hex characters followed by NUL padding) and rewrites that token with the
// current module root key, keeping the image length unchanged.  The program
// therefore carries its key material inside its own image and never receives it
// on the command line or through the environment.
//
// The array below is that token.  It is `used` so the compiler cannot drop it and
// it is the only copy in the image, so the installer's scan finds exactly one
// occurrence.  At run time `feature_key()` reads whatever the installer wrote
// there: the 128-character placeholder before installation, the real root key
// afterwards.
//
#pragma once

#include <cstddef>
#include <cstring>

namespace maplesu::payload {

inline constexpr size_t kFeatureTokenSize = 4096;
inline constexpr size_t kFeatureKeyMaxSize = 1024;

}  // namespace maplesu::payload
