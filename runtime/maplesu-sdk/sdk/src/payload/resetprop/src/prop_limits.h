// resetprop -- Android property record limits shared by the CLI and the API layer.
//
// The fast property area holds names shorter than 32 bytes and values shorter
// than 92 bytes; longer values use the long-property representation.  The CLI
// uses the value limit to decide when a read-only property must be recreated,
// the API layer uses both as scratch-buffer sizes.
//
#pragma once

#include <cstddef>

namespace maplesu::payload::resetprop {

inline constexpr size_t kPropNameMax = 32;
inline constexpr size_t kPropValueMax = 92;
// Highest bit of prop_info::serial marks a long property.
inline constexpr unsigned kLongPropertyFlag = 0x80000000u;

}  // namespace maplesu::payload::resetprop
