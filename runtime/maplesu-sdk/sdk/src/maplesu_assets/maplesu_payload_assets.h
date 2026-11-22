// MapleSU payload assets implementation.
//
#pragma once

#include <cstddef>

#if defined(MAPLESU_PAYLOAD_ASSETS) && MAPLESU_PAYLOAD_ASSETS
#include "payload_assets.generated.h"
#include "payload_sizes.generated.h"
#define MAPLESU_PAYLOAD_ASSETS_REAL 1
#else
namespace maplesu::sdk {
static const unsigned char su_data[1] = {0x00};
static const unsigned char resetprop_file_data[1] = {0x00};
static const unsigned char webui_loader_data[1] = {0x00};
static const unsigned char autorun_bootstrap_file_data[1] = {0x00};

// Stub build: the payload arrays are one byte, so the size pins describe the
// reference payloads the installers are standing in for.  A real build reads the
// same constants from the generated sizes header (payload_sizes.generated.h),
// which sdk/tools/build_payloads.py derives from the actual built programs.
constexpr unsigned long kSuPayloadSize = 741912;           // .data 0x0b5218
constexpr unsigned long kResetpropPayloadSize = 400568;    // .data 0x061cb8
constexpr unsigned long kWebuiLoaderPayloadSize = 766320;  // .data 0x0bb170
constexpr unsigned long kAutorunBootstrapPayloadSize = 1351120;  // .data 0x149dd0
}  // namespace maplesu::sdk
#endif

namespace maplesu::sdk {

// Compile-time truth: are the arrays the real payload bytes or the 1-byte stubs?
constexpr bool kPayloadsReal = MAPLESU_PAYLOAD_ASSETS_REAL != 0;

// They are asserted against sizeof(<array>) for real builds (see the installers)
// and let stub builds report what they are standing in for.  In a real build the
// four constants come from payload_sizes.generated.h (included above), so they
// always describe the bytes this build actually embeds.

}  // namespace maplesu::sdk
