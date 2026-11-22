#pragma once
#include <stdint.h>

#define MAPLESU_HELPER_CAPABILITY_NOTE_TYPE UINT32_C(0x4d534831)
#define MAPLESU_HELPER_CAPABILITY_ABI UINT32_C(1)
#define MAPLESU_HELPER_CAPABILITY_MODULE_BOOT_GATE UINT32_C(1)
#define MAPLESU_HELPER_CAPABILITY_MIN_VERSION_CODE UINT32_C(50200)

/* Private ELF capability description; it conveys no authentication or Root. */
struct maplesu_helper_capability_note {
    uint32_t namesz;
    uint32_t descsz;
    uint32_t type;
    char name[8];
    uint32_t abi_version;
    uint32_t helper_version_code;
    uint32_t capabilities;
    uint32_t reserved;
};
