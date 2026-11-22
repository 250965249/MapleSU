/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef MAPLESU_EXECUTION_FRAME_H
#define MAPLESU_EXECUTION_FRAME_H
#include "request_protocol.h"
#ifdef __KERNEL__
#include <linux/string.h>
#else
#include <string.h>
#endif
#define MAPLESU_FRAME_MAGIC UINT32_C(0x3146534d)
#define MAPLESU_FRAME_VERSION 1u
#define MAPLESU_FRAME_BEGIN 1u
#define MAPLESU_FRAME_VOID 2u
#define MAPLESU_FRAME_U64 3u
struct maplesu_execution_marker {
    uint32_t magic;
    uint16_t version, length;
    uint32_t kind, reserved;
};
static inline int maplesu_frame_contains(const unsigned char *bytes, uint32_t size,
                                        const char *marker, uint32_t length)
{
    uint32_t at;
    if (size < length) return 0;
    for (at = 0; at <= size - length; ++at)
        if (!memcmp(bytes + at, marker, length)) return 1;
    return 0;
}
/* One frame contract for the SDK emitter and resident executor. This proves
 * ABI shape, not arbitrary bytecode safety or non-returning callee behavior. */
static inline int maplesu_standard_frame_valid(const unsigned char *bytes, uint32_t size)
{
    static const uint32_t prefix[] = {0xd503245f,0xa9bf53f3,0xa9bf5bf5,0xa9bf63f7,
        0xa9bf6bf9,0xa9bf73fb,0xa9bf7bfd,0x14000005};
    static const uint32_t suffix[] = {0xa8c17bfd,0xa8c173fb,0xa8c16bf9,0xa8c163f7,
        0xa8c15bf5,0xa8c153f3,0xd65f03c0};
    const struct maplesu_execution_marker begin = {MAPLESU_FRAME_MAGIC,1,16,1,0};
    uint32_t at;
    int ended = 0;
    if (!bytes || size < 100 || (size & 3) || memcmp(bytes,prefix,sizeof(prefix)) ||
        memcmp(bytes + sizeof(prefix),&begin,sizeof(begin))) return 0;
    if (maplesu_frame_contains(bytes,size,"05YWtaGvdCvO80RRK5wuYlPiP5khll8YcJ4P2zGL53FIK9VG3EJGBY20vkCz1kO",64) ||
        maplesu_frame_contains(bytes,size,"CtAjGglsdr80qLTmGyaXMBMorEA9tc2Mll62TwcifS6CujoERzZJVwtQtl3X20C",64) ||
        maplesu_frame_contains(bytes,size,"7Cj4G79IYh5P9GpIBTMeLZsN1YBaylVD77IsAPgfnEhuWn8MGqEd8eBpEcmDoo5",64)) return 0;
    for (at = 48; at <= size - 4; at += 4) {
        struct maplesu_execution_marker marker;
        uint32_t branch,magic,move;
        int tail,valid;
        memcpy(&branch,bytes + at - 4,4);
        memcpy(&magic,bytes + at,4);
        if (size - at < sizeof(marker)) {
            if (branch == 0x14000005 && magic == MAPLESU_FRAME_MAGIC) return 0;
            continue;
        }
        memcpy(&marker,bytes + at,sizeof(marker));
        if (!memcmp(&marker,&begin,sizeof(begin))) return 0;
        tail = size - at >= sizeof(marker) + 32 &&
            !memcmp(bytes + at + sizeof(marker) + 4,suffix,sizeof(suffix));
        valid = marker.magic == MAPLESU_FRAME_MAGIC && marker.version == 1 && marker.length == 16 &&
            (marker.kind == MAPLESU_FRAME_VOID || marker.kind == MAPLESU_FRAME_U64);
        if (branch != 0x14000005) { if (valid && tail) return 0; continue; }
        if (marker.magic != MAPLESU_FRAME_MAGIC && !tail) continue;
        if (!valid || marker.reserved || !tail) return 0;
        memcpy(&move,bytes + at + sizeof(marker),4);
        if ((move & ~UINT32_C(0x001f0000)) != 0xaa0003e0 ||
            (marker.kind == MAPLESU_FRAME_VOID && move != 0xaa1f03e0)) return 0;
        ended = 1;
        at += sizeof(marker) + 32 - 4;
    }
    return ended;
}
#endif
