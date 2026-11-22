/* Runs at load_module before signatures, relocations, module lists or module init.
 * The input is the loader's private kernel copy, never a user pointer. */
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long u64;

extern void vr_release(void *info, int flags);

static u16 le16(const u8 *p) { return p[0] | (u16)p[1] << 8; }
static u32 le32(const u8 *p) {
    return p[0] | (u32)p[1] << 8 | (u32)p[2] << 16 | (u32)p[3] << 24;
}
static u64 le64(const u8 *p) { return le32(p) | (u64)le32(p + 4) << 32; }
static int range(u64 off, u64 size, u64 len) { return off <= len && size <= len - off; }

int vr_filter(void *info, int flags, u32 hdr_off, u32 len_off, int compressed_cleanup) {
    const u8 *hdr = *(const u8 **)((u8 *)info + hdr_off);
    u64 len = *(u64 *)((u8 *)info + len_off);
    if ((flags & 4) && !compressed_cleanup) return 0;
    if (!hdr || len < 64 || len > 0x10000000UL) return 0;
    if (le32(hdr) != 0x464c457f || hdr[4] != 2 || hdr[5] != 1 ||
        hdr[6] != 1 || le16(hdr + 16) != 1 || le16(hdr + 18) != 183 ||
        le16(hdr + 58) != 64) return 0;
    u64 shoff = le64(hdr + 40);
    u32 count = le16(hdr + 60), strings = le16(hdr + 62);
    if (!count || count > 4096 || strings >= count || !range(shoff, (u64)count * 64, len)) return 0;
    const u8 *strsec = hdr + shoff + (u64)strings * 64;
    u64 stroff = le64(strsec + 24), strsize = le64(strsec + 32);
    if (!range(stroff, strsize, len)) return 0;
    for (u32 i = 0; i < count; i++) {
        const u8 *sec = hdr + shoff + (u64)i * 64;
        u32 name = le32(sec);
        if (!range(name, 9, strsize)) continue;
        const u8 *s = hdr + stroff + name;
        if (s[0] != '.' || s[1] != 'm' || s[2] != 'o' || s[3] != 'd' ||
            s[4] != 'i' || s[5] != 'n' || s[6] != 'f' || s[7] != 'o' || s[8]) continue;
        u64 off = le64(sec + 24), size = le64(sec + 32);
        if (le32(sec + 4) != 1 || !range(off, size, len) || size > 0x100000UL) return 0;
        const u8 *p = hdr + off;
        for (u64 at = 0; at < size;) {
            u64 end = at;
            while (end < size && p[end]) end++;
            if (end == size) return 0;
            if (end - at == 7 && p[at] == 'n' && p[at+1] == 'a' && p[at+2] == 'm' &&
                p[at+3] == 'e' && p[at+4] == '=' && p[at+5] == 'v' && p[at+6] == 'r') {
                vr_release(info, flags);
                return 1;
            }
            at = end + 1;
        }
    }
    return 0;
}
