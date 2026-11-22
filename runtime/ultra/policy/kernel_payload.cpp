#include "kernel_payload.h"
#include <algorithm>
#include <cstring>
#include <elf.h>
#include <set>
#include <stdexcept>
#include <string_view>

namespace maplesu::module_policy {
namespace {
constexpr uint64_t max_image = 8 << 20;
[[noreturn]] void fail(const char* reason) {
    throw std::runtime_error(std::string("MODULE_POLICY_PAYLOAD_") + reason);
}
void require(bool ok, const char* reason) { if (!ok) fail(reason); }
void range(uint64_t offset, uint64_t size, uint64_t limit) {
    require(offset <= limit && size <= limit - offset, "RANGE");
}
template<class T> T read(std::span<const uint8_t> bytes, uint64_t offset) {
    range(offset, sizeof(T), bytes.size());
    T value;
    memcpy(&value, bytes.data() + offset, sizeof(value));
    return value;
}
std::string name(std::span<const uint8_t> strings, uint64_t offset) {
    require(offset < strings.size(), "STRING");
    const auto* start = reinterpret_cast<const char*>(strings.data() + offset);
    const auto* end = static_cast<const char*>(memchr(start, 0, strings.size() - offset));
    require(end, "STRING");
    return std::string(start, end);
}
bool mapped(const PolicyPayload& p, uint64_t at, uint64_t size, uint32_t flags) {
    return std::any_of(p.segments.begin(), p.segments.end(), [&](const auto& seg) {
        return (seg.flags & flags) == flags && at >= seg.offset &&
            at - seg.offset <= seg.size && size <= seg.size - (at - seg.offset);
    });
}
bool landing(uint32_t instruction) {
    return instruction == 0xd503245f;
}
}
std::string kernel_build_id(std::span<const uint8_t> notes) {
    require(notes.size() <= 65536, "NOTES_SIZE");
    std::string result;
    uint64_t at = 0;
    while (at < notes.size()) {
        auto n = read<Elf64_Nhdr>(notes, at);
        at += sizeof(n);
        range(at, (uint64_t(n.n_namesz) + 3) & ~uint64_t(3), notes.size());
        bool gnu = n.n_namesz == 4 && !memcmp(notes.data() + at, "GNU", 4);
        at += (uint64_t(n.n_namesz) + 3) & ~uint64_t(3);
        range(at, (uint64_t(n.n_descsz) + 3) & ~uint64_t(3), notes.size());
        if (gnu && n.n_type == NT_GNU_BUILD_ID) {
            require(result.empty() && n.n_descsz >= 8 && n.n_descsz <= 64, "BUILD_ID");
            const char* hex = "0123456789abcdef";
            for (uint32_t i = 0; i < n.n_descsz; ++i) {
                auto b = notes[at + i];
                result += hex[b >> 4]; result += hex[b & 15];
            }
        }
        at += (uint64_t(n.n_descsz) + 3) & ~uint64_t(3);
    }
    require(!result.empty(), "BUILD_ID_MISSING");
    return result;
}
PolicyPayload parse_policy_payload(std::span<const uint8_t> bytes, uint32_t page_size) {
    require(page_size == 4096 || page_size == 16384 || page_size == 65536, "PAGE_SIZE");
    require(bytes.size() <= max_image, "SIZE");
    const auto h = read<Elf64_Ehdr>(bytes, 0);
    require(!memcmp(h.e_ident, ELFMAG, SELFMAG) && h.e_ident[EI_CLASS] == ELFCLASS64 &&
        h.e_ident[EI_DATA] == ELFDATA2LSB && h.e_ident[EI_VERSION] == EV_CURRENT &&
        h.e_machine == EM_AARCH64 && h.e_type == ET_DYN && h.e_version == EV_CURRENT &&
        h.e_ehsize == sizeof(h) && h.e_entry == 0 && h.e_flags == 0, "FORMAT");
    require(h.e_phnum > 0 && h.e_phnum <= 32 && h.e_phentsize == sizeof(Elf64_Phdr) &&
        h.e_shnum > 0 && h.e_shnum <= 512 && h.e_shentsize == sizeof(Elf64_Shdr) &&
        h.e_shstrndx < h.e_shnum, "TABLE");
    range(h.e_phoff, uint64_t(h.e_phnum) * sizeof(Elf64_Phdr), bytes.size());
    range(h.e_shoff, uint64_t(h.e_shnum) * sizeof(Elf64_Shdr), bytes.size());
    PolicyPayload result;
    result.page_size = page_size;
    std::vector<Elf64_Phdr> loads;
    uint64_t end = 0;
    for (unsigned i = 0; i < h.e_phnum; ++i) {
        auto p = read<Elf64_Phdr>(bytes, h.e_phoff + i * sizeof(Elf64_Phdr));
        require(p.p_type != PT_INTERP && p.p_type != PT_TLS &&
                (p.p_type != PT_GNU_STACK || !(p.p_flags & PF_X)), "PROGRAM");
        if (p.p_type != PT_LOAD) continue;
        require(p.p_memsz && p.p_filesz <= p.p_memsz &&
            (p.p_flags & PF_R) && !(p.p_flags & ~(PF_R | PF_W | PF_X)) &&
            !((p.p_flags & PF_W) && (p.p_flags & PF_X)), "SEGMENT");
        require(p.p_align >= page_size && p.p_align <= 65536 &&
            !(p.p_align & (p.p_align - 1)) && p.p_vaddr % p.p_align == p.p_offset % p.p_align,
            "ALIGNMENT");
        range(p.p_offset, p.p_filesz, bytes.size());
        range(p.p_vaddr, p.p_memsz, max_image);
        const auto first_page = p.p_vaddr / page_size;
        const auto last_page = (p.p_vaddr + p.p_memsz + page_size - 1) / page_size;
        for (const auto& prior : loads)
            require(last_page <= prior.p_vaddr / page_size || first_page >=
                (prior.p_vaddr + prior.p_memsz + page_size - 1) / page_size, "SEGMENT_OVERLAP");
        end = std::max<uint64_t>(end, p.p_vaddr + p.p_memsz);
        loads.push_back(p);
        result.segments.push_back({uint32_t(p.p_vaddr), uint32_t(p.p_memsz), p.p_flags});
    }
    require(!loads.empty() && loads.front().p_vaddr == 0 && end > 0, "LOADS");
    result.image.resize((end + page_size - 1) & ~(uint64_t(page_size) - 1));
    for (const auto& p : loads)
        memcpy(result.image.data() + p.p_vaddr, bytes.data() + p.p_offset, p.p_filesz);
    std::vector<Elf64_Shdr> sections;
    for (unsigned i = 0; i < h.e_shnum; ++i) {
        auto s = read<Elf64_Shdr>(bytes, h.e_shoff + i * sizeof(Elf64_Shdr));
        if (s.sh_type != SHT_NOBITS) range(s.sh_offset, s.sh_size, bytes.size());
        if (s.sh_flags & SHF_ALLOC) {
            require(!(s.sh_flags & SHF_TLS), "TLS");
            require(mapped(result, s.sh_addr, s.sh_size, PF_R), "SECTION_MAPPING");
            if (s.sh_type != SHT_NOBITS)
                require(std::any_of(loads.begin(), loads.end(), [&](const auto& p) {
                    return s.sh_addr >= p.p_vaddr && s.sh_addr - p.p_vaddr <= p.p_filesz &&
                        s.sh_size <= p.p_filesz - (s.sh_addr - p.p_vaddr) &&
                        s.sh_offset == p.p_offset + s.sh_addr - p.p_vaddr;
                }), "SECTION_FILE_MAPPING");
            require(s.sh_type != SHT_REL && s.sh_type != SHT_RELR, "RELOCATION_FORMAT");
        }
        sections.push_back(s);
    }
    const auto& ns = sections[h.e_shstrndx];
    require(ns.sh_type == SHT_STRTAB, "SECTION_NAMES");
    auto names = bytes.subspan(ns.sh_offset, ns.sh_size);
    std::map<std::string, size_t> named;
    for (size_t i = 1; i < sections.size(); ++i) {
        auto n = name(names, sections[i].sh_name);
        require(named.emplace(n, i).second, "DUPLICATE_SECTION");
        if (n == "__jump_table" || n == "__ex_table" || n == ".init_array" || n == ".fini_array")
            require(!sections[i].sh_size, "UNREGISTERED_SECTION");
    }
    auto section = [&](const char* n) -> const Elf64_Shdr& {
        auto it = named.find(n);
        require(it != named.end(), "SECTION_MISSING");
        return sections[it->second];
    };
    const auto& ds = section(".dynsym");
    require(ds.sh_type == SHT_DYNSYM && (ds.sh_flags & SHF_ALLOC) &&
        ds.sh_entsize == sizeof(Elf64_Sym) && ds.sh_size % sizeof(Elf64_Sym) == 0 &&
        ds.sh_size / sizeof(Elf64_Sym) <= 8192 && ds.sh_link < sections.size(), "DYNSYM");
    const auto& st = sections[ds.sh_link];
    require(st.sh_type == SHT_STRTAB && (st.sh_flags & SHF_ALLOC), "DYNSTR");
    auto strings = bytes.subspan(st.sh_offset, st.sh_size);
    std::vector<Elf64_Sym> syms;
    std::vector<std::string> sym_names;
    for (uint64_t i = 0; i < ds.sh_size / sizeof(Elf64_Sym); ++i) {
        auto sym = read<Elf64_Sym>(bytes, ds.sh_offset + i * sizeof(Elf64_Sym));
        auto n = name(strings, sym.st_name);
        require(ELF64_ST_TYPE(sym.st_info) != STT_GNU_IFUNC && ELF64_ST_TYPE(sym.st_info) != STT_TLS,
                "SYMBOL_TYPE");
        if (sym.st_shndx != SHN_UNDEF && !n.empty()) {
            require(sym.st_shndx < sections.size() &&
                mapped(result, sym.st_value, sym.st_size, PF_R) &&
                result.exports.emplace(n, sym.st_value).second, "SYMBOL");
        }
        syms.push_back(sym);
        sym_names.push_back(n);
    }
    const auto& dynamic = section(".dynamic");
    require(dynamic.sh_type == SHT_DYNAMIC && dynamic.sh_size % sizeof(Elf64_Dyn) == 0, "DYNAMIC");
    std::map<int64_t, uint64_t> tags;
    for (uint64_t i = 0; i < dynamic.sh_size; i += sizeof(Elf64_Dyn)) {
        auto d = read<Elf64_Dyn>(bytes, dynamic.sh_offset + i);
        if (d.d_tag == DT_NULL) break;
        switch (d.d_tag) {
        case DT_FLAGS: case DT_FLAGS_1: case DT_RELA: case DT_RELASZ: case DT_RELAENT:
        case DT_RELACOUNT: case DT_JMPREL: case DT_PLTRELSZ: case DT_PLTGOT: case DT_PLTREL:
        case DT_SYMTAB: case DT_SYMENT: case DT_STRTAB: case DT_STRSZ: case DT_GNU_HASH:
        case DT_HASH: case 0x70000001: // DT_AARCH64_BTI_PLT
            break;
        default: fail("DYNAMIC_TAG");
        }
        require(tags.emplace(d.d_tag, d.d_un.d_val).second, "DUPLICATE_TAG");
    }
    require(tags[DT_SYMTAB] == ds.sh_addr && tags[DT_SYMENT] == sizeof(Elf64_Sym) &&
        tags[DT_STRTAB] == st.sh_addr && tags[DT_STRSZ] == st.sh_size &&
        !(tags[DT_FLAGS] & (DF_TEXTREL | DF_STATIC_TLS)) &&
        !(tags[DT_FLAGS_1] & ~uint64_t(DF_1_NOW)), "DYNAMIC_VALUES");
    std::set<uint64_t> destinations;
    for (size_t index = 1; index < sections.size(); ++index) {
        const auto& s = sections[index];
        if (s.sh_type != SHT_RELA || !(s.sh_flags & SHF_ALLOC)) continue;
        require(s.sh_link == named.at(".dynsym") && s.sh_entsize == sizeof(Elf64_Rela) &&
            s.sh_size % sizeof(Elf64_Rela) == 0, "RELOCATION_TABLE");
        bool plt = tags[DT_JMPREL] == s.sh_addr;
        require(plt ? tags[DT_PLTRELSZ] == s.sh_size && tags[DT_PLTREL] == DT_RELA :
            tags[DT_RELA] == s.sh_addr && tags[DT_RELASZ] == s.sh_size &&
            tags[DT_RELAENT] == sizeof(Elf64_Rela), "RELOCATION_DYNAMIC");
        for (uint64_t at = 0; at < s.sh_size; at += sizeof(Elf64_Rela)) {
            auto r = read<Elf64_Rela>(bytes, s.sh_offset + at);
            const auto type = ELF64_R_TYPE(r.r_info), sym = ELF64_R_SYM(r.r_info);
            require(!(r.r_offset & 7) && mapped(result, r.r_offset, 8, PF_W) &&
                destinations.insert(r.r_offset).second && sym < syms.size(), "RELOCATION_TARGET");
            require(type == R_AARCH64_RELATIVE || type == R_AARCH64_GLOB_DAT ||
                type == R_AARCH64_JUMP_SLOT, "RELOCATION_TYPE");
            if (type == R_AARCH64_RELATIVE)
                require(!sym && r.r_addend >= 0 && mapped(result, r.r_addend, 1, PF_R), "RELATIVE");
            else
                require(sym && syms[sym].st_shndx == SHN_UNDEF && !sym_names[sym].empty() &&
                    ELF64_ST_BIND(syms[sym].st_info) == STB_GLOBAL && !r.r_addend, "IMPORT");
            result.relocations.push_back({uint32_t(r.r_offset), uint32_t(type),
                uint64_t(r.r_addend), sym_names[sym]});
        }
    }
    const char* entries[] = {"maplesu_policy_view_prepare", "maplesu_policy_view_handles",
        "maplesu_policy_view_context", "maplesu_policy_view_access",
        "maplesu_policy_view_setprocattr", "maplesu_policy_view_status_open",
        "maplesu_policy_view_status_read", "maplesu_policy_view_status_mmap",
        "maplesu_policy_view_filter", "maplesu_policy_view_creds_changed", "maplesu_policy_view_receive"};
    for (const auto* n : entries) {
        auto it = result.exports.find(n);
        require(it != result.exports.end() && !(it->second & 3) &&
            mapped(result, it->second, 4, PF_X) && landing(read<uint32_t>(result.image, it->second)), "ENTRY");
    }
    // Entry landing instructions alone do not certify BTI: require the linker property too.
    const auto& note = section(".note.gnu.property");
    auto header = read<Elf64_Nhdr>(bytes, note.sh_offset);
    require(note.sh_size == 32 && header.n_namesz == 4 && header.n_descsz == 16 &&
        header.n_type == NT_GNU_PROPERTY_TYPE_0 && !memcmp(bytes.data() + note.sh_offset + 12, "GNU", 4) &&
        read<uint32_t>(bytes, note.sh_offset + 16) == GNU_PROPERTY_AARCH64_FEATURE_1_AND &&
        read<uint32_t>(bytes, note.sh_offset + 20) == 4 &&
        (read<uint32_t>(bytes, note.sh_offset + 24) & GNU_PROPERTY_AARCH64_FEATURE_1_BTI), "BTI_PROPERTY");
    auto alt = named.find(".altinstructions");
    if (alt != named.end()) {
        const auto& s = sections[alt->second];
        require((s.sh_flags & SHF_ALLOC) && !(s.sh_size % 12), "ALTERNATIVES");
        result.alternatives = s.sh_addr;
        result.alternative_bytes = s.sh_size;
        for (uint64_t i = 0; i < s.sh_size; i += 12) {
            auto at = s.sh_addr + i;
            auto original = at + int64_t(read<int32_t>(result.image, at));
            auto replacement = at + 4 + int64_t(read<int32_t>(result.image, at + 4));
            auto length = result.image[at + 10];
            require(length && !(length & 3) && length == result.image[at + 11] &&
                mapped(result, original, length, PF_X) && mapped(result, replacement, length, PF_X),
                "ALTERNATIVE_RANGE");
        }
    }
    auto frames = named.find(".eh_frame");
    if (frames != named.end()) {
        const auto& s = sections[frames->second];
        require((s.sh_flags & SHF_ALLOC) && !(s.sh_addr & 3) && !(s.sh_size & 3), "SCS_FRAMES");
        result.scs_frames = s.sh_addr;
        result.scs_frame_bytes = s.sh_size;
    }
    return result;
}
std::vector<uint32_t> policy_scs_patch_sites(const PolicyPayload& p) {
    require(p.scs_frame_bytes && mapped(p, p.scs_frames, p.scs_frame_bytes, PF_R), "SCS_FRAMES");
    uint64_t at = p.scs_frames, end = at + p.scs_frame_bytes;
    std::set<uint64_t> cies;
    std::set<uint32_t> sites;
    while (at < end) {
        require(end - at >= 4, "SCS_FRAME_LENGTH");
        auto length = read<uint32_t>(p.image, at);
        if (!length) {
            require(at + 4 == end, "SCS_TERMINATOR");
            break;
        }
        require(length >= 12 && !(length & 3) && length <= end - at - 4, "SCS_FRAME_LENGTH");
        const auto next = at + 4 + length;
        auto cie = read<uint32_t>(p.image, at + 4);
        if (!cie) {
            // Native scs_patch assumes code alignment 1 for FDEs. zR uses
            // signed PC-relative 32-bit pointers and no FDE augmentation data.
            require(length == 16 && p.image[at + 8] == 1 &&
                !memcmp(p.image.data() + at + 9, "zR", 3) && p.image[at + 12] == 1 &&
                (p.image[at + 13] == 0x7c || p.image[at + 13] == 0x78) &&
                p.image[at + 14] == 30 && p.image[at + 15] == 1 && p.image[at + 16] == 0x1b &&
                p.image[at + 17] == 0x0c && p.image[at + 18] == 31 && !p.image[at + 19], "SCS_CIE");
            cies.insert(at);
        } else {
            require(length >= 16 && cie <= at + 4 && cies.count(at + 4 - cie), "SCS_CIE_POINTER");
            int64_t first = int64_t(at + 8) + read<int32_t>(p.image, at + 8);
            auto size = read<int32_t>(p.image, at + 12);
            require(first >= 0 && size > 0 && !(first & 3) && !(size & 3) &&
                mapped(p, uint64_t(first), uint32_t(size), PF_X), "SCS_CODE_RANGE");
            uint64_t loc = first, limit = first + size, op = at + 16;
            require(!p.image[op++], "SCS_AUGMENTATION");
            auto skip_leb = [&] {
                unsigned n = 0;
                for (;;) {
                    require(op < next && ++n <= 10, "SCS_LEB");
                    if (!(p.image[op++] & 0x80)) break;
                }
            };
            while (op < next) {
                auto byte = p.image[op++];
                uint32_t advance = 0;
                if (byte >= 0x40 && byte <= 0x7f) advance = byte & 0x3f;
                else if (byte >= 0x80 && byte <= 0xbf) skip_leb();
                else if (byte >= 0xc0) {}
                else switch (byte) {
                case 0: case 0x0a: case 0x0b: break;
                case 2:
                    require(op < next, "SCS_OPCODE_RANGE"); advance = p.image[op++]; break;
                case 3:
                    require(next - op >= 2, "SCS_OPCODE_RANGE");
                    advance = p.image[op] | uint32_t(p.image[op + 1]) << 8; op += 2; break;
                case 5: case 0x0c: skip_leb(); [[fallthrough]];
                case 6: case 8: case 0x0d: case 0x0e: case 0x13: skip_leb(); break;
                case 0x2d: {
                    require(loc >= uint64_t(first) + 4, "SCS_PATCH_RANGE");
                    auto insn = read<uint32_t>(p.image, loc - 4);
                    if (insn == 0xd503233f || insn == 0xd50323bf) sites.insert(loc - 4);
                    break;
                }
                default: fail("SCS_OPCODE");
                }
                require(advance <= limit - loc, "SCS_LOCATION");
                loc += advance;
            }
        }
        at = next;
    }
    require(!cies.empty() && !sites.empty(), "SCS_EMPTY");
    return {sites.begin(), sites.end()};
}
void relocate_policy_payload(PolicyPayload& p, uint64_t base,
                             const std::map<std::string, uint64_t>& imports) {
    require(!p.base && base >= 0xffff000000000000ULL && !(base & 65535) &&
        p.image.size() <= UINT64_MAX - base, "BASE");
    // Resolve every import before altering the first image byte.
    for (const auto& r : p.relocations) {
        if (r.type == R_AARCH64_RELATIVE) continue;
        auto it = imports.find(r.symbol);
        require(it != imports.end() && it->second >= 0xffff000000000000ULL, "IMPORT_ADDRESS");
    }
    for (const auto& r : p.relocations) {
        auto value = r.type == R_AARCH64_RELATIVE ? base + r.value : imports.at(r.symbol);
        memcpy(p.image.data() + r.offset, &value, sizeof(value));
    }
    p.base = base;
}
}
