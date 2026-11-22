#include "kernel_payload.h"
#include <cassert>
#include <cstdio>
#include <cstring>
#include <elf.h>
#include <fstream>
#include <iterator>
#include <stdexcept>

using namespace maplesu::module_policy;
namespace {
unsigned tests = 0;
std::vector<uint8_t> original;
template<class T> T get(const std::vector<uint8_t>& b, size_t at) {
    T v; assert(at <= b.size() && sizeof(v) <= b.size() - at); memcpy(&v, b.data() + at, sizeof(v)); return v;
}
template<class T> void put(std::vector<uint8_t>& b, size_t at, T v) {
    assert(at <= b.size() && sizeof(v) <= b.size() - at); memcpy(b.data() + at, &v, sizeof(v));
}
void rejects(const std::vector<uint8_t>& b, uint32_t pages = 4096) {
    bool failed = false;
    try { (void)parse_policy_payload(b, pages); }
    catch (const std::runtime_error& e) { failed = std::string(e.what()).starts_with("MODULE_POLICY_PAYLOAD_"); }
    assert(failed); ++tests;
}
size_t section_offset(const char* name) {
    auto h = get<Elf64_Ehdr>(original, 0);
    auto ns = get<Elf64_Shdr>(original, h.e_shoff + h.e_shstrndx * sizeof(Elf64_Shdr));
    for (unsigned i = 0; i < h.e_shnum; ++i) {
        size_t at = h.e_shoff + i * sizeof(Elf64_Shdr);
        auto s = get<Elf64_Shdr>(original, at);
        if (!strcmp(reinterpret_cast<const char*>(original.data() + ns.sh_offset + s.sh_name), name)) return at;
    }
    return 0;
}
}
int main(int argc, char** argv) {
    assert(argc == 2 || argc == 3);
    std::ifstream input(argv[1], std::ios::binary); assert(input);
    original.assign(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
    // /sys/kernel/notes is an ELF note stream, not an ELF image. Keep note
    // alignment/truncation and duplicate identities outside the kernel boundary.
    std::vector<uint8_t> notes(12 + 4 + 20);
    put<Elf64_Nhdr>(notes, 0, {4, 20, NT_GNU_BUILD_ID});
    memcpy(notes.data() + 12, "GNU", 4);
    for (unsigned i = 0; i < 20; ++i) notes[16 + i] = i;
    assert(kernel_build_id(notes) == "000102030405060708090a0b0c0d0e0f10111213"); ++tests;
    auto bad_notes = [&](const std::vector<uint8_t>& b) {
        bool failed = false;
        try { (void)kernel_build_id(b); } catch (const std::runtime_error&) { failed = true; }
        assert(failed); ++tests;
    };
    for (size_t n = 0; n < notes.size(); ++n) bad_notes({notes.begin(), notes.begin() + n});
    auto duplicate = notes; duplicate.insert(duplicate.end(), notes.begin(), notes.end()); bad_notes(duplicate);
    auto changed = notes; put<uint32_t>(changed, 4, UINT32_MAX); bad_notes(changed);
    changed = notes; put<uint32_t>(changed, 0, UINT32_MAX); bad_notes(changed);
    changed = notes; changed[15] = 'X'; bad_notes(changed);
    changed = notes; put<uint32_t>(changed, 8, NT_GNU_PROPERTY_TYPE_0); bad_notes(changed);
    changed = notes; put<uint32_t>(changed, 4, 4); changed.resize(20); bad_notes(changed);
    changed.resize(65537); bad_notes(changed);
    // Other kernel notes may precede GNU's build ID with 4-byte padding.
    std::vector<uint8_t> prefix(20);
    put<Elf64_Nhdr>(prefix, 0, {1, 1, 99}); prefix[12] = 'X'; prefix[16] = 0xab;
    prefix.insert(prefix.end(), notes.begin(), notes.end());
    assert(kernel_build_id(prefix) == kernel_build_id(notes)); ++tests;
    const auto h = get<Elf64_Ehdr>(original, 0);
    for (uint32_t page : {4096, 16384, 65536}) {
        auto p = parse_policy_payload(original, page);
        assert(p.exports.size() >= 6 && !p.relocations.empty() && p.image.size() % page == 0); ++tests;
        std::map<std::string, uint64_t> imports;
        for (const auto& r : p.relocations) if (!r.symbol.empty()) imports.emplace(r.symbol, 0xffff000012340000);
        relocate_policy_payload(p, 0xffff800040000000, imports);
        for (const auto& r : p.relocations)
            assert(get<uint64_t>(p.image, r.offset) == (r.symbol.empty() ? p.base + r.value : imports.at(r.symbol)));
        ++tests;
        bool failed = false;
        try { relocate_policy_payload(p, p.base, imports); } catch (const std::runtime_error&) { failed = true; }
        assert(failed); ++tests;
    }
    for (uint32_t page : {0, 1, 4095, 8192, 32768, 131072}) rejects(original, page);
    for (size_t n = 0; n < sizeof(Elf64_Ehdr); ++n) rejects({original.begin(), original.begin() + n});
    for (size_t n : {size_t(h.e_phoff), size_t(h.e_shoff), original.size() - 1}) rejects({original.begin(), original.begin() + n});
    auto b = original;
    b[EI_CLASS] = ELFCLASS32; rejects(b);
    b = original; b[EI_DATA] = ELFDATA2MSB; rejects(b);
    b = original; put<uint16_t>(b, offsetof(Elf64_Ehdr, e_type), ET_EXEC); rejects(b);
    b = original; put<uint16_t>(b, offsetof(Elf64_Ehdr, e_machine), EM_X86_64); rejects(b);
    b = original; put<uint64_t>(b, offsetof(Elf64_Ehdr, e_phoff), UINT64_MAX); rejects(b);
    b = original; put<uint64_t>(b, offsetof(Elf64_Ehdr, e_shoff), UINT64_MAX); rejects(b);
    b = original; put<uint16_t>(b, offsetof(Elf64_Ehdr, e_phnum), 65535); rejects(b);
    b = original; put<uint16_t>(b, offsetof(Elf64_Ehdr, e_shstrndx), h.e_shnum); rejects(b);
    size_t first_load = 0;
    for (unsigned i = 0; i < h.e_phnum; ++i) {
        size_t at = h.e_phoff + i * sizeof(Elf64_Phdr);
        auto seg = get<Elf64_Phdr>(original, at);
        if (seg.p_type != PT_LOAD) continue;
        if (!first_load) first_load = at;
        b = original; put<uint32_t>(b, at + offsetof(Elf64_Phdr, p_flags), PF_R | PF_W | PF_X); rejects(b);
        b = original; put<uint64_t>(b, at + offsetof(Elf64_Phdr, p_memsz), 0); rejects(b);
        b = original; put<uint64_t>(b, at + offsetof(Elf64_Phdr, p_offset), UINT64_MAX); rejects(b);
        b = original; put<uint64_t>(b, at + offsetof(Elf64_Phdr, p_align), 32767); rejects(b);
        b = original; put<uint32_t>(b, at + offsetof(Elf64_Phdr, p_type), PT_TLS); rejects(b);
        if (at != first_load) { b = original; put<uint64_t>(b, at + offsetof(Elf64_Phdr, p_vaddr), 0); rejects(b); }
    }
    for (const auto* n : {".dynsym", ".dynstr", ".dynamic", ".note.gnu.property"}) {
        size_t at = section_offset(n); assert(at);
        b = original; put<uint64_t>(b, at + offsetof(Elf64_Shdr, sh_offset), UINT64_MAX); rejects(b);
        b = original; put<uint64_t>(b, at + offsetof(Elf64_Shdr, sh_addr), 0x600000); rejects(b);
    }
    auto ds = get<Elf64_Shdr>(original, section_offset(".dynamic"));
    b = original; put<int64_t>(b, ds.sh_offset, DT_NEEDED); rejects(b);
    auto rela = get<Elf64_Shdr>(original, section_offset(".rela.plt"));
    b = original; put<uint64_t>(b, rela.sh_offset + offsetof(Elf64_Rela, r_info), ELF64_R_INFO(1, R_AARCH64_ABS64)); rejects(b);
    b = original; put<uint64_t>(b, rela.sh_offset + offsetof(Elf64_Rela, r_offset), 0); rejects(b);
    b = original; put<int64_t>(b, rela.sh_offset + offsetof(Elf64_Rela, r_addend), 1); rejects(b);
    b = original; put<uint64_t>(b, rela.sh_offset + offsetof(Elf64_Rela, r_info), ELF64_R_INFO(65535, R_AARCH64_JUMP_SLOT)); rejects(b);
    if (rela.sh_size > sizeof(Elf64_Rela)) {
        b = original; put<uint64_t>(b, rela.sh_offset + sizeof(Elf64_Rela), get<uint64_t>(original, rela.sh_offset)); rejects(b);
    }
    auto note = get<Elf64_Shdr>(original, section_offset(".note.gnu.property"));
    b = original; put<uint32_t>(b, note.sh_offset + 24, 0); rejects(b);
    auto alt_index = section_offset(".altinstructions");
    if (alt_index) {
        auto alt = get<Elf64_Shdr>(original, alt_index);
        if (alt.sh_size) {
            b = original; put<int32_t>(b, alt.sh_offset, 0x400000); rejects(b);
            b = original; b[alt.sh_offset + 10] = 1; rejects(b);
        }
    }
    auto p = parse_policy_payload(original, 4096);
    if (argc == 3) {
        const auto sites = policy_scs_patch_sites(p); assert(!sites.empty()); ++tests;
        for (auto at : sites) {
            auto insn = get<uint32_t>(p.image, at);
            assert(insn == 0xd503233f || insn == 0xd50323bf);
        }
        auto rejects_scs = [&](PolicyPayload value) {
            bool failed = false;
            try { (void)policy_scs_patch_sites(value); } catch (const std::runtime_error&) { failed = true; }
            assert(failed); ++tests;
        };
        auto altered = p; altered.scs_frame_bytes = 0; rejects_scs(altered);
        altered = p; altered.scs_frames = uint32_t(p.image.size()); rejects_scs(altered);
        // The first CIE and FDE belong to the real clang-produced table.
        const auto cie = p.scs_frames;
        const auto fde = cie + 4 + get<uint32_t>(p.image, cie);
        for (auto [at, value] : std::vector<std::pair<uint32_t, uint32_t>>{
                {cie, UINT32_MAX}, {cie, 0}, {fde, UINT32_MAX}, {fde + 4, UINT32_MAX},
                {fde + 8, 0x7fffffff}, {fde + 12, 0xffffffff}, {fde + 12, 0}}) {
            altered = p; put<uint32_t>(altered.image, at, value); rejects_scs(altered);
        }
        for (uint32_t at : {cie + 8, cie + 9, cie + 12, cie + 16, fde + 16}) {
            altered = p; altered.image[at] ^= 0x80; rejects_scs(altered);
        }
    }
    auto text = get<Elf64_Shdr>(original, section_offset(".text"));
    b = original; put<uint32_t>(b, text.sh_offset + p.exports.at("maplesu_policy_view_prepare") - text.sh_addr, 0xd503201f); rejects(b);
    auto unchanged = p.image;
    for (uint64_t base : {uint64_t(0), uint64_t(0x10000000), uint64_t(0xffff000000000001), UINT64_MAX - 65535}) {
        bool failed = false;
        try { relocate_policy_payload(p, base, {}); } catch (const std::runtime_error&) { failed = true; }
        assert(failed && p.image == unchanged && !p.base); ++tests;
    }
    bool failed = false;
    try { relocate_policy_payload(p, 0xffff800000000000, {}); } catch (const std::runtime_error&) { failed = true; }
    assert(failed && p.image == unchanged && !p.base); ++tests;
    printf("PASS %u PIC parser/relocation cases (real payload, three page sizes, malformed inputs, W^X and imports)\n", tests);
}
