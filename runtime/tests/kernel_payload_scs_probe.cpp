// Emit prevalidated input/expected bytes for replay of the actual kernel patcher.
#include "kernel_payload.h"
#include <cassert>
#include <cstring>
#include <fstream>
#include <iterator>
using namespace maplesu::module_policy;
int main(int argc, char** argv) {
    assert(argc == 3);
    std::ifstream input(argv[1], std::ios::binary); assert(input);
    const std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    auto p = parse_policy_payload(bytes, 4096);
    auto sites = policy_scs_patch_sites(p);
    auto save = [&](const char* suffix) {
        std::ofstream output(std::string(argv[2]) + suffix, std::ios::binary);
        output.write(reinterpret_cast<const char*>(p.image.data()), p.image.size()); assert(output);
    };
    save("-before.bin");
    for (auto at : sites) {
        uint32_t insn; memcpy(&insn, p.image.data() + at, 4);
        insn = insn == 0xd503233f ? 0xf800865e : 0xf85f8e5e;
        memcpy(p.image.data() + at, &insn, 4);
    }
    save("-expected.bin");
    std::ofstream meta(std::string(argv[2]) + ".json");
    meta << "{\"frameOffset\":" << p.scs_frames << ",\"frameBytes\":" << p.scs_frame_bytes
         << ",\"patchSites\":" << sites.size() << "}\n"; assert(meta);
}
