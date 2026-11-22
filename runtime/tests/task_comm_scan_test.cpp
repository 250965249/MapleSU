#include "task_comm_scan.h"
#include <cassert>
#include <cstdio>
#include <stdexcept>
#include <vector>

namespace {
constexpr uint64_t task = 0xffff800001000000ULL;
const uint8_t name[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,0};
struct Memory {
    std::array<uint8_t, 8208> bytes{};
    uint32_t readable = 8192;
    bool reject_bulk = false;
    unsigned reads = 0, exact_reads = 0;
    std::vector<std::pair<uint32_t, uint32_t>> requests;
    void put(uint32_t offset) { std::memcpy(bytes.data() + offset, name, 15); }
    KModErr read(uint64_t address, void* out, uint32_t size) {
        assert(address >= task && address - task + size <= 8192);
        assert(size >= 15 && size <= 256);
        ++reads;
        if (size == 15) ++exact_reads;
        requests.emplace_back(address - task, size);
        if ((reject_bulk && size > 15) || address - task + size > readable)
            return KModErr::ERR_MODULE_NOT_KADDR;
        std::memcpy(out, bytes.data() + address - task, size);
        return KModErr::OK;
    }
    KModErr scan(uint32_t& offset) {
        return maplesu_task_comm::scan(task, name, offset,
            [&](uint64_t address, void* out, uint32_t size) { return read(address, out, size); });
    }
};
}

int main() {
    unsigned cases = 0;
    for (const uint32_t location : {4U, 8U, 236U, 240U, 244U, 248U, 484U, 488U,
                                  2096U, 4080U, 4084U, 4088U, 4092U, 4096U, 8172U, 8176U}) {
        Memory memory;
        memory.put(location);
        uint32_t found = 0;
        assert(memory.scan(found) == KModErr::OK && found == location);
        assert(memory.reads == location / 244 + 1);
        if (location == 2096) assert(memory.reads == 9);
        ++cases;
    }
    for (const uint32_t location : {0U, 5U, 8180U}) {
        Memory memory;
        memory.put(location);
        uint32_t found = 123;
        assert(memory.scan(found) == KModErr::ERR_MODULE_OFFSET_NOT_FOUND && found == 0);
        ++cases;
    }
    {
        Memory memory;
        memory.put(240);
        memory.put(488);
        uint32_t found = 0;
        assert(memory.scan(found) == KModErr::OK && found == 240 && memory.reads == 1);
        ++cases;
    }
    for (const uint32_t location : {4U, 244U, 2096U, 4092U, 8176U}) {
        Memory memory;
        memory.put(location);
        memory.readable = location + 15;
        uint32_t found = 0;
        assert(memory.scan(found) == KModErr::OK && found == location);
        assert(memory.exact_reads > 0 || location == 8176);
        ++cases;
    }
    {
        Memory memory;
        memory.reject_bulk = true;
        memory.put(2096);
        uint32_t found = 0;
        assert(memory.scan(found) == KModErr::OK && found == 2096);
        assert(memory.exact_reads == 525);
        ++cases;
    }
    {
        Memory memory;
        memory.readable = 14;
        uint32_t found = 0;
        assert(memory.scan(found) == KModErr::ERR_MODULE_NOT_KADDR && found == 0);
        assert(memory.reads == 2 && memory.exact_reads == 1);
        ++cases;
    }
    {
        Memory memory;
        uint32_t found = 99;
        assert(memory.scan(found) == KModErr::ERR_MODULE_OFFSET_NOT_FOUND && found == 0);
        assert(memory.requests.back().first + memory.requests.back().second <= 8192);
        ++cases;
    }
    std::printf("PASS task comm scan: %u cases; 2096 offset needs 9 bulk reads; exact fallback retained\n", cases);
}
