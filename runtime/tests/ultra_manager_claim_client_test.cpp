// SPDX-License-Identifier: GPL-3.0-only
#include "../ultra/bridge/manager_identity_claim.h"
#include <cassert>
#include <cstring>
#include <iostream>
#include <stdexcept>

int main() {
    unsigned int checks = 0;
    for (const uint64_t value : {1ULL, 0x123456789abcdef0ULL, 0xffffffffffffffffULL}) {
        char name[MSU_MANAGER_CLAIM_NAME_BYTES + 1];
        msu_manager_claim_name(name, value);
        assert(std::strlen(name) == MSU_MANAGER_CLAIM_NAME_BYTES);
        assert(msu_manager_claim_address(name, std::strlen(name)) == value);
        for (size_t size = 0; size < MSU_MANAGER_CLAIM_NAME_BYTES; ++size) {
            assert(!msu_manager_claim_address(name, size));
            ++checks;
        }
        for (size_t at = 0; at < MSU_MANAGER_CLAIM_NAME_BYTES; ++at) {
            const char original = name[at];
            name[at] = '!';
            assert(!msu_manager_claim_address(name, MSU_MANAGER_CLAIM_NAME_BYTES));
            name[at] = original;
            ++checks;
        }
        ++checks;
    }
    assert(!msu_manager_claim_address(nullptr, MSU_MANAGER_CLAIM_NAME_BYTES));
    const std::string key = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL";
    assert(key.size() == MSU_MANAGER_CLAIM_KEY_BYTES);
    auto respond = [&](const char* name, size_t size) {
        const auto pointer = msu_manager_claim_address(name, std::strlen(name));
        assert(pointer);
        auto* bytes = reinterpret_cast<char*>(static_cast<uintptr_t>(pointer));
        for (size_t at = 0; at < MSU_MANAGER_CLAIM_KEY_BYTES; ++at) assert(bytes[at] == 0);
        std::memcpy(bytes, key.data(), size);
    };
    assert(maplesu::manager_identity_candidate_with([&](const char* name) {
        respond(name, key.size());
    }) == key);
    ++checks;
    for (size_t size = 0; size < key.size(); ++size) {
        assert(maplesu::manager_identity_candidate_with([&](const char* name) {
            respond(name, size);
        }).empty());
        ++checks;
    }
    for (size_t at = 0; at < key.size(); ++at) {
        assert(maplesu::manager_identity_candidate_with([&](const char* name) {
            respond(name, key.size());
            auto* bytes = reinterpret_cast<char*>(static_cast<uintptr_t>(
                msu_manager_claim_address(name, std::strlen(name))));
            bytes[at] = '!';
        }).empty());
        ++checks;
    }
    try {
        maplesu::manager_identity_candidate_with([&](const char* name) {
            respond(name, key.size());
            throw std::runtime_error("fixture interrupted");
        });
        assert(false);
    } catch (const std::runtime_error&) { ++checks; }
    /* Actually execute the absent-path request on an ordinary host kernel. */
    assert(maplesu::manager_identity_candidate().empty());
    ++checks;
    std::cout << "manager claim client checks: " << checks << '\n';
}
