#include "../src/aarch64/branch_encoding.h"
#include <cstdint>
#include <iostream>

int main() {
    std::uint64_t from = 0, to = 0;
    while (std::cin >> std::hex >> from >> to) {
        std::uint32_t word = 0;
        const bool accepted = maplesu::aarch64::encode_b(from, to, word);
        std::cout << accepted << ' ' << std::hex << word << '\n';
    }
}
