#include "../ultra/bridge/image_credentials.h"
#include <cassert>
#include <fstream>
#include <iostream>
#include <iterator>

namespace {
constexpr char alphabet[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
constexpr size_t key_at = 128, metadata_at = 2048, call_at = 1024;
using Bytes = std::vector<uint8_t>;

void word(Bytes& bytes, size_t at, uint32_t value) {
    for (unsigned i = 0; i < 4; ++i) bytes[at + i] = uint8_t(value >> (i * 8));
}

std::string key(int delta) {
    std::string result(48, 'a'), digits;
    unsigned magnitude = unsigned(delta < 0 ? -delta : delta);
    do { digits.insert(digits.begin(), alphabet[magnitude % 62]); magnitude /= 62; } while (magnitude);
    digits += delta < 0 ? '0' : '1';
    const size_t count = digits.size() + 1, start = 50 - count;
    std::string encoded(1, 'a');
    for (size_t i = 0; i < digits.size(); ++i)
        encoded += alphabet[(std::strchr(alphabet, digits[i]) - alphabet + 10 + i) % 62];
    for (size_t i = 0; i + 2 < encoded.size(); ++i) result[start + i] = encoded[i];
    result[15] = encoded[count - 2]; result[2] = encoded[count - 1];
    result[1] = alphabet[(10 + count) % 62];
    return result;
}

Bytes fixture(int delta = int(metadata_at - call_at)) {
    Bytes bytes(4096, 0);
    std::memcpy(bytes.data() + 56, "ARMd", 4);
    const auto credential = key(delta);
    std::memcpy(bytes.data() + key_at, credential.data(), credential.size());
    word(bytes, metadata_at, metadata_at);
    word(bytes, metadata_at + 4, 3072);
    const auto path = "/data/" + credential.substr(0, 16) + "/init";
    std::memcpy(bytes.data() + metadata_at + 8, path.c_str(), path.size() + 1);
    if (int(metadata_at) - delta >= 0 && int(metadata_at) - delta + 4 <= int(bytes.size()))
        word(bytes, size_t(int(metadata_at) - delta), 0xd63f0140);
    return bytes;
}

void expect(const Bytes& bytes, size_t count) {
    const auto result = maplesu::image_credentials(bytes.data(), bytes.size());
    assert(result.size() == count);
    if (count) assert(result.front() == std::string(reinterpret_cast<const char*>(bytes.data() + key_at), 48));
}
}

int main(int argc, char** argv) {
    expect(fixture(), 1);
    expect(fixture(-1024), 1);
    expect(fixture(128 * 1024 * 1024), 0);
    expect(fixture(-128 * 1024 * 1024), 0);
    expect(fixture(1025), 0);
    auto bytes = fixture();
    std::memcpy(bytes.data() + 256, bytes.data() + key_at, 48); expect(bytes, 1);
    bytes = fixture(); std::memcpy(bytes.data() + 2560, bytes.data() + metadata_at, 36);
    word(bytes, 2560, 2560); expect(bytes, 1);
    bytes = fixture(); bytes[56] = 0; expect(bytes, 0);
    bytes = fixture(); word(bytes, metadata_at, metadata_at + 4); expect(bytes, 0);
    bytes = fixture(); word(bytes, metadata_at + 4, 4096); expect(bytes, 0);
    bytes = fixture(); word(bytes, metadata_at + 4, 3073); expect(bytes, 0);
    bytes = fixture(); bytes[metadata_at + 14] = '!'; expect(bytes, 0);
    bytes = fixture(); bytes[metadata_at + 14] = 'b'; expect(bytes, 0);
    bytes = fixture(); bytes[metadata_at + 35] = '!'; expect(bytes, 0);
    bytes = fixture(); word(bytes, call_at, 0xd63f0120); expect(bytes, 0);
    bytes = fixture(); bytes[key_at + 1] = bytes[key_at]; expect(bytes, 0);
    bytes = fixture(); bytes[key_at + 47] = '!'; expect(bytes, 0);
    bytes = fixture(); bytes.resize(metadata_at + 35); expect(bytes, 0);
    bytes = fixture(); bytes.resize(63); expect(bytes, 0);
    bytes = fixture(); std::fill(bytes.begin() + 64, bytes.end(), 'a'); expect(bytes, 0);
    assert(maplesu::image_credentials(nullptr, 4096).empty());
    assert(maplesu::image_credentials(bytes.data(), size_t(256) * 1024 * 1024 + 1).empty());
    std::cout << "PASS 22 structural extraction cases\n";
    assert(argc % 2 == 1);
    for (int i = 1; i < argc; i += 2) {
        const size_t expected = size_t(std::stoi(argv[i]));
        std::ifstream input(argv[i + 1], std::ios::binary);
        assert(input.good());
        const Bytes raw{std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
        const auto candidates = maplesu::image_credentials(raw.data(), raw.size());
        assert(candidates.size() == expected);
        std::cout << "PASS real patched kernel " << i / 2 + 1 << ": candidates=" << candidates.size()
            << "; no root claimed\n";
    }
}
