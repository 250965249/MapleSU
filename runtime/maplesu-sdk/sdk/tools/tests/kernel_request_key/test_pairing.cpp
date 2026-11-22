// Actual SDK client paired with captured production A64 emitter by the Python runner.
#include "module_base_kernel_request.h"
#include "maplesu_request_private.h"

#include <array>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unordered_set>
#include <vector>

extern "C" void __set_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(const char*);

namespace {
struct Case {
    const char* name;
    bool probe;
    uint32_t command;
    uint64_t value;
    bool channel_error = false;
    int32_t status = 0;
    bool unsupported = false;
};
const Case* active;
int prepares, uid_reads, gid_reads, transports, failures;
std::unordered_set<uint64_t> ids;
std::string hex(const void* pointer, size_t count) {
    const auto* bytes = static_cast<const unsigned char*>(pointer);
    std::string out(count * 2, '0');
    constexpr char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < count; ++i) {
        out[2 * i] = digits[bytes[i] >> 4]; out[2 * i + 1] = digits[bytes[i] & 15];
    }
    return out;
}
std::vector<unsigned char> unhex(const std::string& text) {
    if (text.size() % 2) std::abort();
    std::vector<unsigned char> out(text.size() / 2);
    for (size_t i = 0; i < out.size(); ++i) {
        char pair[] = {text[2 * i], text[2 * i + 1], 0};
        char* end = nullptr;
        out[i] = static_cast<unsigned char>(std::strtoul(pair, &end, 16));
        if (*end) std::abort();
    }
    return out;
}
bool input(std::string& line) {
    char buffer[4096];
    if (!std::fgets(buffer, sizeof(buffer), stdin)) return false;
    line = buffer;
    while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) line.pop_back();
    return true;
}
void check(bool value) { if (!value) ++failures; }
}

namespace kernel_module { uint32_t get_page_size() { return 4096; } }
extern "C" int64_t maplesu_prepare_kernel_request() noexcept { ++prepares; return 0; }
extern "C" int __wrap_getresuid(uid_t* real, uid_t* effective, uid_t* saved) {
    ++uid_reads; *real = *effective = 10000; *saved = 1234; return 0;
}
extern "C" int __wrap_getresgid(gid_t* real, gid_t* effective, gid_t* saved) {
    ++gid_reads; *real = *effective = 10000; *saved = 5678; return 0;
}
extern "C" long __wrap_syscall(long number, ...) {
    ++transports;
    va_list args;
    va_start(args, number);
    const auto* packet = va_arg(args, const unsigned char*);
    va_end(args);
    std::array<unsigned char, 18> frame{};
    for (size_t i = 0; i < frame.size(); ++i) frame[i] = packet[48 + i] + packet[66 + i];
    uint64_t pointer = 0, saved = 0;
    std::memcpy(&pointer, frame.data() + 10, 8);
    std::memcpy(&saved, frame.data() + 2, 8);
    const auto* request = reinterpret_cast<const maplesu_request_v2*>(static_cast<uintptr_t>(pointer));
    auto* response = reinterpret_cast<maplesu_response_v2*>(static_cast<uintptr_t>(request->response_user));
    check(number == 221 && packet[84] == 0 && std::strlen(reinterpret_cast<const char*>(packet)) == 84);
    check(frame[0] == 52 && frame[1] == 0xa2);
    check(saved == (active->probe ? (uint64_t(5678) << 32 | 1234) : 0));
    check(pointer > UINT32_MAX && request->response_user > UINT32_MAX);
    check(ids.insert(request->request_id).second && request->request_id != 0);
    std::printf("{\"type\":\"transport\",\"case\":\"%s\",\"packet\":\"%s\","
                "\"frame\":\"%s\",\"requestPointer\":%llu,\"responsePointer\":%llu,"
                "\"request\":\"%s\",\"response\":\"%s\"}\n", active->name,
                hex(packet, 85).c_str(), hex(frame.data(), frame.size()).c_str(),
                static_cast<unsigned long long>(pointer),
                static_cast<unsigned long long>(request->response_user),
                hex(request, sizeof(*request)).c_str(), hex(response, sizeof(*response)).c_str());
    std::fflush(stdout);
    std::string answer;
    if (!input(answer)) std::abort();
    const auto bytes = unhex(answer);
    if (bytes.size() != sizeof(*response)) std::abort();
    std::memcpy(response, bytes.data(), bytes.size());
    return -1; // Deliberately unrelated to the actual response status/result.
}

int main() {
    std::string key_hex;
    if (!input(key_hex)) return 2;
    const auto bytes = unhex(key_hex);
    check(bytes.size() == 48);
    const std::string key(bytes.begin(), bytes.end());
    __set_current_module_root_key_hd04aBTnbSZlTRP7S4mQpIeVvr2ssGjW(key.c_str());
    std::vector<Case> cases = {
        {"query", true, 1, 0}, {"echo_zero", false, 2, 0},
        {"echo_all_bits", false, 2, UINT64_MAX}, {"echo_high_bit", false, 2, uint64_t(1) << 63},
        {"echo_old_sentinel", false, 2, uint64_t(-19999)},
        {"echo_mixed", false, 2, 0x1234567887654321ull},
        {"unknown_command", false, 99, UINT64_MAX, false, -95},
        {"bad_reserved", false, 2, 1, false, -22},
        {"bad_version", false, 2, 1, false, -22},
        {"bad_magic", false, 2, 1, false, -22},
        {"bad_length", false, 2, 1, false, -22},
        {"from_error", false, 2, 1, true}, {"to_error", false, 2, 1, true},
        {"partial_to", false, 2, 1, true}, {"completion_error", false, 2, 1, true},
        {"response_id", false, 2, 1, true}, {"response_command", false, 2, 1, true},
        {"query_bad_metadata", true, 1, 0, true}, {"bad_key", false, 2, 1, true},
        {"request_snapshot", false, 2, 0xfedcba9876543210ull},
        {"query_from_error", true, 1, 0, false, 0, true},
    };
    for (const auto& item : cases) {
        active = &item; prepares = uid_reads = gid_reads = transports = 0;
        const int before = failures;
        maplesu_response_v2 response{};
        bool supported = false;
        const auto error = item.probe ? kernel_module::maplesu_request_v2_probe(response, supported) :
            kernel_module::maplesu_request_v2_exchange(item.command, item.value, 0, response);
        check(error == (item.channel_error ? KModErr::ERR_MODULE_TEST_CHANNEL : KModErr::OK));
        check(transports == 1 && prepares == int(item.probe) && uid_reads == int(item.probe) && gid_reads == int(item.probe));
        check(supported == (item.probe && !item.channel_error && !item.unsupported));
        if (!item.channel_error && !item.unsupported) {
            check(response.status == item.status && response.command == item.command);
            const uint64_t expected = item.status ? 0 : (item.command == 1 ? 3 : item.value);
            check(response.result == expected);
        } else {
            const maplesu_response_v2 empty{};
            check(!std::memcmp(&response, &empty, sizeof(empty)));
        }
        std::printf("{\"type\":\"result\",\"case\":\"%s\",\"error\":%lld,"
                    "\"supported\":%s,\"response\":\"%s\",\"prepareCalls\":%d,"
                    "\"uidReads\":%d,\"gidReads\":%d,\"transports\":%d,\"passed\":%s}\n",
                    item.name, static_cast<long long>(error), supported ? "true" : "false",
                    hex(&response, sizeof(response)).c_str(), prepares, uid_reads, gid_reads, transports,
                    before == failures ? "true" : "false");
        std::fflush(stdout);
    }
    std::printf("{\"type\":\"summary\",\"cases\":%zu,\"uniqueRequestIds\":%zu,\"failures\":%d}\n",
                cases.size(), ids.size(), failures);
    return failures ? 1 : 0;
}
