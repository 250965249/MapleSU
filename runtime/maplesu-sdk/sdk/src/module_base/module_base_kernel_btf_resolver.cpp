// module base kernel btf resolver implementation.
//
#include "kernel_module_kit_umbrella.h"
#include <algorithm>
#include <array>
#include <set>
#include <tuple>
#include <cerrno>
#include <cstddef>
#include <functional>
#include <limits>
#include <linux/btf.h>
#include <mutex>

#include "maplesu_kernel_layout_private.h"
#include "maplesu_request_identity.h"
#include "kernel_layout.h"

static_assert(sizeof(btf_type) == 12 && alignof(btf_type) == 4);
static_assert(sizeof(btf_member) == 12 && offsetof(btf_member, offset) == 8);

static KModErr get_kernel_shellcode_u64_result(
    std::function<KModErr(asmjit::a64::Assembler*, asmjit::a64::GpX&)> emit,
    uint64_t& result) {
    auto ctx = init_aarch64_asm();
    auto* a = ctx.assembler();
    kernel_module::arm64_module_asm_func_start(a);
    auto return_reg = asmjit::a64::x0;
    RETURN_IF_ERROR(emit(a, return_reg));
    kernel_module::arm64_module_asm_func_end(a, return_reg);
    return kernel_module::execute_kernel_asm_func(aarch64_asm_to_bytes(a), result);
}

namespace kernel_module {

// Alternative symbols are probes, not final missing-symbol diagnostics.
__attribute__((visibility("hidden"))) KModErr maplesu_lookup_optional_symbol(const char*, uint64_t&);

static uint64_t g_vmlinux_btf_ptr = 0;
static uint64_t g_btf_strs_data = 0;
static uint32_t g_btf_strs_length = 0;
static std::map<uint32_t, std::string> g_btf_name_cache;
static std::mutex g_live_btf_mutex;

static bool btf_kernel_pointer(uint64_t value) {
    return value >= 0xfff0000000000000ULL && value < static_cast<uint64_t>(-4095LL);
}

static const char* btf_trim_struct_prefix(const char* name) {
    return strncmp(name, "struct ", 7) == 0 ? name + 7 : name;
}

namespace {

enum class AccessKind {
    unknown, task, pointer, scalar, address, id_overflow, task_scalar,
    target_task, cap_pointer, cap_scalar, output, constant, rcu_scalar
};
enum class AccessResult { credential_scalar, task_scalar, capability_outputs };
struct AccessValue {
    AccessKind kind = AccessKind::unknown;
    int32_t field = -1;
    uint32_t offset = 0, width = 0;
    uint64_t address = 0;
    bool operator==(const AccessValue&) const = default;
    bool operator<(const AccessValue& other) const {
        return std::tie(kind, field, offset, width, address) < std::tie(other.kind, other.field, other.offset, other.width, other.address);
    }
};
using AccessRegisters = std::array<AccessValue, 32>;
using AccessCapFields = std::array<AccessValue, 3>; // effective, inheritable, permitted output arguments.
struct AccessCapState {
    AccessCapFields fields{};
    int32_t nesting = -1;
    uint32_t phase = 0, stack = 0; // RCU not entered / active / exited; current stack frame bytes.
    bool scs = false, special = false;
    bool operator<(const AccessCapState& other) const {
        return std::tie(fields, nesting, phase, stack, scs, special) <
            std::tie(other.fields, other.nesting, other.phase, other.stack, other.scs, other.special);
    }
};
struct AccessRcuCalls {
    uint64_t lock = 0, unlock = 0, special = 0;
};
bool access_caps_complete(const AccessCapState& state) {
    for (size_t i = 0; i < state.fields.size(); ++i) {
        const auto& field = state.fields[i];
        if (field.kind != AccessKind::cap_scalar || field.width != 8 || field.field < 0 ||
            (field.field & 7) || field.field != state.fields[0].field ||
            uint64_t(field.offset) + field.width > INT32_MAX) return false;
        for (size_t j = 0; j < i; ++j)
            if (field.offset < uint64_t(state.fields[j].offset) + 8 &&
                state.fields[j].offset < uint64_t(field.offset) + 8) return false;
    }
    return true;
}
std::mutex accessor_mutex;
std::map<std::string, KernelFieldDescription> accessor_fields;
RequestIdentity accessor_identity;
RequestOwnerBinding accessor_owner;
bool accessor_owner_bound = false;

bool access_hint(uint32_t word) {
    return word == 0xd503201fU || word == 0xd503233fU || word == 0xd50323bfU ||
        word == 0xd503211fU || word == 0xd503219fU ||
        (word & 0xffffff3fU) == 0xd503241fU;
}
uint32_t access_word(const std::vector<uint8_t>& bytes, size_t at) {
    return uint32_t(bytes[at]) | uint32_t(bytes[at + 1]) << 8 |
        uint32_t(bytes[at + 2]) << 16 | uint32_t(bytes[at + 3]) << 24;
}
bool access_target(uint64_t pc, uint32_t immediate, unsigned bits, uint64_t& target) {
    int64_t displacement = immediate;
    if (immediate & (1U << (bits - 1))) displacement -= int64_t(1) << bits;
    displacement *= 4;
    if (displacement < 0) {
        if (uint64_t(-displacement) > pc) return false;
        target = pc - uint64_t(-displacement);
    } else {
        if (uint64_t(displacement) > UINT64_MAX - pc) return false;
        target = pc + uint64_t(displacement);
    }
    return true;
}
KModErr read_accessor_text(uint64_t address, std::vector<uint8_t>& bytes) {
    if (!btf_kernel_pointer(address) || (address & 3)) return KModErr::ERR_MODULE_NOT_KADDR;
    uint64_t size = 0;
    RETURN_IF_ERROR(get_kernel_shellcode_u64_result(
        [address](asmjit::a64::Assembler* a, asmjit::a64::GpX& result) {
            using namespace asmjit::a64;
            StackBufGuard scratch(a, 16, x10);
            a->add(x11, x10, 8);
            KModErr error = KModErr::OK;
            export_symbol::kallsyms_lookup_size_offset(a, error, address, x10, x11);
            RETURN_IF_ERROR(error);
            const auto invalid = a->newLabel(), done = a->newLabel();
            a->cbz(x0, invalid);
            a->ldr(x0, ptr(sp, 8));
            a->cbnz(x0, invalid);
            a->ldr(x0, ptr(sp));
            a->b(done);
            a->bind(invalid);
            aarch64_asm_mov_x(a, x0, 0);
            a->bind(done);
            result = x0;
            return KModErr::OK;
        }, size));
    if (size < 4 || (size & 3) || size > UINT32_MAX || size > UINT64_MAX - address ||
        !btf_kernel_pointer(address + size - 1)) return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    bytes.resize(static_cast<size_t>(std::min<uint64_t>(size, 512)));
    return read_kernel_mem(address, bytes.data(), static_cast<uint32_t>(bytes.size()));
}

// Track values reaching a getter return, known ID converter, or cap_capget output.
// The capability mode distinguishes target/objective credentials from current.
KModErr inspect_accessor(uint64_t start, uint64_t converter, uint64_t overflow, AccessValue& result,
                        AccessResult requested = AccessResult::credential_scalar,
                        AccessCapFields* cap_fields = nullptr, const AccessRcuCalls& rcu_calls = {}) {
    const bool cap_mode = requested == AccessResult::capability_outputs;
    if (cap_mode && !cap_fields) return KModErr::ERR_MODULE_PARAM;
    std::vector<uint8_t> bytes;
    std::set<uint64_t> thunks;
    for (;;) {
        if (thunks.size() == 8 || !thunks.insert(start).second) return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
        RETURN_IF_ERROR(read_accessor_text(start, bytes));
        size_t first = 0;
        while (first + 4 <= bytes.size() && access_hint(access_word(bytes, first))) first += 4;
        if (first + 4 > bytes.size()) return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
        const uint32_t word = access_word(bytes, first);
        if ((word & 0xfc000000U) != 0x14000000U) break;
        uint64_t target = 0;
        if (!access_target(start + first, word & 0x03ffffffU, 26, target)) return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
        if (target >= start && target - start < bytes.size()) break;
        start = target; // A direct entry thunk, never an inferred jump-table slot.
    }
    using AccessPath = std::array<uint64_t, 2>; // read_accessor_text bounds the body to 128 instructions.
    using State = std::tuple<size_t, AccessRegisters, AccessValue, AccessCapState, AccessPath>;
    AccessRegisters inputs{};
    if (cap_mode) {
        inputs[0] = {AccessKind::target_task};
        for (unsigned i = 0; i < 3; ++i) inputs[i + 1] = {AccessKind::output, static_cast<int32_t>(i), 0, 8};
    }
    std::vector<State> pending{{0, inputs, {}, {}, {}}};
    std::set<State> visited;
    AccessCapFields completed{};
    bool returned = false;
    auto consume = [&](const AccessValue& value, const AccessCapState& caps) {
        if (cap_mode) {
            if (value.kind != AccessKind::constant || value.address || (value.width != 4 && value.width != 8) ||
                caps.phase != 2 || caps.stack || caps.scs || !access_caps_complete(caps) ||
                (returned && completed != caps.fields)) return false;
            completed = caps.fields; returned = true; return true;
        }
        if (requested == AccessResult::task_scalar) {
            if (value.kind != AccessKind::task_scalar || value.field != -1 || value.width != 4) return false;
        } else if (value.kind != AccessKind::scalar || value.field < 0 || value.width != 4 ||
                   (value.field & 7) || (value.offset & 3)) return false;
        if (returned && value != result) return false;
        result = value; returned = true; return true;
    };
    while (!pending.empty()) {
        auto state = std::move(pending.back()); pending.pop_back();
        const size_t at = std::get<0>(state);
        if (at + 4 > bytes.size() || (at & 3)) return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
        auto caps = std::get<3>(state);
        auto path = std::get<4>(state);
        if (cap_mode) {
            const size_t slot = at / 4;
            if (slot >= path.size() * 64) return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
            const uint64_t bit = uint64_t(1) << (slot & 63);
            if (path[slot / 64] & bit) return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
            path[slot / 64] |= bit; // A repeated PC on this path is a loop, never a successful merge.
        }
        if (!visited.insert(state).second) continue;
        if (visited.size() > 4096) return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
        auto values = std::get<1>(state);
        const auto compared = std::get<2>(state);
        auto next_compared = compared;
        const uint32_t word = access_word(bytes, at);
        const unsigned rd = word & 31, rn = word >> 5 & 31, rm = word >> 16 & 31;
        auto load = [&](const AccessValue& base, uint64_t offset, uint32_t width, uint32_t opcode) {
            AccessValue loaded;
            if (offset > INT32_MAX) return loaded;
            if (cap_mode) {
                if (opcode != 1 || offset + width > INT32_MAX) return loaded;
                if (base.kind == AccessKind::target_task && width == 8 && caps.phase == 1)
                    loaded = {AccessKind::cap_pointer, static_cast<int32_t>(offset), 0, 8};
                else if (base.kind == AccessKind::cap_pointer && width == 8 && caps.phase == 1)
                    loaded = {AccessKind::cap_scalar, base.field, static_cast<uint32_t>(offset), 8};
                else if (base.kind == AccessKind::task && width == 4)
                    loaded = {AccessKind::rcu_scalar, 0, static_cast<uint32_t>(offset), 4};
                return loaded;
            }
            const bool direct_task = requested == AccessResult::task_scalar && base.kind == AccessKind::task && width == 4;
            if (opcode == 1 || (direct_task && opcode == 2)) {
                if (direct_task)
                    loaded = {AccessKind::task_scalar, -1, static_cast<uint32_t>(offset), 4};
                else if (base.kind == AccessKind::task && width == 8)
                    loaded = {AccessKind::pointer, static_cast<int32_t>(offset), 0, 8};
                else if (base.kind == AccessKind::pointer)
                    loaded = {AccessKind::scalar, base.field, static_cast<uint32_t>(offset), width};
                else if (base.kind == AccessKind::address && width == 4 && overflow &&
                         offset <= UINT64_MAX - base.address && base.address + offset == overflow)
                    loaded = {AccessKind::id_overflow, -1, 0, 4};
            }
            return loaded;
        };
        size_t next = at + 4;
        if (word == 0xd65f03c0U) {
            if (!consume(values[0], caps)) return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
            continue;
        } else if (access_hint(word)) {
        } else if ((word & 0xffffffe0U) == 0xd5384100U) {
            values[rd] = {AccessKind::task, -1, 0, 0};
        } else if ((word & 0x7fe0ffe0U) == 0x2a0003e0U) {
            if (cap_mode && rm == 31)
                values[rd] = {AccessKind::constant, -1, 0, (word & 0x80000000U) ? 8U : 4U, 0};
            else if (cap_mode)
                values[rd] = (word & 0x80000000U) || (values[rm].width == 4 &&
                    (values[rm].kind == AccessKind::rcu_scalar || values[rm].kind == AccessKind::constant)) ? values[rm] : AccessValue{};
            else values[rd] = (word & 0x80000000U) || values[rm].kind == AccessKind::scalar ||
                (requested == AccessResult::task_scalar && values[rm].kind == AccessKind::task_scalar) ? values[rm] : AccessValue{};
        } else if ((word & 0x7fe00c00U) == 0x1a800000U) {
            const auto left = values[rn], right = values[rm];
            const unsigned condition = word >> 12 & 15;
            values[rd] = {};
            if (left == right && (!cap_mode || (word & 0x80000000U) ||
                (left.width == 4 && (left.kind == AccessKind::constant || left.kind == AccessKind::rcu_scalar)))) values[rd] = left;
            else if (!(word & 0x80000000U)) {
                // from_k[ug]id_munged's inline -1/overflow projection only.
                if (condition == 1 && left.kind == AccessKind::scalar && left == compared && right.kind == AccessKind::id_overflow)
                    values[rd] = left;
                else if (condition == 0 && right.kind == AccessKind::scalar && right == compared && left.kind == AccessKind::id_overflow)
                    values[rd] = right;
            }
        } else if ((word & 0xfffffc1fU) == 0x3100041fU) {
            if (cap_mode) return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
            next_compared = values[rn]; // CMN Wfield,#1, retained across instructions that preserve NZCV.
        } else if ((word & 0x9f000000U) == 0x90000000U || (word & 0x9f000000U) == 0x10000000U) {
            int64_t immediate = (word >> 5 & 0x7ffff) << 2 | (word >> 29 & 3);
            if (immediate & (1 << 20)) immediate -= int64_t(1) << 21;
            const bool page = (word & 0x9f000000U) == 0x90000000U;
            const uint64_t base = page ? (start + at) & ~uint64_t(4095) : start + at;
            if (page) immediate *= 4096;
            const uint64_t magnitude = immediate < 0 ? uint64_t(-immediate) : uint64_t(immediate);
            values[rd] = {};
            if ((immediate < 0 && magnitude <= base) || (immediate >= 0 && magnitude <= UINT64_MAX - base))
                values[rd] = {AccessKind::address, -1, 0, 0, immediate < 0 ? base - magnitude : base + magnitude};
        } else if ((word & 0xff000000U) == 0x91000000U) {
            const uint32_t immediate = (word >> 10 & 0xfff) << ((word & (1U << 22)) ? 12 : 0);
            auto base = values[rn];
            if ((base.kind == AccessKind::task || base.kind == AccessKind::pointer ||
                 (cap_mode && (base.kind == AccessKind::target_task || base.kind == AccessKind::cap_pointer || base.kind == AccessKind::output))) &&
                uint64_t(base.offset) + immediate <= INT32_MAX) {
                base.offset += immediate; values[rd] = base;
            } else if (base.kind == AccessKind::address && immediate <= UINT64_MAX - base.address) {
                base.address += immediate; values[rd] = base;
            } else values[rd] = {};
        } else if (cap_mode && !(word & 0x80000000U) && (word & 0x1f000000U) == 0x11000000U) {
            const uint32_t immediate = (word >> 10 & 0xfff) << ((word & (1U << 22)) ? 12 : 0);
            const bool subtract = word & (1U << 30), flags = word & (1U << 29);
            auto source = values[rn];
            if (rd == 31 || immediate != 1 || subtract != flags ||
                source.kind != AccessKind::rcu_scalar || source.width != 4 || source.field != 0)
                return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
            source.field = subtract ? -1 : 1; values[rd] = source; next_compared = {};
        } else if (cap_mode && ((word & 0x3ffffc00U) == 0x08dffc00U || (word & 0x3ffffc00U) == 0x38bfc000U)) {
            const auto base = values[rn];
            values[rd] = load(base, base.offset, 1U << (word >> 30), 1);
        } else if ((word & 0x3b000000U) == 0x39000000U && !(word & (1U << 26))) {
            const uint32_t width = 1U << (word >> 30), opcode = word >> 22 & 3;
            const auto base = values[rn];
            const uint32_t immediate = (word >> 10 & 0xfff) * width;
            const uint64_t offset = uint64_t(base.offset) + immediate;
            if (opcode) {
                values[rd] = load(base, offset, width, opcode);
            } else if (cap_mode) {
                const auto source = values[rd];
                if (base.kind == AccessKind::output) {
                    if (offset || width != 8 || base.field < 0 || base.field >= 3 || caps.phase != 1 ||
                        source.kind != AccessKind::cap_scalar || source.width != 8 ||
                        caps.fields[base.field].kind != AccessKind::unknown) return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
                    caps.fields[base.field] = source;
                } else if (base.kind == AccessKind::task && width == 4 && offset <= INT32_MAX &&
                           source.kind == AccessKind::rcu_scalar && source.width == 4 && source.offset == offset) {
                    if (caps.phase == 0 && source.field == 1) {
                        caps.nesting = static_cast<int32_t>(offset); caps.phase = 1;
                    } else if (caps.phase == 1 && source.field == -1 && caps.nesting == static_cast<int32_t>(offset) &&
                               access_caps_complete(caps)) {
                        caps.phase = 2;
                    } else return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
                } else if (rn != 31 || uint64_t(immediate) + width > caps.stack) {
                    return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
                }
            }
        } else if ((word & 0x7c000000U) == 0x14000000U) {
            uint64_t target = 0;
            if (!access_target(start + at, word & 0x03ffffffU, 26, target)) return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
            const bool call = word & 0x80000000U;
            if (!call && target >= start && target - start < bytes.size()) {
                if (!cap_mode && target <= start + at) return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
                next = static_cast<size_t>(target - start);
            } else {
                if (cap_mode) {
                    if (!call) return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
                    // Only these exact RCU APIs have summaries; unknown calls never preserve evidence.
                    if (rcu_calls.lock && target == rcu_calls.lock) {
                        if (caps.phase || caps.nesting >= 0) return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
                        caps.phase = 1;
                    } else if (rcu_calls.unlock && target == rcu_calls.unlock) {
                        if (caps.phase != 1 || caps.nesting >= 0 || !access_caps_complete(caps))
                            return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
                        caps.phase = 2;
                    } else if (rcu_calls.special && target == rcu_calls.special) {
                        if (caps.phase != 2 || caps.nesting < 0 || caps.special || !access_caps_complete(caps) ||
                            values[0].kind != AccessKind::task || values[0].offset)
                            return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
                        caps.special = true;
                    } else return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
                }
                const auto output = (!cap_mode && converter && target == converter) ? values[1] : AccessValue{};
                if (!call) {
                    if (!consume(output, caps)) return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
                    continue;
                }
                for (unsigned i = 0; i <= 18; ++i) values[i] = {};
                values[30] = {}; values[0] = output;
                next_compared = {}; // Explicit call summaries never preserve NZCV or volatile provenance.
            }
        } else if ((word & 0xff000010U) == 0x54000000U || (word & 0x7e000000U) == 0x34000000U ||
                   (word & 0x7e000000U) == 0x36000000U) {
            const unsigned bits = (word & 0x7e000000U) == 0x36000000U ? 14 : 19;
            uint64_t target = 0;
            if (!access_target(start + at, word >> 5 & ((1U << bits) - 1), bits, target) ||
                (!cap_mode && target <= start + at) || target < start || target - start >= bytes.size())
                return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
            pending.push_back({static_cast<size_t>(target - start), values, compared, caps, path});
        } else if ((word & 0x3a000000U) == 0x28000000U) {
            if (cap_mode) {
                const bool loading = word & (1U << 22);
                const unsigned mode = word >> 23 & 3;
                int64_t displacement = word >> 15 & 127;
                if (displacement & 64) displacement -= 128;
                displacement *= 8;
                if (rn != 31 || word & (1U << 26) || (word >> 30) != 2 || !mode ||
                    (mode == 3 && (loading || displacement >= 0)) ||
                    (mode == 1 && (!loading || displacement <= 0))) return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
                int64_t depth = caps.stack, address = displacement;
                if (mode == 3) { depth -= displacement; address = 0; }
                else if (mode == 1) address = 0;
                if (depth < 0 || depth > INT32_MAX || address < 0 || address + 16 > depth)
                    return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
                if (mode == 1) depth -= displacement;
                if (depth < 0 || depth > INT32_MAX) return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
                caps.stack = static_cast<uint32_t>(depth);
            }
            if (word & (1U << 22)) { values[rd] = {}; values[word >> 10 & 31] = {}; }
            if ((word >> 23 & 3) == 1 || (word >> 23 & 3) == 3) values[rn] = {};
        } else if ((word & 0x3b000000U) == 0x38000000U && !(word & (1U << 26))) {
            if (cap_mode) {
                if (word == 0xf800865eU && !caps.scs && !caps.phase && !caps.stack) caps.scs = true;
                else if (word == 0xf85f8e5eU && caps.scs && caps.phase == 2 && !caps.stack) caps.scs = false;
                else return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
            }
            if (word & (3U << 10)) values[rn] = {};
            if (word & (3U << 22)) values[rd] = {};
        } else if ((word & 0x1c000000U) == 0x10000000U || (word & 0x0e000000U) == 0x0a000000U) {
            if (cap_mode) return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
            values[rd] = {}; // Untracked arithmetic/ADRP overwrites its destination.
            next_compared = {}; // These broad families include NZCV writers.
        } else return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
        values[31] = {};
        pending.push_back({next, std::move(values), next_compared, caps, path});
    }
    if (!returned) return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    if (cap_mode) *cap_fields = completed;
    return KModErr::OK;
}

KModErr resolve_accessor_field_impl(const char* owner, const char* member, uint32_t width, KernelFieldDescription& output) {
    if (!owner || !member) return KModErr::ERR_MODULE_PARAM;
    const std::string key = std::string(owner) + "." + member;
    const bool seccomp = key == "task_struct.seccomp.mode" && width == 4;
    const bool caps = width == 8 && (key == "task_struct.real_cred" || key == "cred.cap_effective" ||
        key == "cred.cap_inheritable" || key == "cred.cap_permitted");
    if (!caps && !seccomp && (key != "task_struct.cred" || width != 8) &&
        ((key != "cred.uid" && key != "cred.euid") || width != 4)) return KModErr::ERR_MODULE_PARAM;
    RequestIdentity identity;
    if (!identity.capture()) return KModErr::ERR_MODULE_ROOT_KEY;
    const bool owner_bound = maplesu_request_auth_authenticated(identity.auth_state);
    RequestOwnerBinding binding{};
    if (owner_bound) {
        maplesu_metadata_owner_v3 metadata{};
        uint64_t descriptor = 0;
        RETURN_IF_ERROR(maplesu_request_owner_channel(metadata, descriptor, binding));
    }
    const auto current = [&] {
        return identity.matches() && (!owner_bound || maplesu_request_owner_binding_matches(binding));
    };
    std::lock_guard<std::mutex> guard(accessor_mutex);
    if (!current()) return KModErr::ERR_MODULE_ROOT_KEY;
    // A process cannot retain these caches across boot. Owner hosts/epochs and
    // full UID are explicit; Legacy reuse is bound to this process/Key/auth tag.
    if (!accessor_identity.matches() || accessor_owner_bound != owner_bound ||
        (owner_bound && (accessor_owner.auth_state != binding.auth_state ||
            accessor_owner.process != binding.process || accessor_owner.full_uid != binding.full_uid ||
            accessor_owner.actual_uid != binding.actual_uid || accessor_owner.epoch != binding.epoch ||
            accessor_owner.host.low != binding.host.low || accessor_owner.host.high != binding.host.high)))
        accessor_fields.clear();
    const auto publish = [&](const std::map<std::string, KernelFieldDescription>& resolved) {
        auto merged = accessor_fields;
        for (const auto& value : resolved) merged.insert_or_assign(value.first, value.second);
        if (!current()) { accessor_fields.clear(); return KModErr::ERR_MODULE_ROOT_KEY; }
        accessor_fields.swap(merged);
        accessor_identity = identity; accessor_owner = binding; accessor_owner_bound = owner_bound;
        output = accessor_fields.at(key);
        return KModErr::OK;
    };
    auto cached = accessor_fields.find(key);
    if (cached != accessor_fields.end()) { output = cached->second; return KModErr::OK; }
    auto field = [](uint32_t offset, uint32_t bytes) {
        KernelFieldDescription result;
        result.offset_bytes = offset; result.width_bytes = bytes;
        result.source = "accessor"; result.reader = "target-text";
        return result; // Owner size remains unknown; no adjacent field is inferred.
    };
    if (caps) {
        uint64_t address = 0;
        RETURN_IF_ERROR(kallsyms_lookup_name("cap_capget", address));
        AccessRcuCalls calls;
        for (const auto& symbol : {std::make_pair("__rcu_read_lock", &calls.lock),
                                  std::make_pair("__rcu_read_unlock", &calls.unlock),
                                  std::make_pair("rcu_read_unlock_special", &calls.special)}) {
            auto error = maplesu_lookup_optional_symbol(symbol.first, *symbol.second);
            if (error == KModErr::ERR_MODULE_SYMBOL_NOT_EXIST) { *symbol.second = 0; continue; }
            RETURN_IF_ERROR(error);
            if (!btf_kernel_pointer(*symbol.second) || (*symbol.second & 3)) return KModErr::ERR_MODULE_NOT_KADDR;
        }
        if ((calls.lock && calls.lock == calls.unlock) || (calls.special &&
            (calls.special == calls.lock || calls.special == calls.unlock))) return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
        AccessValue unused;
        AccessCapFields values;
        RETURN_IF_ERROR(inspect_accessor(address, 0, 0, unused, AccessResult::capability_outputs, &values, calls));
        std::map<std::string, KernelFieldDescription> resolved;
        auto describe = [&](uint32_t offset) {
            auto result = field(offset, 8);
            result.parser_version = 2;
            return result;
        };
        resolved.emplace("task_struct.real_cred", describe(static_cast<uint32_t>(values[0].field)));
        for (unsigned i = 0; const char* member : {"cap_effective", "cap_inheritable", "cap_permitted"})
            resolved.emplace(std::string("cred.") + member, describe(values[i++].offset));
        return publish(resolved);
    }
    if (seccomp) {
        AccessValue value;
        bool have = false;
        for (const char* name : {"prctl_get_seccomp", "seccomp_mode"}) {
            uint64_t address = 0;
            auto error = maplesu_lookup_optional_symbol(name, address);
            if (error == KModErr::ERR_MODULE_SYMBOL_NOT_EXIST) continue;
            RETURN_IF_ERROR(error);
            AccessValue candidate;
            RETURN_IF_ERROR(inspect_accessor(address, 0, 0, candidate, AccessResult::task_scalar));
            if (have && candidate != value) return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
            value = candidate; have = true;
        }
        if (!have) return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
        return publish({{key, field(value.offset, 4)}});
    }
    int32_t task_cred = -1;
    std::map<std::string, AccessValue> found;
    std::array<std::pair<uint64_t, uint64_t>, 2> id_symbols{};
    std::array<bool, 2> id_symbols_ready{};
    for (const char* id : {"uid", "euid", "gid", "egid"}) {
        const bool uid = !strcmp(id, "uid") || !strcmp(id, "euid");
        const size_t family = uid ? 0 : 1;
        auto& [converter, overflow] = id_symbols[family];
        // Missing converters are common on inlined vendor getters. Resolve each
        // family once in this operation; never persist a negative across auth.
        if (!id_symbols_ready[family]) {
            for (const auto& symbol : {std::make_pair(uid ? "from_kuid_munged" : "from_kgid_munged", &converter),
                                       std::make_pair(uid ? "overflowuid" : "overflowgid", &overflow)}) {
                auto error = maplesu_lookup_optional_symbol(symbol.first, *symbol.second);
                if (is_ok(error)) {
                    if (!btf_kernel_pointer(*symbol.second) || (*symbol.second & 3)) return KModErr::ERR_MODULE_NOT_KADDR;
                } else if (error != KModErr::ERR_MODULE_SYMBOL_NOT_EXIST) return error;
            }
            id_symbols_ready[family] = true;
        }
        bool have = false;
        AccessValue value;
        for (const char* prefix : {"__arm64_sys_get", "sys_get"}) {
            const std::string name = std::string(prefix) + id;
            uint64_t address = 0;
            auto error = maplesu_lookup_optional_symbol(name.c_str(), address);
            if (error == KModErr::ERR_MODULE_SYMBOL_NOT_EXIST) continue;
            RETURN_IF_ERROR(error);
            AccessValue candidate;
            RETURN_IF_ERROR(inspect_accessor(address, converter, overflow, candidate));
            if (have && candidate != value) return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
            value = candidate; have = true;
        }
        if (!have) continue;
        if (task_cred >= 0 && task_cred != value.field) return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
        task_cred = value.field;
        found.emplace(id, value);
    }
    if (task_cred < 0 || (key != "task_struct.cred" && !found.count(member))) return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    std::map<std::string, KernelFieldDescription> resolved;
    resolved.emplace("task_struct.cred", field(static_cast<uint32_t>(task_cred), 8));
    for (const char* id : {"uid", "euid"}) if (found.count(id))
        resolved.emplace(std::string("cred.") + id, field(found.at(id).offset, 4));
    return publish(resolved);
}

KModErr resolve_accessor_field(const char* owner, const char* member, uint32_t width, KernelFieldDescription& output) {
    const auto error = resolve_accessor_field_impl(owner, member, width, output);
    if (error == KModErr::ERR_MODULE_SYMBOL_NOT_EXIST || error == KModErr::ERR_MODULE_OFFSET_NOT_FOUND)
        printf("MapleSU layout: %s.%s: accessor resolution failed (%lld)\n",
            owner ? owner : "", member ? member : "", static_cast<long long>(error));
    return error;
}

std::mutex blob_mutex;
std::vector<uint8_t> running_blob;
const char* running_reader = nullptr;
std::map<std::string, KernelFieldDescription> running_fields;
constexpr size_t kMaxBtfBytes = 64 * 1024 * 1024;

KModErr read_running_blob(std::vector<uint8_t>& bytes, bool& available, const char*& reader,
                         bool kernel_fallback = true) {
    available = true;
    FILE* input = fopen("/sys/kernel/btf/vmlinux", "rb");
    if (input) {
        uint8_t block[64 * 1024];
        KModErr result = KModErr::OK;
        while (true) {
            size_t count = fread(block, 1, sizeof(block), input);
            if (count > kMaxBtfBytes - bytes.size()) {
                result = KModErr::ERR_MODULE_READ_FILE;
                break;
            }
            bytes.insert(bytes.end(), block, block + count);
            if (count < sizeof(block)) {
                if (ferror(input)) result = KModErr::ERR_MODULE_READ_FILE;
                break;
            }
        }
        fclose(input);
        reader = "sysfs";
        return result;
    }
    if (errno != ENOENT && errno != ENOTDIR && errno != EACCES && errno != EPERM)
        return KModErr::ERR_MODULE_OPEN_FILE;
    if (!kernel_fallback) {
        available = false; // The sysfs source is unavailable; kernel BTF was not inspected.
        return KModErr::ERR_MODULE_SYMBOL_NOT_EXIST;
    }

    uint64_t start = 0, end = 0;
    auto start_error = kallsyms_lookup_name("__start_BTF", start);
    auto end_error = kallsyms_lookup_name("__stop_BTF", end);
    if (start_error == KModErr::ERR_MODULE_SYMBOL_NOT_EXIST && end_error == KModErr::ERR_MODULE_SYMBOL_NOT_EXIST) {
        available = false;
        return KModErr::ERR_MODULE_SYMBOL_NOT_EXIST;
    }
    RETURN_IF_ERROR(start_error);
    RETURN_IF_ERROR(end_error);
    if (!btf_kernel_pointer(start) || !btf_kernel_pointer(end) || end <= start || end - start > kMaxBtfBytes)
        return KModErr::ERR_MODULE_NOT_KADDR;
    bytes.resize(static_cast<size_t>(end - start));
    for (size_t at = 0; at < bytes.size();) {
        const uint32_t count = static_cast<uint32_t>(std::min<size_t>(64 * 1024, bytes.size() - at));
        RETURN_IF_ERROR(read_kernel_mem(start + at, bytes.data() + at, count));
        at += count;
    }
    reader = "kernel-symbols";
    return KModErr::OK;
}

KModErr resolve_blob_field(const char* owner, const char* member, uint32_t expected_width,
                          KernelFieldDescription& output, bool& available) {
    available = true;
    if (!owner || !*owner || (member && !*member)) return KModErr::ERR_MODULE_PARAM;
    owner = btf_trim_struct_prefix(owner);
    if (!*owner) return KModErr::ERR_MODULE_PARAM;
    const std::string key = std::string(owner) + "." + (member ? member : "");
    std::lock_guard<std::mutex> guard(blob_mutex);
    auto found = running_fields.find(key);
    if (found != running_fields.end()) {
        if (expected_width && found->second.width_bytes != expected_width) {
            printf("MapleSU layout: %s.%s: width mismatch\n", owner, member ? member : "sizeof");
            return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
        }
        output = found->second;
        return KModErr::OK;
    }
    std::vector<uint8_t> candidate;
    const char* reader = running_reader;
    if (running_blob.empty()) RETURN_IF_ERROR(read_running_blob(candidate, available, reader));
    const auto& blob = running_blob.empty() ? candidate : running_blob;
    try {
        using namespace maplesu::module_policy;
        const std::vector<std::string> fields = member ? std::vector<std::string>{member} : std::vector<std::string>{};
        KernelLayoutDescription layout;
        if (!strcmp(owner, "cred") || !strcmp(owner, "task_struct"))
            layout = describe_task_credential_layout(blob, !strcmp(owner, "task_struct") ? fields : std::vector<std::string>{},
                !strcmp(owner, "cred") ? fields : std::vector<std::string>{});
        else layout = describe_kernel_layout(blob, {{owner, fields}});
        auto type = std::find_if(layout.types.begin(), layout.types.end(),
            [owner](const LayoutType& value) { return value.name == owner; });
        if (type == layout.types.end()) return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
        KernelFieldDescription field;
        field.owner_size_bytes = type->size;
        field.reader = reader;
        if (member) {
            const auto& value = type->fields.at(0);
            if ((value.bit_offset & 7) || !value.bit_size || (value.bit_size & 7) ||
                uint64_t(value.bit_offset) + value.bit_size > uint64_t(type->size) * 8 ||
                value.bit_offset / 8 > static_cast<uint32_t>(std::numeric_limits<int32_t>::max()) ||
                (expected_width && value.bit_size / 8 != expected_width)) {
                printf("MapleSU layout: %s.%s: width or owner bounds mismatch\n", owner, member);
                return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
            }
            field.offset_bytes = value.bit_offset / 8;
            field.width_bytes = value.bit_size / 8;
        }
        if (running_blob.empty()) {
            running_blob = std::move(candidate);
            running_reader = reader;
        }
        running_fields.emplace(key, field);
        output = field;
        return KModErr::OK;
    } catch (const std::exception& error) {
        printf("MapleSU layout: %s.%s: %s\n", owner, member ? member : "sizeof", error.what());
        return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    }
}

// The legacy kprobe reader also has to work on the fixed no-BTF family.  Do
// not infer offsets from a kernel version or adjacent fields: recover the two
// offsets only when arch_prepare_kprobe visibly performs
//   p->opcode = *(u32 *)p->addr
// in the target text.  This is deliberately narrower than the credential
// accessor decoder and returns no result for an unrecognised producer.
KModErr resolve_kprobe_fields_from_target(KernelFieldDescription& addr,
                                          KernelFieldDescription& opcode) {
    uint64_t prepare = 0;
    RETURN_IF_ERROR(kallsyms_lookup_name("arch_prepare_kprobe", prepare));
    std::vector<uint8_t> text;
    RETURN_IF_ERROR(read_accessor_text(prepare, text));
    if (text.size() < 4 || (text.size() & 3)) return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;

    enum class Kind { unknown, object, address, opcode };
    struct Value { Kind kind = Kind::unknown; uint32_t offset = 0; };
    std::array<Value, 32> values{};
    values[0].kind = Kind::object; // AArch64 ABI: x0 is struct kprobe *.
    uint32_t address_offset = 0, opcode_offset = 0;
    bool found = false;
    std::set<size_t> visited;
    for (size_t at = 0; at < text.size(); at += 4) {
        if (!visited.insert(at).second) return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
        const uint32_t word = access_word(text, at);
        const unsigned rd = word & 31, rn = word >> 5 & 31, rm = word >> 16 & 31;
        if (access_hint(word)) {
        } else if ((word & 0x7fe0ffe0u) == 0x2a0003e0u) {
            const Value source = values[rm];
            values[rd] = (word & 0x80000000u) || source.kind == Kind::opcode ? source : Value{};
        } else if ((word & 0xff000000u) == 0x91000000u) {
            const uint32_t immediate = (word >> 10 & 0xfff) << ((word & (1u << 22)) ? 12 : 0);
            const Value source = values[rn];
            values[rd] = {};
            if (source.kind == Kind::object && immediate <= 0x400u - source.offset)
                values[rd] = {Kind::object, source.offset + immediate};
        } else if ((word & 0x3b000000u) == 0x39000000u && !(word & (1u << 26))) {
            const uint32_t width = 1u << (word >> 30), operation = word >> 22 & 3;
            const uint32_t immediate = (word >> 10 & 0xfff) * width;
            const Value base = values[rn], source = values[rd];
            if (operation) {
                values[rd] = {};
                if (operation == 1 && base.kind == Kind::object && width == 8 &&
                    immediate <= 0x400u - base.offset)
                    values[rd] = {Kind::address, base.offset + immediate};
                else if (operation == 1 && base.kind == Kind::address && width == 4 && !immediate)
                    values[rd] = {Kind::opcode, base.offset};
            } else if (base.kind == Kind::object && source.kind == Kind::opcode && width == 4 &&
                       immediate <= 0x400u - base.offset) {
                address_offset = source.offset;
                opcode_offset = base.offset + immediate;
                found = true;
                break;
            }
        } else if ((word & 0x7c000000u) == 0x14000000u) {
            if (word & 0x80000000u) {
                for (unsigned i = 0; i <= 18; ++i) values[i] = {};
                values[30] = {};
            } else {
                uint64_t target = 0;
                if (!access_target(prepare + at, word & 0x03ffffffu, 26, target) ||
                    target < prepare || target - prepare >= text.size())
                    return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
                at = static_cast<size_t>(target - prepare) - 4;
            }
        } else if ((word & 0xff000010u) == 0x54000000u ||
                   (word & 0x7e000000u) == 0x34000000u ||
                   (word & 0x7e000000u) == 0x36000000u) {
            // Only a witnessed fallthrough copy is accepted; branch targets are not scanned.
        } else if ((word & 0x3a000000u) == 0x28000000u && !(word & (1u << 26))) {
            if (word & (1u << 22)) { values[rd] = {}; values[word >> 10 & 31] = {}; }
            if ((word >> 23 & 3) == 1 || (word >> 23 & 3) == 3) values[rn] = {};
        } else if ((word & 0x3b000000u) == 0x38000000u && !(word & (1u << 26))) {
            if (word & (3u << 22)) values[rd] = {};
            if (word & (3u << 10)) values[rn] = {};
        } else if ((word & 0xfffffc1fu) == 0xd63f0000u) {
            for (unsigned i = 0; i <= 18; ++i) values[i] = {};
            values[30] = {};
        } else if ((word & 0x1c000000u) == 0x10000000u ||
                   (word & 0x0e000000u) == 0x0a000000u ||
                   (word & 0xffffffe0u) == 0xd5384100u) {
            values[rd] = {};
        } else return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
        values[31] = {};
    }
    if (!found || (address_offset & 7u) || (opcode_offset & 3u) ||
        (opcode_offset >= address_offset && opcode_offset - address_offset < 8u))
        return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    addr = {};
    addr.offset_bytes = address_offset;
    addr.width_bytes = 8;
    addr.source = "accessor";
    addr.reader = "arch_prepare_kprobe";
    addr.parser_version = 3;
    opcode = {};
    opcode.offset_bytes = opcode_offset;
    opcode.width_bytes = 4;
    opcode.source = "accessor";
    opcode.reader = "arch_prepare_kprobe";
    opcode.parser_version = 3;
    return KModErr::OK;
}
}

KModErr maplesu_resolve_btf_field(const char* owner, const char* member, uint32_t expected_width,
                               KernelFieldDescription& field, bool& blob_available) {
    return resolve_blob_field(owner, member, expected_width, field, blob_available);
}

KModErr maplesu_resolve_root_credential_offsets(uint32_t& task_cred, uint32_t& cred_uid,
    uint32_t& cred_euid, uint32_t& task_seccomp, uint32_t& cred_inheritable) {
    RequestIdentity identity;
    if (!identity.capture()) return KModErr::ERR_MODULE_ROOT_KEY;
    struct Request { const char* owner; const char* member; uint32_t width; };
    constexpr Request requests[] = {{"task_struct", "cred", 8}, {"cred", "uid", 4},
        {"cred", "euid", 4}, {"task_struct", "seccomp.mode", 4}, {"cred", "cap_inheritable", 8}};
    std::array<KernelFieldDescription, 5> fields{};
    bool available = true;
    {
        std::lock_guard<std::mutex> guard(blob_mutex);
        bool cached = true;
        for (size_t i = 0; i < fields.size(); ++i) {
            const auto found = running_fields.find(std::string(requests[i].owner) + "." + requests[i].member);
            if (found == running_fields.end()) { cached = false; break; }
            fields[i] = found->second;
        }
        if (!cached) {
            std::vector<uint8_t> candidate;
            const char* reader = running_reader;
            if (running_blob.empty()) {
                // Pre-root has a bounded target-text source for these five fields.
                // Do not transfer the entire BTF through the small READ wire here.
                const auto error = read_running_blob(candidate, available, reader, false);
                if (available && is_failed(error)) return error;
            }
            if (available) try {
                const auto& blob = running_blob.empty() ? candidate : running_blob;
                const auto layout = maplesu::module_policy::describe_task_credential_layout(blob,
                    {"cred", "seccomp.mode"}, {"uid", "euid", "cap_inheritable"});
                for (size_t i = 0; i < fields.size(); ++i) {
                    const auto& request = requests[i];
                    const auto type = std::find_if(layout.types.begin(), layout.types.end(),
                        [&](const auto& value) { return value.name == request.owner; });
                    if (type == layout.types.end()) return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
                    const auto member = std::find_if(type->fields.begin(), type->fields.end(),
                        [&](const auto& value) { return value.name == request.member; });
                    if (member == type->fields.end() || (member->bit_offset & 7) ||
                        member->bit_size != request.width * 8 ||
                        uint64_t(member->bit_offset) + member->bit_size > uint64_t(type->size) * 8 ||
                        member->bit_offset / 8 > static_cast<uint32_t>(INT32_MAX))
                        return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
                    fields[i].offset_bytes = member->bit_offset / 8;
                    fields[i].width_bytes = request.width;
                    fields[i].owner_size_bytes = type->size;
                    fields[i].reader = reader;
                }
                if (running_blob.empty()) { running_blob = std::move(candidate); running_reader = reader; }
                for (size_t i = 0; i < fields.size(); ++i)
                    running_fields.emplace(std::string(requests[i].owner) + "." + requests[i].member, fields[i]);
            } catch (const std::exception&) { return KModErr::ERR_MODULE_OFFSET_NOT_FOUND; }
        }
    }
    if (!available) for (size_t i = 0; i < fields.size(); ++i)
        RETURN_IF_ERROR(resolve_accessor_field(requests[i].owner, requests[i].member, requests[i].width, fields[i]));
    for (size_t i = 0; i < fields.size(); ++i)
        if (fields[i].width_bytes != requests[i].width) return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    if (!identity.matches()) return KModErr::ERR_MODULE_ROOT_KEY;
    task_cred = fields[0].offset_bytes; cred_uid = fields[1].offset_bytes;
    cred_euid = fields[2].offset_bytes; task_seccomp = fields[3].offset_bytes;
    cred_inheritable = fields[4].offset_bytes;
    return KModErr::OK;
}

KModErr maplesu_resolve_kprobe_fields(KernelFieldDescription& addr,
                                      KernelFieldDescription& opcode,
                                      bool& blob_available) {
    blob_available = true;
    KModErr error = resolve_blob_field("kprobe", "addr", 8, addr, blob_available);
    if (blob_available) {
        RETURN_IF_ERROR(error);
        bool same_blob = true;
        RETURN_IF_ERROR(resolve_blob_field("kprobe", "opcode", 4, opcode, same_blob));
        if (!same_blob) return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
        return KModErr::OK;
    }
    error = resolve_kprobe_fields_from_target(addr, opcode);
    if (error == KModErr::OK) blob_available = false;
    return error;
}

KModErr maplesu_resolve_accessor_field(const char* owner, const char* member, uint32_t expected_width,
                                    KernelFieldDescription& field) {
    return resolve_accessor_field(owner, member, expected_width, field);
}

static KModErr btf_name_kaddr_by_offset_local(uint64_t btf, uint32_t offset,
                                            uint64_t& address) {
    address = 0;
    return get_kernel_shellcode_u64_result(
        [btf, offset](asmjit::a64::Assembler* a, asmjit::a64::GpX& result) {
            KModErr err = KModErr::OK;
            export_symbol::linux_above_5_10_0::btf_name_by_offset(a, err, btf, offset);
            RETURN_IF_ERROR(err);
            result = asmjit::a64::x0;
            return KModErr::OK;
        }, address);
}

static KModErr btf_string_section_length(uint64_t btf, uint64_t strings,
                                        uint32_t& length) {
    // vmlinux has no base BTF: the target accessor accepts every byte offset
    // below hdr.str_len, including offsets inside a name, and returns NULL above it.
    const auto probe = [btf, strings](uint32_t offset, uint64_t& address) {
        RETURN_IF_ERROR(btf_name_kaddr_by_offset_local(btf, offset, address));
        if (address && (offset > UINT64_MAX - strings || !btf_kernel_pointer(address) ||
            address != strings + offset)) return KModErr::ERR_MODULE_NOT_KADDR;
        return KModErr::OK;
    };
    uint64_t address = 0;
    RETURN_IF_ERROR(probe(UINT32_MAX, address));
    if (address) return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    uint32_t low = 0, high = UINT32_MAX;
    while (high - low > 1) {
        const uint32_t middle = low + (high - low) / 2;
        RETURN_IF_ERROR(probe(middle, address));
        if (!address) {
            high = middle;
        } else {
            low = middle;
        }
    }
    length = high;
    return KModErr::OK;
}

static KModErr btf_resolver_init() {
    if (g_vmlinux_btf_ptr) return KModErr::OK;
    uint64_t candidate = 0;
    KModErr error = get_kernel_shellcode_u64_result(
        [](asmjit::a64::Assembler* a, asmjit::a64::GpX& result) {
            KModErr err = KModErr::OK;
            export_symbol::linux_above_5_10_0::bpf_get_btf_vmlinux(a, err);
            RETURN_IF_ERROR(err);
            result = asmjit::a64::x0;
            return KModErr::OK;
        }, candidate);
    if (is_failed(error) || !btf_kernel_pointer(candidate)) {
        uint64_t symbol = 0;
        RETURN_IF_ERROR(kallsyms_lookup_name("btf_vmlinux", symbol));
        if (!btf_kernel_pointer(symbol)) return KModErr::ERR_MODULE_NOT_KADDR;
        uint64_t value = 0;
        RETURN_IF_ERROR(read_kernel_mem(symbol, &value, sizeof(value)));
        candidate = value;
        if (!btf_kernel_pointer(candidate)) {
            return KModErr::ERR_MODULE_NOT_KADDR;
        }
    }
    uint64_t strings = 0;
    RETURN_IF_ERROR(btf_name_kaddr_by_offset_local(candidate, 0, strings));
    if (!btf_kernel_pointer(strings)) return KModErr::ERR_MODULE_NOT_KADDR;
    char first = 0;
    RETURN_IF_ERROR(read_kernel_mem(strings, &first, 1));
    if (first) return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    uint32_t length = 0;
    RETURN_IF_ERROR(btf_string_section_length(candidate, strings, length));
    g_btf_strs_data = strings;
    g_btf_strs_length = length;
    g_vmlinux_btf_ptr = candidate;
    return KModErr::OK;
}

static KModErr btf_find_by_name_kind_local(const char* name, uint32_t kind, int& id) {
    id = 0;
    if (!name || !*name) return KModErr::ERR_MODULE_PARAM;
    uint64_t value = 0;
    // so construction of std::function retains its throwing-copy cleanup.
    const std::string name_copy(name);
    RETURN_IF_ERROR(get_kernel_shellcode_u64_result(
        [name_copy, kind](asmjit::a64::Assembler* a, asmjit::a64::GpX& result) {
            KModErr err = KModErr::OK;
            // B / padded NUL-terminated data / ADR x10 sequence comes from
            aarch64_asm_set_x_cstr_ptr(a, asmjit::a64::x10, name_copy);
            export_symbol::linux_above_5_10_0::btf_find_by_name_kind(
                a, err, g_vmlinux_btf_ptr, asmjit::a64::x10, kind);
            RETURN_IF_ERROR(err);
            result = asmjit::a64::x0;
            return KModErr::OK;
        }, value));
    if (value > static_cast<uint64_t>(INT32_MAX)) return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    id = static_cast<int>(value);
    return KModErr::OK;
}

static KModErr btf_type_by_id_local(uint32_t id, uint64_t& type_address) {
    type_address = 0;
    if (!id) return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    RETURN_IF_ERROR(get_kernel_shellcode_u64_result(
        [id](asmjit::a64::Assembler* a, asmjit::a64::GpX& result) {
            KModErr err = KModErr::OK;
            export_symbol::linux_above_5_10_0::btf_type_by_id(
                a, err, g_vmlinux_btf_ptr, id);
            RETURN_IF_ERROR(err);
            result = asmjit::a64::x0;
            return KModErr::OK;
        }, type_address));
    return btf_kernel_pointer(type_address) ? KModErr::OK : KModErr::ERR_MODULE_NOT_KADDR;
}

static KModErr btf_read_at(uint64_t address, void* data, uint32_t size) {
    if (!size || !btf_kernel_pointer(address) || size - 1 > UINT64_MAX - address ||
        !btf_kernel_pointer(address + size - 1)) return KModErr::ERR_MODULE_NOT_KADDR;
    return read_kernel_mem(address, data, size);
}

static KModErr btf_read_type_at(uint64_t address, btf_type& type) {
    return btf_read_at(address, &type, sizeof(type));
}

static KModErr btf_read_type_extra(uint64_t address, void* data, uint32_t size) {
    if (sizeof(btf_type) > UINT64_MAX - address) return KModErr::ERR_MODULE_NOT_KADDR;
    return btf_read_at(address + sizeof(btf_type), data, size);
}

static KModErr btf_skip_modifiers_local(uint32_t id, uint64_t& type_address) {
    type_address = 0;
    if (!id) return KModErr::ERR_MODULE_PARAM;
    std::set<uint32_t> visited;
    while (id) {
        if (!visited.insert(id).second) return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
        uint64_t address = 0;
        RETURN_IF_ERROR(btf_type_by_id_local(id, address));
        if (!address) return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
        btf_type type{};
        RETURN_IF_ERROR(btf_read_type_at(address, type));
        switch ((type.info >> 24) & 31) {
            case 8: case 9: case 10: case 11: case 18:
                id = type.type;
                break;
            default:
                type_address = address;
                return KModErr::OK;
        }
    }
    return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
}

static KModErr read_kernel_cstring(uint64_t address, uint32_t max_len,
                                  std::string& output) {
    std::string candidate;
    char buffer[64];
    for (uint32_t offset = 0; offset < max_len;) {
        if (offset > UINT64_MAX - address || !btf_kernel_pointer(address + offset))
            return KModErr::ERR_MODULE_NOT_KADDR;
        const uint64_t current = address + offset;
        const uint32_t count = static_cast<uint32_t>(std::min<uint64_t>(
            std::min<uint32_t>(max_len - offset, sizeof(buffer)),
            static_cast<uint64_t>(-4095LL) - current));
        RETURN_IF_ERROR(read_kernel_mem(current, buffer, count));
        const auto* end = static_cast<const char*>(memchr(buffer, 0, count));
        if (end) {
            candidate.append(buffer, static_cast<size_t>(end - buffer));
            output = std::move(candidate);
            return KModErr::OK;
        }
        candidate.append(buffer, count);
        offset += count;
    }
    return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
}

static KModErr btf_name_by_offset_local(uint32_t offset, std::string& output) {
    auto found = g_btf_name_cache.find(offset);
    if (found != g_btf_name_cache.end()) {
        output = found->second;
        return KModErr::OK;
    }
    std::string name;
    if (offset >= g_btf_strs_length) return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    if (offset > UINT64_MAX - g_btf_strs_data) return KModErr::ERR_MODULE_NOT_KADDR;
    RETURN_IF_ERROR(read_kernel_cstring(g_btf_strs_data + offset, g_btf_strs_length - offset, name));
    g_btf_name_cache.emplace(offset, name);
    output = name;
    return KModErr::OK;
}

static KModErr btf_type_size_local(uint32_t id, uint32_t& size,
                                  std::set<uint64_t>& active) {
    if (active.size() >= 32) return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    uint64_t address = 0;
    RETURN_IF_ERROR(btf_skip_modifiers_local(id, address));
    if (!active.insert(address).second) return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    struct Remove {
        std::set<uint64_t>& active; uint64_t address;
        ~Remove() { active.erase(address); }
    } remove{active, address};
    btf_type type{};
    RETURN_IF_ERROR(btf_read_type_at(address, type));
    switch ((type.info >> 24) & 31) {
        case 2: size = 8; break; // This SDK executes on AArch64.
        case 1: case 4: case 5: case 6: case 16: case 19:
            size = type.size; break;
        case 3: {
            btf_array array{};
            RETURN_IF_ERROR(btf_read_type_extra(address, &array, sizeof(array)));
            uint32_t element = 0;
            RETURN_IF_ERROR(btf_type_size_local(array.type, element, active));
            if (!array.nelems || element > UINT32_MAX / array.nelems)
                return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
            size = element * array.nelems;
            break;
        }
        default: return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    }
    return size ? KModErr::OK : KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
}

struct LiveBtfMember {
    uint64_t bit_offset = 0;
    uint64_t bit_size = 0;
};

static KModErr btf_find_member_recursive(uint64_t type_address, const char* name,
                                       uint64_t base_bits, LiveBtfMember& result,
                                       bool& found, std::set<uint64_t>& active) {
    found = false;
    if (active.size() >= 16) return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    if (!active.insert(type_address).second) return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    struct Remove {
        std::set<uint64_t>& active; uint64_t address;
        ~Remove() { active.erase(address); }
    } remove{active, type_address};
    btf_type type{};
    RETURN_IF_ERROR(btf_read_type_at(type_address, type));
    const uint32_t kind = (type.info >> 24) & 31;
    if ((kind != 4 && kind != 5) || !type.size) return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    const uint32_t count = type.info & 0xffff;
    if (!count) return KModErr::OK;
    std::vector<btf_member> members(count);
    RETURN_IF_ERROR(btf_read_type_extra(type_address, members.data(), count * sizeof(btf_member)));
    const char* dot = strchr(name, '.');
    const std::string wanted(name, dot ? static_cast<size_t>(dot - name) : strlen(name));
    if (wanted.empty() || (dot && !dot[1])) return KModErr::ERR_MODULE_PARAM;
    auto select = [&](LiveBtfMember candidate) {
        if (found) return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
        result = candidate; found = true;
        return KModErr::OK;
    };
    for (const auto& member : members) {
        std::string member_name;
        RETURN_IF_ERROR(btf_name_by_offset_local(member.name_off, member_name));
        const bool has_bitfields = (type.info >> 31) != 0;
        uint64_t bits = has_bitfields ? (member.offset & 0xffffff) : member.offset;
        if (bits > UINT64_MAX - base_bits) return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
        if (member_name.empty() || member_name == wanted) {
            uint64_t nested_address = 0;
            RETURN_IF_ERROR(btf_skip_modifiers_local(member.type, nested_address));
            btf_type nested_type{};
            RETURN_IF_ERROR(btf_read_type_at(nested_address, nested_type));
            const uint32_t nested_kind = (nested_type.info >> 24) & 31;
            if (member_name.empty() && nested_kind != 4 && nested_kind != 5) continue;
            if (member_name.empty() && !nested_type.size && !(nested_type.info & 0xffff)) {
                if ((bits & 7) || bits > uint64_t(type.size) * 8 ||
                    (has_bitfields && (member.offset >> 24)))
                    return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
                continue; // An empty anonymous aggregate contains no matching field.
            }
            std::set<uint64_t> size_active;
            uint32_t member_size = 0;
            RETURN_IF_ERROR(btf_type_size_local(member.type, member_size, size_active));
            uint64_t width = has_bitfields ? member.offset >> 24 : 0;
            if (!width) width = uint64_t(member_size) * 8;
            if (!member_name.empty() && nested_kind == 1) {
                uint32_t encoding = 0;
                RETURN_IF_ERROR(btf_read_type_extra(nested_address, &encoding, sizeof(encoding)));
                const uint32_t int_bits = encoding & 0xff, int_offset = encoding >> 16 & 0xff;
                if (!int_bits || int_bits + int_offset > 128 ||
                    int_bits + int_offset > uint64_t(member_size) * 8)
                    return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
                if (has_bitfields) {
                    if (int_offset || int_bits < 8 || (int_bits & (int_bits - 1)) ||
                        (member.offset >> 24) > int_bits) return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
                    width = member.offset >> 24 ? member.offset >> 24 : int_bits;
                } else {
                    bits += int_offset;
                    width = int_bits;
                }
            } else if (has_bitfields && (member.offset >> 24) &&
                       ((nested_kind != 6 && nested_kind != 19) || width > uint64_t(member_size) * 8))
                return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
            if (bits > uint64_t(type.size) * 8 || width > uint64_t(type.size) * 8 - bits ||
                bits > UINT64_MAX - base_bits) return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
            if (member_name.empty() || dot) {
                if (width != uint64_t(member_size) * 8 || (bits & 7) ||
                    (nested_kind != 4 && nested_kind != 5)) return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
                LiveBtfMember nested;
                bool nested_found = false;
                RETURN_IF_ERROR(btf_find_member_recursive(nested_address, member_name.empty() ? name : dot + 1,
                    base_bits + bits, nested, nested_found, active));
                if (nested_found) RETURN_IF_ERROR(select(nested));
            } else {
                RETURN_IF_ERROR(select({base_bits + bits, width}));
            }
        }
    }
    return KModErr::OK;
}

KModErr btf_resolve_member_offset(const char* struct_name, const char* member_name,
                                 uint32_t& offset) {
    offset = 0;
    if (!struct_name || !*struct_name || !member_name || !*member_name)
        return KModErr::ERR_MODULE_PARAM;
    struct_name = btf_trim_struct_prefix(struct_name);
    KernelFieldDescription field;
    bool available = false;
    KModErr error = resolve_blob_field(struct_name, member_name, 0, field, available);
    if (available) {
        if (is_ok(error)) offset = field.offset_bytes;
        return error;
    }
    std::lock_guard<std::mutex> guard(g_live_btf_mutex);
    RETURN_IF_ERROR(btf_resolver_init());
    int id = 0;
    RETURN_IF_ERROR(btf_find_by_name_kind_local(struct_name, 4, id));
    if (id <= 0) return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    uint64_t address = 0;
    RETURN_IF_ERROR(btf_skip_modifiers_local(static_cast<uint32_t>(id), address));
    if (!address) return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    LiveBtfMember member;
    bool found = false;
    std::set<uint64_t> active;
    RETURN_IF_ERROR(btf_find_member_recursive(address, member_name, 0, member, found, active));
    if (!found || (member.bit_offset & 7) || (member.bit_size & 7) ||
        (member.bit_offset >> 3) > std::numeric_limits<uint32_t>::max())
        return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    offset = static_cast<uint32_t>(member.bit_offset >> 3);
    return KModErr::OK;
}

KModErr btf_resolve_struct_size(const char* struct_name, uint32_t& size) {
    size = 0;
    if (!struct_name || !*struct_name) return KModErr::ERR_MODULE_PARAM;
    struct_name = btf_trim_struct_prefix(struct_name);
    KernelFieldDescription field;
    bool available = false;
    KModErr error = resolve_blob_field(struct_name, nullptr, 0, field, available);
    if (available) {
        if (is_ok(error)) size = field.owner_size_bytes;
        return error;
    }
    std::lock_guard<std::mutex> guard(g_live_btf_mutex);
    RETURN_IF_ERROR(btf_resolver_init());
    int id = 0;
    RETURN_IF_ERROR(btf_find_by_name_kind_local(struct_name, 4, id));
    if (id <= 0) return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    uint64_t address = 0;
    RETURN_IF_ERROR(btf_skip_modifiers_local(static_cast<uint32_t>(id), address));
    if (!address) return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    btf_type type{};
    RETURN_IF_ERROR(btf_read_type_at(address, type));
    if (((type.info >> 24) & 31) != 4) return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    size = type.size;
    return size ? KModErr::OK : KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
}

// Readback forks run beside other SDK callers. Keep each mutable layout cache
// quiescent across fork; a child must never inherit another thread's cache lock.
// The caller holds publication first, then tries these locks without waiting.
// Complete in both parent and child before SDK use. Busy is not a Root proof.
extern "C" __attribute__((visibility("hidden"))) bool maplesu_btf_try_fork_prepare() noexcept {
    if (!accessor_mutex.try_lock()) return false;
    if (!blob_mutex.try_lock()) { accessor_mutex.unlock(); return false; }
    if (!g_live_btf_mutex.try_lock()) { blob_mutex.unlock(); accessor_mutex.unlock(); return false; }
    return true;
}
extern "C" __attribute__((visibility("hidden"))) void maplesu_btf_fork_complete() noexcept {
    g_live_btf_mutex.unlock();
    blob_mutex.unlock();
    accessor_mutex.unlock();
}

}  // namespace kernel_module
