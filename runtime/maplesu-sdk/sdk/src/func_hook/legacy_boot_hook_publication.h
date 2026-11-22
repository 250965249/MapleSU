#pragma once

namespace {
// This compatibility path retains its complete closure for the boot. A handle
// can disable future callbacks, but does not prove that existing readers left.
constexpr uint64_t kLegacyBootHookMagic = UINT64_C(0x314854424c55534d);
constexpr uint32_t kLegacyBootGateBytes = 4096;
// Schema-2 fixed emitter <=156 bytes plus <=3 relocated instructions,
// each <=28 bytes (far literal scratch path); round the bound to 16 bytes.
constexpr uint32_t kLegacyBootGateReservationBytes = (156u + 3u * 28u + 15u) & ~15u;
static_assert(kLegacyBootGateReservationBytes <= kLegacyBootGateBytes);
struct LegacyBootHookHeader {
    uint64_t magic;
    uint32_t schema, length;
    uint64_t function, entry, payload, origin;
    uint32_t payload_bytes, gate_bytes, first, original;
};
static_assert(sizeof(LegacyBootHookHeader) == 64, "boot Hook metadata");

struct LegacyBootHook {
    HookContext context{};
    RequestIdentity identity;
};
std::map<HookHandle, std::unique_ptr<LegacyBootHook>> legacy_boot_hooks;

void legacy_boot_handle(const LegacyBootHookHeader& header, uint64_t gate,
                        uint64_t disable_flag, const RequestIdentity& identity, HookHandle* output) {
    if (!output) return;
    auto hook = std::make_unique<LegacyBootHook>();
    hook->identity = identity;
    hook->context = {header.entry, header.original, gate, kLegacyBootGateBytes,
        1, disable_flag};
    const auto handle = &hook->context;
    legacy_boot_hooks.emplace(handle, std::move(hook));
    *output = handle;
}

bool legacy_boot_flag_address(uint64_t flag, uint64_t payload, uint32_t size, uint64_t gate) {
    const uint64_t page = get_page_size();
    if (!page || (page & (page - 1)) || flag < UINT64_C(0xffff000000000000) ||
        (flag & (page - 1)) || payload < UINT64_C(0xffff000000000008) ||
        payload > UINT64_MAX - size || gate > UINT64_MAX - kLegacyBootGateBytes)
        return false;
    const uint64_t mask = ~(page - 1);
    return (flag < ((payload - 8) & mask) || flag > ((payload + size - 1) & mask)) &&
        (flag < (gate & mask) || flag > ((gate + kLegacyBootGateBytes - 1) & mask));
}

KModErr uninstall_legacy_boot_hook(LegacyBootHook& hook) {
    if (!hook.identity.matches()) return KModErr::ERR_MODULE_ROOT_KEY;
    const uint8_t disabled = 1;
    auto error = write_kernel_mem(hook.context.disable_flag, &disabled, 1, KernMemProt::KMP_RW);
    if (error != KModErr::OK) return error;
    uint8_t observed = 0;
    error = read_kernel_mem(hook.context.disable_flag, &observed, 1);
    if (error != KModErr::OK) return error;
    if (observed != disabled) return KModErr::ERR_MODULE_ASM;
    hook.context.enabled = 0;
    if (!hook.identity.matches()) return KModErr::ERR_MODULE_ROOT_KEY;
    // The old native contract has no readers grace period. Callers must retain
    // UID/shared state even after this successful disable-byte readback.
    errno = EINPROGRESS;
    return KModErr::ERR_MODULE_MUST_UNINSTALL;
}

KModErr legacy_boot_backend_selected(bool& selected) {
    selected = false;
    if (maplesu_request_owner_mode() ||
        !maplesu_request_auth_legacy(maplesu_request_auth_state())) return KModErr::OK;
    maplesu_metadata_v2 metadata{};
    uint64_t descriptor = 0;
    bool supported = false;
    auto error = maplesu_kernel_metadata_v2(metadata, descriptor, supported);
    if (error != KModErr::OK || !supported) return error;
    if (descriptor > UINT64_MAX - sizeof(metadata) - sizeof(maplesu_legacy_hook_metadata_private))
        return KModErr::ERR_MODULE_NOT_KADDR;
    maplesu_legacy_hook_metadata_private tail{};
    error = maplesu_request_v2_read(descriptor + sizeof(metadata), &tail, sizeof(tail));
    if (error != KModErr::OK) return error;
    // The actual v2 producer emits an entirely zero private tail when its target
    // Image has no native provider. Corrupt or nonzero metadata does not select
    // a different backend, nor does a failed provider operation.
    const maplesu_legacy_hook_metadata_private absent{};
    selected = !std::memcmp(&tail, &absent, sizeof(tail));
    return KModErr::OK;
}

struct LegacyBootHookLock {
    int fd = -1;
    ~LegacyBootHookLock() {
        const int error = errno;
        if (fd >= 0) { (void)flock(fd, LOCK_UN); close(fd); }
        errno = error;
    }
    KModErr acquire() {
        std::string directory;
        auto error = ::maplesu::storage::current_kernel_directory(directory);
        if (error != KModErr::OK) return error;
        const std::string path = directory + ".legacy-boot-hook.lock";
        do { fd = open(path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600); }
        while (fd < 0 && errno == EINTR);
        if (fd < 0) return KModErr::ERR_MODULE_OPEN_FILE;
        struct stat st{};
        if (fstat(fd, &st)) return KModErr::ERR_MODULE_READ_FILE;
        if (!S_ISREG(st.st_mode) || st.st_uid || st.st_nlink != 1 || (st.st_mode & 0077)) {
            errno = EPERM;
            return KModErr::ERR_MODULE_OPEN_FILE;
        }
        int result;
        do { result = flock(fd, LOCK_EX); } while (result < 0 && errno == EINTR);
        return result ? KModErr::ERR_MODULE_OPEN_FILE : KModErr::OK;
    }
};

bool legacy_boot_branch_target(uint64_t entry, uint32_t word, uint64_t& target) {
    if ((word & 0xfc000000u) != 0x14000000u) return false;
    const int64_t displacement = static_cast<int32_t>(word << 6) / 16;
    return maplesu_kernel_read::metadata_address(entry, displacement, 4, target);
}

KModErr legacy_boot_gate(uint64_t gate, const LegacyBootHookHeader& header,
                        std::vector<uint8_t>& code, uint64_t& origin) {
    auto context = init_aarch64_asm();
    auto* a = context.assembler();
    if (!a) return KModErr::ERR_MODULE_ASM;
    const auto run = a->newLabel();
    a->b(run);
    a->embed(&header, sizeof(header));
    a->bind(run);
    a->sub(sp, sp, Imm(kHookTrampolineFrame));
    a->stp(x29, x30, ptr(sp).pre(-16));
    const auto disabled = a->newLabel();
    if (header.schema == 2) {
        aarch64_asm_mov_x(a, x29, header.payload - 8);
        a->ldr(x29, ptr(x29));
        a->ldrb(w29, ptr(x29));
        a->cbnz(w29, disabled);
        a->ldp(x29, x30, ptr(sp));
    }
    a->stp(x28, xzr, ptr(sp).pre(-16));
    aarch64_asm_mov_x(a, x28, header.payload);
    a->blr(x28);
    a->bind(disabled);
    a->ldp(x29, x30, ptr(sp).post(16));
    a->add(sp, sp, Imm(kHookTrampolineFrame));
    auto error = emit_old_insn_and_jump_back(a, gate, {{header.entry, header.original}});
    if (error != KModErr::OK) return error;
    origin = gate + a->offset();
    aarch64_asm_bit_c(a);
    a->ldp(x0, x1, ptr(sp).post(16));
    std::vector<InsnRecord> records{{header.function, header.first}};
    if (header.entry != header.function) records.push_back({header.entry, header.original});
    error = emit_old_insn_and_jump_back(a, gate, records);
    if (error != KModErr::OK) return error;
    code = aarch64_asm_to_bytes(a);
    if (context.has_error() || code.empty() || code.size() > kLegacyBootGateBytes)
        return KModErr::ERR_MODULE_ASM;
    auto finalized = header;
    finalized.origin = origin;
    finalized.gate_bytes = static_cast<uint32_t>(code.size());
    std::memcpy(code.data() + 4, &finalized, sizeof(finalized));
    return KModErr::OK;
}

KModErr legacy_boot_payload(const void* buffer, uint32_t size, uint32_t first,
                           uint64_t origin, std::vector<uint8_t>& payload) {
    const auto origin_slot = find_origin_kaddr_slot_offset(buffer, size);
    const auto return_slot = find_ret_insn_slot_offset(buffer, size);
    if (origin_slot < 0 || uint64_t(origin_slot) + 8 > size ||
        return_slot < 0 || uint64_t(return_slot) + 8 > size) return kErrHookFuncNotStandard;
    auto context = init_aarch64_asm();
    auto* a = context.assembler();
    if (!a) return KModErr::ERR_MODULE_ASM;
    emit_ret_by_entry_insn(a, first);
    const auto tail = aarch64_asm_to_bytes(a);
    if (context.has_error() || tail.empty() || tail.size() > 8) return kErrAsmRetTooLong;
    payload.assign(static_cast<const uint8_t*>(buffer), static_cast<const uint8_t*>(buffer) + size);
    std::memcpy(payload.data() + origin_slot, &origin, sizeof(origin));
    std::memcpy(payload.data() + return_slot, tail.data(), tail.size());
    return KModErr::OK;
}

KModErr legacy_boot_existing(uint64_t function, uint64_t entry, uint32_t branch,
                            const void* buffer, uint32_t size,
                            const RequestIdentity& identity, HookHandle* output, bool& recognized) {
    recognized = false;
    uint64_t gate = 0;
    if (!legacy_boot_branch_target(entry, branch, gate) || gate > UINT64_MAX - 68)
        return KModErr::ERR_MODULE_DUPLICATE;
    uint64_t magic = 0;
    auto error = read_kernel_mem(gate + 4, &magic, sizeof(magic));
    if (error != KModErr::OK) return error;
    // An Image shim or compiler branch is an original instruction to relocate.
    // Only our own marker selects strict existing-publication validation.
    if (magic != kLegacyBootHookMagic) return KModErr::OK;
    recognized = true;
    LegacyBootHookHeader header{};
    error = read_kernel_mem(gate + 4, &header, sizeof(header));
    if (error != KModErr::OK) return error;
    if (header.magic != kLegacyBootHookMagic || (header.schema != 1 && header.schema != 2) ||
        header.length != sizeof(header) || header.function != function || header.entry != entry ||
        header.payload_bytes != size || header.gate_bytes > kLegacyBootGateBytes ||
        header.payload < UINT64_C(0xffff000000000000) || (header.payload & 3u) ||
        header.payload > UINT64_MAX - size) return KModErr::ERR_MODULE_DUPLICATE;
    std::vector<uint8_t> code, payload;
    uint64_t origin = 0;
    error = legacy_boot_gate(gate, header, code, origin);
    if (error != KModErr::OK) return error;
    if (origin != header.origin || code.size() != header.gate_bytes)
        return KModErr::ERR_MODULE_DUPLICATE;
    error = legacy_boot_payload(buffer, size, header.first, origin, payload);
    if (error != KModErr::OK) return error;
    std::vector<uint8_t> actual_code(code.size()), actual_payload(size);
    error = read_kernel_mem(gate, actual_code.data(), static_cast<uint32_t>(actual_code.size()));
    if (error != KModErr::OK) return error;
    error = read_kernel_mem(header.payload, actual_payload.data(), size);
    if (error != KModErr::OK) return error;
    if (actual_code != code || actual_payload != payload)
        return KModErr::ERR_MODULE_DUPLICATE;
    uint32_t current_branch = 0;
    error = read_kernel_mem(entry, &current_branch, sizeof(current_branch));
    if (error != KModErr::OK) return error;
    if (current_branch != branch) return KModErr::ERR_MODULE_DUPLICATE;
    if (function != entry) {
        uint32_t current_first = 0;
        error = read_kernel_mem(function, &current_first, sizeof(current_first));
        if (error != KModErr::OK) return error;
        if (current_first != header.first) return KModErr::ERR_MODULE_DUPLICATE;
    } else if (header.first != header.original) {
        return KModErr::ERR_MODULE_DUPLICATE;
    }
    if (header.schema == 2) {
        if (header.payload < UINT64_C(0xffff000000000008)) return KModErr::ERR_MODULE_DUPLICATE;
        uint64_t disable_flag = 0;
        error = read_kernel_mem(header.payload - 8, &disable_flag, sizeof(disable_flag));
        if (error != KModErr::OK) return error;
        if (!legacy_boot_flag_address(disable_flag, header.payload, size, gate))
            return KModErr::ERR_MODULE_DUPLICATE;
        uint8_t disabled = 0;
        error = read_kernel_mem(disable_flag, &disabled, 1);
        if (error != KModErr::OK) return error;
        if (disabled) {
            errno = EINPROGRESS;
            return KModErr::ERR_MODULE_MUST_UNINSTALL;
        }
        if (!identity.matches()) return KModErr::ERR_MODULE_ROOT_KEY;
        legacy_boot_handle(header, gate, disable_flag, identity, output);
    } else if (output) {
        // A schema-1 gate has no disable load; never invent a working handle.
        errno = EOPNOTSUPP;
        return KModErr::ERR_MODULE_MUST_UNINSTALL;
    }
    return KModErr::OK;
}

// The check and native rendezvous are one authenticated EXEC. Holding the
// kernel's own probe mutex closes the lookup/register race. Existing native
// probes are rejected; this path does not claim logical-text overlay ownership.
KModErr legacy_boot_publish(uint64_t function, uint64_t entry, uint32_t first,
                           uint32_t expected, uint32_t branch) {
    uint64_t mutex = 0, text_mutex = 0, cpus_lock = 0, cpus_unlock = 0;
    auto error = kallsyms_lookup_name("kprobe_mutex", mutex);
    if (error != KModErr::OK) return error;
    error = kallsyms_lookup_name("text_mutex", text_mutex);
    if (error != KModErr::OK) return error;
    error = kallsyms_lookup_name("cpus_read_lock", cpus_lock);
    if (error != KModErr::OK) return error;
    error = kallsyms_lookup_name("cpus_read_unlock", cpus_unlock);
    if (error != KModErr::OK) return error;
    if (mutex < UINT64_C(0xffff000000000000) || (mutex & 7u) ||
        text_mutex < UINT64_C(0xffff000000000000) || (text_mutex & 7u) ||
        cpus_lock < UINT64_C(0xffff000000000000) || (cpus_lock & 3u) ||
        cpus_unlock < UINT64_C(0xffff000000000000) || (cpus_unlock & 3u))
        return KModErr::ERR_MODULE_NOT_KADDR;
    auto context = init_aarch64_asm();
    auto* a = context.assembler();
    if (!a) return KModErr::ERR_MODULE_ASM;
    const auto unlock = a->newLabel();
    arm64_module_asm_func_start(a);
    a->sub(sp, sp, Imm(32));
    aarch64_asm_mov_x(a, x19, entry);
    aarch64_asm_mov_x(a, x20, mutex);
    aarch64_asm_mov_x(a, x24, text_mutex);
    aarch64_asm_mov_x(a, x23, uint64_t(int64_t(-EBUSY)));
    export_symbol::mutex_lock(a, error, x20);
    if (error != KModErr::OK) return error;
    // Match kprobe_text_owner's lock order. The target patch primitive uses
    // stop_machine_cpuslocked and leaves hotplug exclusion to its caller.
    aarch64_asm_mov_x(a, x16, cpus_lock);
    a->blr(x16);
    export_symbol::mutex_lock(a, error, x24);
    if (error != KModErr::OK) return error;
    export_symbol::get_kprobe(a, error, x19);
    if (error != KModErr::OK) return error;
    a->cbnz(x0, unlock);
    aarch64_asm_mov_x(a, x23, uint64_t(int64_t(-EFAULT)));
    a->mov(x22, sp);
    export_symbol::copy_from_kernel_nofault(a, error, x22, x19, uint64_t(4));
    if (error != KModErr::OK) return error;
    a->cbnz(x0, unlock);
    aarch64_asm_mov_x(a, x23, uint64_t(int64_t(-ESTALE)));
    a->ldr(w10, ptr(sp));
    aarch64_asm_mov_w(a, w11, expected);
    a->cmp(w10, w11);
    a->b(CondCode::kNE, unlock);
    if (function != entry) {
        aarch64_asm_mov_x(a, x21, function);
        aarch64_asm_mov_x(a, x23, uint64_t(int64_t(-EBUSY)));
        export_symbol::get_kprobe(a, error, x21);
        if (error != KModErr::OK) return error;
        a->cbnz(x0, unlock);
        aarch64_asm_mov_x(a, x23, uint64_t(int64_t(-EFAULT)));
        export_symbol::copy_from_kernel_nofault(a, error, x22, x21, uint64_t(4));
        if (error != KModErr::OK) return error;
        a->cbnz(x0, unlock);
        aarch64_asm_mov_x(a, x23, uint64_t(int64_t(-ESTALE)));
        a->ldr(w10, ptr(sp));
        aarch64_asm_mov_w(a, w11, first);
        a->cmp(w10, w11);
        a->b(CondCode::kNE, unlock);
    }
    a->str(x19, ptr(sp, 16));
    aarch64_asm_mov_w(a, w10, branch);
    a->str(w10, ptr(sp, 24));
    a->add(x0, sp, Imm(16));
    a->add(x1, sp, Imm(24));
    aarch64_asm_mov_w(a, w2, 1);
    export_symbol::aarch64_insn_patch_text(a, error, x0, x1, w2);
    if (error != KModErr::OK) return error;
    a->sxtw(x23, w0);
    a->bind(unlock);
    export_symbol::mutex_unlock(a, error, x24);
    if (error != KModErr::OK) return error;
    aarch64_asm_mov_x(a, x16, cpus_unlock);
    a->blr(x16);
    export_symbol::mutex_unlock(a, error, x20);
    if (error != KModErr::OK) return error;
    a->add(sp, sp, Imm(32));
    arm64_module_asm_func_end(a, x23);
    if (context.has_error()) return KModErr::ERR_MODULE_ASM;
    uint64_t status = 0;
    error = execute_kernel_asm_func(aarch64_asm_to_bytes(a), status);
    if (error != KModErr::OK) return error;
    if (status) {
        const auto native = static_cast<int64_t>(status);
        if (native < 0 && native >= -4095) errno = static_cast<int>(-native);
        return native == -EBUSY ? KModErr::ERR_MODULE_DUPLICATE : KModErr::ERR_MODULE_ASM;
    }
    return icache_invalidate_all_cpus();
}

KModErr install_legacy_boot_before(uint64_t function, const void* buffer, uint32_t size,
                                   HookHandle* output) {
    if (function < UINT64_C(0xffff000000000000) || (function & 3u) || function > UINT64_MAX - 8)
        return KModErr::ERR_MODULE_ADDR_NOT_ALGIN4;
    if (!buffer || size < 64 || (size & 3u) || size > MAPLESU_MANAGEMENT_MAX_BYTES - 32 ||
        reinterpret_cast<uintptr_t>(buffer) > UINTPTR_MAX - (size - 1)) return kErrHookFuncNotStandard;
    const auto* first_byte = static_cast<const char*>(buffer);
    if (std::search(first_byte, first_byte + size, kMyBeforeHookBeginFlag, kMyBeforeHookBeginFlag + 64) == first_byte + size ||
        std::search(first_byte, first_byte + size, kMyBeforeHookEndFlag, kMyBeforeHookEndFlag + 64) == first_byte + size)
        return kErrHookFuncNotStandard;
    RequestIdentity identity;
    if (!identity.capture()) return KModErr::ERR_MODULE_ROOT_KEY;
    LegacyBootHookLock lock;
    auto error = lock.acquire();
    if (error != KModErr::OK) return error;
    uint32_t first = 0;
    error = read_kernel_mem(function, &first, sizeof(first));
    if (error != KModErr::OK) return error;
    const bool bti = (first & 0xffffff3fu) == 0xd503241fu;
    const uint32_t pac = first + 0x2afcdce1u;
    const bool pac_prologue = uint32_t((pac << 27) | (pac >> 5)) < 4u;
    const uint64_t entry = function + ((bti || pac_prologue) ? 4 : 0);
    uint32_t expected = first;
    if (entry != function) {
        error = read_kernel_mem(entry, &expected, sizeof(expected));
        if (error != KModErr::OK) return error;
    }
    if ((expected & 0xfc000000u) == 0x14000000u) {
        if (!identity.matches()) return KModErr::ERR_MODULE_ROOT_KEY;
        bool recognized = false;
        error = legacy_boot_existing(function, entry, expected, buffer, size, identity, output, recognized);
        if (error != KModErr::OK) return error;
        if (recognized) return identity.matches() ? KModErr::OK : KModErr::ERR_MODULE_ROOT_KEY;
    }
    if ((first & 0xffe0001fu) == 0xd4200000u || (expected & 0xffe0001fu) == 0xd4200000u)
        return KModErr::ERR_MODULE_DUPLICATE;
    // Reserve once, never preview/re-use a range that can already be executing.
    // All current m031 callers are serialized by this protected deployment lock.
    uint64_t gate = 0, payload_address = 0;
    error = acquire_kernel_idle_region(kLegacyBootGateReservationBytes, gate);
    if (error != KModErr::OK) return error;
    uint32_t branch = 0;
    if (!maplesu::aarch64::encode_b(entry, gate, branch)) return kErrAsmBranchEncode;
    const uint32_t prefix = output ? 8 : 0;
    error = request_kernel_alloc_mem(size + prefix, payload_address);
    if (error != KModErr::OK) return error;
    if (payload_address < UINT64_C(0xffff000000000000) || (payload_address & 3u) ||
        payload_address > UINT64_MAX - size - prefix) return KModErr::ERR_MODULE_NOT_KADDR;
    payload_address += prefix;
    uint64_t disable_flag = 0;
    if (prefix) {
        error = request_kernel_alloc_mem(1, disable_flag);
        if (error != KModErr::OK) return error;
        if (!legacy_boot_flag_address(disable_flag, payload_address, size, gate))
            return KModErr::ERR_MODULE_NOT_KADDR;
    }
    LegacyBootHookHeader header{kLegacyBootHookMagic, output ? 2u : 1u, sizeof(header), function,
        entry, payload_address, 0, size, 0, first, expected};
    std::vector<uint8_t> code, payload;
    uint64_t origin = 0;
    error = legacy_boot_gate(gate, header, code, origin);
    if (error != KModErr::OK) return error;
    if (code.size() > kLegacyBootGateReservationBytes) return KModErr::ERR_MODULE_ASM;
    error = legacy_boot_payload(buffer, size, first, origin, payload);
    if (error != KModErr::OK) return error;
    if (!identity.matches()) return KModErr::ERR_MODULE_ROOT_KEY;
    if (prefix) {
        // The prefix is a read-only pointer after KMP_X. Its target has a
        // separate page-aligned native allocation and remains writable.
        error = write_kernel_mem(payload_address - 8, &disable_flag, sizeof(disable_flag), KernMemProt::KMP_RW);
        if (error != KModErr::OK) return error;
        uint64_t actual_pointer = 0;
        error = read_kernel_mem(payload_address - 8, &actual_pointer, sizeof(actual_pointer));
        if (error != KModErr::OK) return error;
        if (actual_pointer != disable_flag) return KModErr::ERR_MODULE_ASM;
        const uint8_t enabled = 0;
        error = write_kernel_mem(disable_flag, &enabled, sizeof(enabled), KernMemProt::KMP_RW);
        if (error != KModErr::OK) return error;
        uint8_t actual_flag = 1;
        error = read_kernel_mem(disable_flag, &actual_flag, sizeof(actual_flag));
        if (error != KModErr::OK) return error;
        if (actual_flag) return KModErr::ERR_MODULE_ASM;
    }
    error = write_kernel_mem(payload_address, payload.data(), size, KernMemProt::KMP_RW);
    if (error != KModErr::OK) return error;
    error = set_kernel_mem_protection(payload_address - prefix, size + prefix, KernMemProt::KMP_X);
    if (error != KModErr::OK) return error;
    error = write_kernel_mem(gate, code.data(), static_cast<uint32_t>(code.size()), KernMemProt::KMP_X);
    if (error != KModErr::OK) return error;
    std::vector<uint8_t> actual(code.size()), actual_payload(size);
    error = read_kernel_mem(gate, actual.data(), static_cast<uint32_t>(actual.size()));
    if (error != KModErr::OK) return error;
    error = read_kernel_mem(payload_address, actual_payload.data(), size);
    if (error != KModErr::OK) return error;
    if (actual != code || actual_payload != payload) return KModErr::ERR_MODULE_ASM;
    if (!identity.matches()) return KModErr::ERR_MODULE_ROOT_KEY;
    // Allocate and register the handle before the first possible entry write.
    // All errors beyond this boundary return it and retain every dependency.
    legacy_boot_handle(header, gate, disable_flag, identity, output);
    error = legacy_boot_publish(function, entry, first, expected, branch);
    // From this boundary the target may be exposed, including transport errors.
    // No path frees code, restores an unknown word, or converts failure to OK.
    if (error != KModErr::OK) return error;
    uint32_t observed = 0;
    error = read_kernel_mem(entry, &observed, sizeof(observed));
    if (error != KModErr::OK) return error;
    if (observed != branch) return KModErr::ERR_MODULE_ASM;
    return identity.matches() ? KModErr::OK : KModErr::ERR_MODULE_ROOT_KEY;
}
} // namespace
