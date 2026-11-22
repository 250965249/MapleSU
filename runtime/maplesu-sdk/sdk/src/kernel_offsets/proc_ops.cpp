// proc_ops implementation.
//
#include <fcntl.h>
#include <poll.h>
#include <sys/mman.h>
#include <unistd.h>

#include <cstdint>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

#include "kernel_module_kit_umbrella.h"
#include "maplesu_kernel_layout_private.h"

#include "offset_probe_private.h"

namespace kernel_module {

// True while at least one of the seven field offsets is still missing.
static bool is_empty(const proc_ops_offsets& offsets) {
    const uint32_t* field = reinterpret_cast<const uint32_t*>(&offsets);
    uint64_t index = 0;
    while (index < 7 && field[index] != 0) {
        ++index;
    }
    return index < 7;
}

namespace {

// "BTI c": proc_ops callbacks are entered through an indirect branch, so each
// emitted callback starts with a branch-target landing pad.
constexpr uint32_t kBranchTargetIdentifyCall = 0xD503245F;

// Number of 8-byte slots in the temporary proc_ops table.  The table is long
// enough to cover all seven callback fields of any supported kernel.
constexpr uint32_t kProbeSlotCount = 32;

KModErr resolve_proc_ops_btf(proc_ops_offsets& offsets, bool& available) {
    const struct {
        const char* name;
        uint32_t proc_ops_offsets::*offset;
    } members[] = {
        {"proc_open", &proc_ops_offsets::proc_open_offset},
        {"proc_read", &proc_ops_offsets::proc_read_offset},
        {"proc_write", &proc_ops_offsets::proc_write_offset},
        {"proc_lseek", &proc_ops_offsets::proc_lseek_offset},
        {"proc_release", &proc_ops_offsets::proc_release_offset},
        {"proc_poll", &proc_ops_offsets::proc_poll_offset},
        {"proc_mmap", &proc_ops_offsets::proc_mmap_offset},
    };
    proc_ops_offsets resolved;
    uint32_t owner_size = 0;
    for (const auto& member : members) {
        KernelFieldDescription field;
        bool field_available = false;
        KModErr error = maplesu_resolve_btf_field("proc_ops", member.name, 8, field, field_available);
        if (!owner_size) available = field_available;
        if (is_failed(error)) return error;
        if (!field_available || (owner_size && owner_size != field.owner_size_bytes))
            return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
        owner_size = field.owner_size_bytes;
        resolved.*member.offset = field.offset_bytes;
    }
    offsets = resolved;
    return KModErr::OK;
}

// Emits the callback used for one table slot: it stores its own slot offset in
// the marker cell and returns 0, so the kernel invocation of a slot publishes
// that slot's offset for the resolver to read back.
std::vector<uint8_t> emit_slot_recorder(uint64_t marker_kaddr, uint32_t slot_offset) {
    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    asmjit::a64::Assembler* a = asm_ctx.assembler();
    a->embed(&kBranchTargetIdentifyCall, sizeof(kBranchTargetIdentifyCall));
    aarch64_asm_mov_x(a, asmjit::a64::regs::x0, marker_kaddr);
    aarch64_asm_mov_w(a, asmjit::a64::regs::w1, slot_offset);
    a->str(asmjit::a64::regs::w1, asmjit::a64::ptr(asmjit::a64::regs::x0));
    a->mov(asmjit::a64::regs::x0, asmjit::a64::regs::xzr);
    a->ret(asmjit::a64::regs::x30);
    return aarch64_asm_to_bytes(a);
}

}  // namespace

// Resolves the seven callback field offsets of struct proc_ops (Linux 5.6.0 and
// newer).  A temporary proc entry is registered with a callback table whose
// slots each record their own offset when invoked; opening, reading, writing,
// seeking, polling, mapping and closing the entry then invokes the kernel's
// callbacks and each read-back marker tells which table slot that operation
// used, i.e. the offset of the corresponding proc_ops field.
KModErr get_proc_ops_offsets(proc_ops_offsets& offsets) {
    bool available = false;
    KModErr btf_error = resolve_proc_ops_btf(offsets, available);
    if (available) return btf_error;

    if (is_kernel_version_less("5.6.0")) {
        return KModErr::ERR_MODULE_OFFSET_NOT_MATCH_LINUX_VER;
    }

    proc_ops_offsets cached;

    std::vector<uint64_t> owned_kaddrs;
    std::vector<std::pair<uint64_t, uint64_t>> executable_ranges;

    // Marker cell: the invoked callback writes its slot offset here.
    uint64_t marker_kaddr = 0;
    KModErr err = alloc_kernel_mem(4, marker_kaddr);
    if (is_failed(err)) {
        return err;
    }
    owned_kaddrs.push_back(marker_kaddr);
    err = fill00_kernel_mem(marker_kaddr, 4, KernMemProt::KMP_RW);
    if (is_failed(err)) {
        return err;
    }

    // One executable recorder per slot.
    std::vector<uint64_t> callbacks;
    callbacks.reserve(kProbeSlotCount);
    for (uint32_t slot = 0; slot < kProbeSlotCount; ++slot) {
        const std::vector<uint8_t> code = emit_slot_recorder(marker_kaddr, slot * 8);
        if (code.empty()) {
            return KModErr::ERR_MODULE_ASM;
        }
        uint64_t code_kaddr = 0;
        err = alloc_kernel_mem(static_cast<uint32_t>(code.size()), code_kaddr);
        if (is_failed(err)) {
            return err;
        }
        owned_kaddrs.push_back(code_kaddr);
        err = write_kernel_mem(code_kaddr, code.data(), static_cast<uint32_t>(code.size()),
                               KernMemProt::KMP_RW);
        if (is_failed(err)) {
            return err;
        }
        err = set_kernel_mem_protection(code_kaddr, code.size(), KernMemProt::KMP_X);
        if (is_failed(err)) {
            return err;
        }
        executable_ranges.push_back({code_kaddr, code.size()});
        callbacks.push_back(code_kaddr);
    }

    // Temporary callback table addressed like a struct proc_ops: slot i holds
    // the recorder for slot i.
    uint64_t fake_ops_kaddr = 0;
    const uint32_t ops_bytes =
            static_cast<uint32_t>(callbacks.size() * sizeof(uint64_t)) & ~static_cast<uint32_t>(7);
    err = alloc_kernel_mem(ops_bytes, fake_ops_kaddr);
    if (is_failed(err)) {
        return err;
    }
    owned_kaddrs.push_back(fake_ops_kaddr);
    err = write_kernel_mem(fake_ops_kaddr, callbacks.data(), ops_bytes, KernMemProt::KMP_RW);
    if (is_failed(err)) {
        return err;
    }

    // Register /proc/<random name> with the temporary table.  proc_create()
    // returns the directory entry that proc_remove() later consumes.
    const std::string proc_name = random_utils::generate_random_str(32);
    uint64_t proc_entry = 0;
    err = get_kernel_shellcode_u64_result(
            [proc_name, fake_ops_kaddr](asmjit::a64::Assembler* a,
                                         asmjit::a64::GpX& result) -> KModErr {
                KModErr call_err = KModErr::OK;
                aarch64_asm_set_x_cstr_ptr(a, asmjit::a64::regs::x10, proc_name);
                aarch64_asm_mov_w(a, asmjit::a64::regs::w11, 0600);
                a->mov(asmjit::a64::regs::x12, asmjit::a64::regs::xzr);
                aarch64_asm_mov_x(a, asmjit::a64::regs::x13, fake_ops_kaddr);
                export_symbol::linux_above_5_6_0::proc_create(
                        a, call_err, asmjit::a64::regs::x10, asmjit::a64::regs::w11,
                        asmjit::a64::regs::x12, asmjit::a64::regs::x13);
                if (is_ok(call_err)) {
                    result = asmjit::a64::regs::x0;
                }
                return call_err;
            },
            proc_entry);
    if (is_failed(err)) {
        return err;
    }

    const uint32_t zero = 0;
    const std::string proc_path = "/proc/" + proc_name;
    fd_guard proc_fd(open(proc_path.c_str(), O_RDWR));

    // open() invokes proc_ops::proc_open.
    err = read_kernel_mem(marker_kaddr, &cached.proc_open_offset, 4);
    if (is_failed(err)) {
        return err;
    }
    err = write_kernel_mem(marker_kaddr, &zero, 4, KernMemProt::KMP_RW);
    if (is_failed(err)) {
        return err;
    }

    // read() invokes proc_ops::proc_read.
    unsigned char probe_byte = 0;
    (void)read(proc_fd.get(), &probe_byte, 1);
    err = read_kernel_mem(marker_kaddr, &cached.proc_read_offset, 4);
    if (is_failed(err)) {
        return err;
    }
    err = fill00_kernel_mem(marker_kaddr, 4, KernMemProt::KMP_RW);
    if (is_failed(err)) {
        return err;
    }

    // write() invokes proc_ops::proc_write.
    (void)write(proc_fd.get(), &probe_byte, 1);
    err = read_kernel_mem(marker_kaddr, &cached.proc_write_offset, 4);
    if (is_failed(err)) {
        return err;
    }
    err = fill00_kernel_mem(marker_kaddr, 4, KernMemProt::KMP_RW);
    if (is_failed(err)) {
        return err;
    }

    // lseek() invokes proc_ops::proc_lseek.
    (void)lseek(proc_fd.get(), 0, SEEK_SET);
    err = read_kernel_mem(marker_kaddr, &cached.proc_lseek_offset, 4);
    if (is_failed(err)) {
        return err;
    }
    err = fill00_kernel_mem(marker_kaddr, 4, KernMemProt::KMP_RW);
    if (is_failed(err)) {
        return err;
    }

    // poll() invokes proc_ops::proc_poll.
    struct pollfd probe_poll = {};
    probe_poll.fd = proc_fd.get();
    probe_poll.events = POLLIN;
    (void)poll(&probe_poll, 1, 0);
    err = read_kernel_mem(marker_kaddr, &cached.proc_poll_offset, 4);
    if (is_failed(err)) {
        return err;
    }
    err = fill00_kernel_mem(marker_kaddr, 4, KernMemProt::KMP_RW);
    if (is_failed(err)) {
        return err;
    }

    // mmap() invokes proc_ops::proc_mmap.
    mmap_guard probe_mapping(mmap(nullptr, 4096, PROT_READ, MAP_PRIVATE, proc_fd.get(), 0), 4096);
    err = read_kernel_mem(marker_kaddr, &cached.proc_mmap_offset, 4);
    if (is_failed(err)) {
        return err;
    }
    err = fill00_kernel_mem(marker_kaddr, 4, KernMemProt::KMP_RW);
    if (is_failed(err)) {
        return err;
    }

    // close() invokes proc_ops::proc_release.  The descriptor is closed here
    // explicitly because that is what triggers the callback; the guard is
    // disarmed so it does not close the number a second time.
    (void)close(proc_fd.get());
    proc_fd.fd_ = -1;
    err = read_kernel_mem(marker_kaddr, &cached.proc_release_offset, 4);
    if (is_failed(err)) {
        return err;
    }
    err = fill00_kernel_mem(marker_kaddr, 4, KernMemProt::KMP_RW);
    if (is_failed(err)) {
        return err;
    }

    // Unregister the probe entry and free its directory entry.
    err = exec_kernel_shellcode_no_result([proc_entry](asmjit::a64::Assembler* a) -> KModErr {
        KModErr call_err = KModErr::OK;
        aarch64_asm_mov_x(a, asmjit::a64::regs::x10, proc_entry);
        export_symbol::proc_remove(a, call_err, asmjit::a64::regs::x10);
        return call_err;
    });
    if (is_failed(err)) {
        return err;
    }

    // The recorder pages are executable no more; make them writable again and
    // release every kernel page the probe owned.
    for (const std::pair<uint64_t, uint64_t>& range : executable_ranges) {
        err = set_kernel_mem_protection(range.first, range.second, KernMemProt::KMP_RW);
        if (is_failed(err)) {
            return err;
        }
    }
    for (uint64_t kaddr : owned_kaddrs) {
        err = free_kernel_mem(kaddr);
        if (is_failed(err)) {
            return err;
        }
    }

    if (is_empty(cached)) {
        return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    }

    memcpy(&offsets, &cached, sizeof(offsets));
    return KModErr::OK;
}

}  // namespace kernel_module
