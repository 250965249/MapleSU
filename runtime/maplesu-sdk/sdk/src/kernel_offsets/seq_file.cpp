// seq_file implementation.
//
#include <fcntl.h>
#include <unistd.h>

#include <cstdint>
#include <vector>

#include "kernel_module_kit_umbrella.h"
#include "maplesu_kernel_layout_private.h"

#include "offset_probe_private.h"
#include "offsets_internal.h"
#include "private_module_tombstone_purge.h"

namespace kernel_module {

namespace {

// Kernel addresses are the pointer values at or above the top of the canonical
// user range; lower values are not kernel pointers.
constexpr uint64_t kKernelAddrMin = 0xFFFF000000000000ULL;

KModErr resolve_seq_btf_offset(const char* member, uint32_t& offset, bool& available) {
    KernelFieldDescription field;
    KModErr error = maplesu_resolve_btf_field("seq_file", member, 8, field, available);
    if (available && is_ok(error)) offset = field.offset_bytes;
    return error;
}

}  // namespace

// Locates the buf field of struct seq_file.  seq_file::buf is the one pointer
// field that is still null right after the file is opened and becomes a kernel
// buffer once the first byte is read, and that buffer starts with the file's
// own first bytes, so the field whose kernel pointer holds the file signature
// is buf.
KModErr get_seq_file_buf_offset(uint32_t& offset) {
    bool available = false;
    KModErr btf_error = resolve_seq_btf_offset("buf", offset, available);
    if (available) return btf_error;

    KModErr err = get_offset_cache("seq_file_buf", offset);
    if (is_ok(err)) {
        return err;  // already cached
    }

    // The first eight bytes of the file are the expected buffer prefix.  An
    // empty prefix means the proc file produced nothing to compare against.
    uint64_t signature = 0;
    const int signature_fd = open("/proc/cmdline", O_RDONLY);
    if (signature_fd < 0) {
        return KModErr::ERR_MODULE_OPEN_FILE;
    }
    read(signature_fd, &signature, sizeof(signature));
    close(signature_fd);
    if (signature == 0) {
        return KModErr::ERR_MODULE_READ_FILE;
    }

    const int cmdline_fd = open("/proc/cmdline", O_RDONLY);
    if (cmdline_fd < 0) {
        return KModErr::ERR_MODULE_OPEN_FILE;
    }
    fd_guard cmdline_guard(cmdline_fd);

    uint64_t file_ptr = 0;
    err = get_current_task_file_ptr(cmdline_guard.get(), file_ptr);
    if (is_failed(err)) {
        return err;
    }

    uint32_t private_data_offset = 0;
    err = get_file_private_data_offset(private_data_offset);
    if (is_failed(err)) {
        return err;
    }

    uint64_t seq_file = 0;
    err = read_kernel_mem(file_ptr + private_data_offset, &seq_file, sizeof(seq_file));
    if (is_failed(err)) {
        return err;
    }
    if (seq_file < kKernelAddrMin) {
        return KModErr::ERR_MODULE_NOT_KADDR;
    }

    std::vector<uint64_t> before_read(8);
    std::vector<uint64_t> after_read(8);
    err = read_kernel_mem(seq_file, before_read.data(), 64);
    if (is_failed(err)) {
        return err;
    }

    unsigned char first_byte = 0;
    if (read(cmdline_guard.get(), &first_byte, 1) != 1) {
        return KModErr::ERR_MODULE_READ_FILE;
    }

    err = read_kernel_mem(seq_file, after_read.data(), 64);
    if (is_failed(err)) {
        return err;
    }

    int match_count = 0;
    uint32_t buf_offset = 0;
    for (size_t i = 0; i < before_read.size(); ++i) {
        if (before_read[i] != 0) {
            continue;
        }
        const uint64_t buffer_ptr = after_read[i];
        if (buffer_ptr < kKernelAddrMin) {
            continue;
        }

        bool read_ok = false;
        uint64_t buffer_prefix = 0;
        err = safe_read_kaddr_t(buffer_ptr, read_ok, buffer_prefix);
        if (is_failed(err)) {
            return err;
        }
        if (!read_ok || buffer_prefix != signature) {
            continue;
        }
        ++match_count;
        buf_offset = static_cast<uint32_t>(i) * 8;
    }

    if (match_count != 1) {
        return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    }
    offset = buf_offset;
    return put_offset_cache("seq_file_buf", buf_offset);
}

// Locates the size field of struct seq_file.  The first read allocates the
// seq_file buffer with its capacity recorded in size and a zero length
// recorded in count; for the field that was still null before the read and
// holds the page size afterwards, that field is size.
KModErr get_seq_file_size_offset(uint32_t& offset) {
    bool available = false;
    KModErr btf_error = resolve_seq_btf_offset("size", offset, available);
    if (available) return btf_error;

    KModErr err = get_offset_cache("seq_file_size", offset);
    if (is_ok(err)) {
        return err;  // already cached
    }

    const uint32_t page_size = get_page_size();

    const int cmdline_fd = open("/proc/cmdline", O_RDONLY);
    if (cmdline_fd < 0) {
        return KModErr::ERR_MODULE_OPEN_FILE;
    }
    fd_guard cmdline_guard(cmdline_fd);

    uint64_t file_ptr = 0;
    err = get_current_task_file_ptr(cmdline_guard.get(), file_ptr);
    if (is_failed(err)) {
        return err;
    }

    uint32_t private_data_offset = 0;
    err = get_file_private_data_offset(private_data_offset);
    if (is_failed(err)) {
        return err;
    }

    uint64_t seq_file = 0;
    err = read_kernel_mem(file_ptr + private_data_offset, &seq_file, sizeof(seq_file));
    if (is_failed(err)) {
        return err;
    }
    if (seq_file < kKernelAddrMin) {
        return KModErr::ERR_MODULE_NOT_KADDR;
    }

    std::vector<uint64_t> before_read(8);
    std::vector<uint64_t> after_read(8);
    err = read_kernel_mem(seq_file, before_read.data(), 64);
    if (is_failed(err)) {
        return err;
    }

    unsigned char first_byte = 0;
    if (read(cmdline_guard.get(), &first_byte, 1) != 1) {
        return KModErr::ERR_MODULE_READ_FILE;
    }

    err = read_kernel_mem(seq_file, after_read.data(), 64);
    if (is_failed(err)) {
        return err;
    }

    int match_count = 0;
    uint32_t size_offset = 0;
    for (size_t i = 0; i < before_read.size(); ++i) {
        if (before_read[i] != 0) {
            continue;
        }
        if (after_read[i] != page_size) {
            continue;
        }
        ++match_count;
        size_offset = static_cast<uint32_t>(i) * 8;
    }

    if (match_count != 1) {
        return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    }
    offset = size_offset;
    return put_offset_cache("seq_file_size", size_offset);
}

// Locates the count field of struct seq_file.  After one read the buffer holds
// the produced bytes; count is the field that was null before the read and
// equals the number of bytes the same file yielded to the caller, while buf and
// size are already identified and skipped.
KModErr get_seq_file_count_offset(uint32_t& offset) {
    bool available = false;
    KModErr btf_error = resolve_seq_btf_offset("count", offset, available);
    if (available) return btf_error;

    KModErr err = get_offset_cache("seq_file_count", offset);
    if (is_ok(err)) {
        return err;  // already cached
    }

    uint32_t buf_offset = 0;
    err = get_seq_file_buf_offset(buf_offset);
    if (is_failed(err)) {
        return err;
    }
    uint32_t size_offset = 0;
    err = get_seq_file_size_offset(size_offset);
    if (is_failed(err)) {
        return err;
    }
    const uint32_t page_size = get_page_size();

    unsigned char content[1024];
    const int content_fd = open("/proc/cmdline", O_RDONLY);
    if (content_fd < 0) {
        return KModErr::ERR_MODULE_OPEN_FILE;
    }
    const uint64_t content_length = static_cast<uint64_t>(read(content_fd, content, sizeof(content)));
    close(content_fd);
    if (static_cast<int32_t>(content_length) < 1) {
        return KModErr::ERR_MODULE_READ_FILE;
    }

    const int cmdline_fd = open("/proc/cmdline", O_RDONLY);
    if (cmdline_fd < 0) {
        return KModErr::ERR_MODULE_OPEN_FILE;
    }
    fd_guard cmdline_guard(cmdline_fd);

    uint64_t file_ptr = 0;
    err = get_current_task_file_ptr(cmdline_guard.get(), file_ptr);
    if (is_failed(err)) {
        return err;
    }

    uint32_t private_data_offset = 0;
    err = get_file_private_data_offset(private_data_offset);
    if (is_failed(err)) {
        return err;
    }

    uint64_t seq_file = 0;
    err = read_kernel_mem(file_ptr + private_data_offset, &seq_file, sizeof(seq_file));
    if (is_failed(err)) {
        return err;
    }
    if (seq_file < kKernelAddrMin) {
        return KModErr::ERR_MODULE_NOT_KADDR;
    }

    std::vector<uint64_t> before_read(8);
    std::vector<uint64_t> after_read(8);
    err = read_kernel_mem(seq_file, before_read.data(), 64);
    if (is_failed(err)) {
        return err;
    }

    unsigned char first_byte = 0;
    if (read(cmdline_guard.get(), &first_byte, 1) != 1) {
        return KModErr::ERR_MODULE_READ_FILE;
    }

    err = read_kernel_mem(seq_file, after_read.data(), 64);
    if (is_failed(err)) {
        return err;
    }

    const size_t buf_index = buf_offset / 8;
    if (before_read[buf_index] != 0 || after_read[buf_index] < kKernelAddrMin) {
        return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    }
    const size_t size_index = size_offset / 8;
    if (before_read[size_index] != 0 || after_read[size_index] != page_size) {
        return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    }

    const uint64_t produced_bytes = static_cast<uint32_t>(content_length);
    const uint64_t produced_bytes_less_one = static_cast<uint32_t>(content_length - 1);

    int match_count = 0;
    uint32_t count_offset = 0;
    for (size_t i = 0; i < before_read.size(); ++i) {
        const uint32_t field_offset = static_cast<uint32_t>(i) * 8;
        if (field_offset == buf_offset || field_offset == size_offset) {
            continue;
        }
        if (before_read[i] != 0) {
            continue;
        }
        if (after_read[i] != produced_bytes && after_read[i] != produced_bytes_less_one) {
            continue;
        }
        ++match_count;
        count_offset = field_offset;
    }

    if (match_count != 1) {
        return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    }
    offset = count_offset;
    return put_offset_cache("seq_file_count", count_offset);
}

}  // namespace kernel_module
