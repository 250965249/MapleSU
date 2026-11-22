// address_space implementation.
//
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <sstream>
#include <string>
#include <vector>

#include "kernel_module_kit_umbrella.h"
#include "maplesu_kernel_layout_private.h"

#include "offset_probe_private.h"
#include "offsets_internal.h"
#include "private_module_tombstone_purge.h"
#include "private_maplesu_paths.h"

namespace kernel_module {

namespace {

// Kernel addresses live at or above the top of the canonical user range; a lower
// value is not a kernel pointer and cannot be dereferenced by a probe.
constexpr uint64_t kKernelAddrMin = 0xFFFF000000000000ULL;

// One address_space snapshot covers the first kilobyte of the structure, which
// is where the host pointer and the i_mmap tree root live.
constexpr uint32_t kAddressSpaceSnapshotSize = 1024;

// Number of aligned pointer slots one i_mmap comparison snapshot reads.
constexpr uint64_t kMmapSlotCount = 64;

} // namespace

// Builds the path of one probe file: "temp<index>" followed by a fixed marker,
// placed inside the module's system-file directory under /data.
static std::string get_temp_file_path(int index) {
    std::stringstream name_stream;
    name_stream << "temp" << index << "FGfl8qvOMwWQXWyYy9b00sY8VnXh0rVM";

    return (std::filesystem::path(maplesu::sdk::get_system_file_dir_path()) / name_stream.str())
        .string();
}

// Creates/recreates the two probe files: each is opened read-write, truncated to
// a distinct length and labelled system_file so the kernel side can read it and
// map it.
static KModErr init_offset_test_file() {
    for (uint64_t idx = 0; idx != 2; ++idx) {
        const std::string path = get_temp_file_path(static_cast<int>(idx));
        const int raw_fd = open(path.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0666);
        fd_guard fd{raw_fd};
        if (raw_fd < 0) {
            return KModErr::ERR_MODULE_CREATE_EMPTY_FILE;
        }
        if (ftruncate(fd.get(), static_cast<off_t>(idx + 4660)) != 0) {
            return KModErr::ERR_MODULE_WRITE_FILE;
        }
        const char *file_path = path.c_str();
        if (chmod(file_path, 0777) != 0) {
            return KModErr::ERR_SET_FILE_SELINUX;
        }
        if (setxattr(file_path, "security.selinux", "u:object_r:system_file:s0", 26, 0) != 0) {
            return KModErr::ERR_SET_FILE_SELINUX;
        }
    }
    return KModErr::OK;
}

// Locates the host field of struct address_space.  host points back at the inode
// that owns the mapping, so the field is the pointer slot that holds the probe
// file's inode address in the address_space of both probe files.
KModErr get_address_space_host_offset(uint32_t &offset) {
    KernelFieldDescription field;
    bool available = false;
    KModErr btf_error = maplesu_resolve_btf_field("address_space", "host", 8, field, available);
    if (available) {
        if (is_ok(btf_error)) offset = field.offset_bytes;
        return btf_error;
    }

    KModErr err = get_offset_cache("address_space_host", offset);
    if (is_ok(err)) {
        return err;
    }

    uint32_t i_mapping_offset = 0;
    err = get_inode_i_mapping_offset(i_mapping_offset);
    if (is_failed(err)) {
        return err;
    }

    RETURN_IF_ERROR(init_offset_test_file());

    std::string probe_path = get_temp_file_path(0);
    std::string other_path = get_temp_file_path(1);

    fd_guard probe_fd(open(probe_path.c_str(), O_RDONLY));
    fd_guard other_fd(open(other_path.c_str(), O_RDONLY));
    if (probe_fd.get() < 0 || other_fd.get() < 0) {
        return KModErr::ERR_MODULE_OPEN_FILE;
    }

    scoped_kpath probe_kp{};
    scoped_kpath other_kp{};
    RETURN_IF_ERROR(acquire_kpath(probe_path, probe_kp));
    RETURN_IF_ERROR(acquire_kpath(other_path, other_kp));

    uint32_t d_inode_offset = 0;
    RETURN_IF_ERROR(get_dentry_d_inode_offset(d_inode_offset));

    uint64_t probe_inode = 0;
    uint64_t other_inode = 0;
    RETURN_IF_ERROR(
        read_kernel_mem(probe_kp.kp.dentry + d_inode_offset, &probe_inode, sizeof(probe_inode)));
    RETURN_IF_ERROR(
        read_kernel_mem(other_kp.kp.dentry + d_inode_offset, &other_inode, sizeof(other_inode)));

    uint64_t probe_mapping = 0;
    uint64_t other_mapping = 0;
    RETURN_IF_ERROR(
        read_kernel_mem(probe_inode + i_mapping_offset, &probe_mapping, sizeof(probe_mapping)));
    RETURN_IF_ERROR(
        read_kernel_mem(other_inode + i_mapping_offset, &other_mapping, sizeof(other_mapping)));

    for (uint64_t slot = 0; slot < 256; slot += 8) {
        uint64_t probe_host = 0;
        uint64_t other_host = 0;
        bool probe_ok = false;
        bool other_ok = false;
        RETURN_IF_ERROR(safe_read_kaddr_t(probe_mapping + slot, probe_ok, probe_host));
        RETURN_IF_ERROR(safe_read_kaddr_t(other_mapping + slot, other_ok, other_host));
        if (!probe_ok) {
            continue;
        }
        if (probe_host != probe_inode || !other_ok) {
            continue;
        }
        if (other_host != other_inode) {
            continue;
        }
        offset = static_cast<uint32_t>(slot);
        return put_offset_cache("address_space_host", offset);
    }
    return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
}

// Locates the i_mmap field of struct address_space.  i_mmap is the cached
// interval-tree root that gains a node once a file mapping exists: right after
// the probe file is mapped its root pointer and leftmost pointer both name the
// same new node, while before the mapping both slots were zero.
KModErr get_address_space_i_mmap_offset(uint32_t &offset) {
    KernelFieldDescription field;
    bool available = false;
    KModErr btf_error = maplesu_resolve_btf_field("address_space", "i_mmap", 0, field, available);
    if (available) {
        if (is_ok(btf_error)) offset = field.offset_bytes;
        return btf_error;
    }

    KModErr err = get_offset_cache("address_space_i_mmap", offset);
    if (is_ok(err)) {
        return err;
    }

    err = init_offset_test_file();
    if (is_failed(err)) {
        return err;
    }

    std::string probe_path = get_temp_file_path(0);
    const int probe_raw_fd = open(probe_path.c_str(), O_RDWR);
    if (probe_raw_fd < 0) {
        return KModErr::ERR_MODULE_OPEN_FILE;
    }
    fd_guard probe_fd(probe_raw_fd);

    const uint32_t page_size = get_page_size();

    uint64_t file_ptr = 0;
    RETURN_IF_ERROR(get_current_task_file_ptr(probe_raw_fd, file_ptr));

    uint32_t f_mapping_offset = 0;
    RETURN_IF_ERROR(get_file_f_mapping_offset(f_mapping_offset));

    uint64_t mapping_ptr = 0;
    RETURN_IF_ERROR(
        read_kernel_mem(file_ptr + f_mapping_offset, &mapping_ptr, sizeof(mapping_ptr)));
    if (mapping_ptr < kKernelAddrMin) {
        return KModErr::ERR_MODULE_NOT_KADDR;
    }

    const uint32_t snapshot_bytes = static_cast<uint32_t>(kMmapSlotCount * sizeof(uint64_t));
    std::vector<uint64_t> before_map(kMmapSlotCount);
    std::vector<uint64_t> after_map(kMmapSlotCount);
    RETURN_IF_ERROR(read_kernel_mem(mapping_ptr, before_map.data(), snapshot_bytes));

    void *user_mapping =
        mmap(nullptr, page_size, PROT_READ | PROT_WRITE, MAP_SHARED, probe_raw_fd, 0);
    if (user_mapping == MAP_FAILED) {
        return KModErr::ERR_MODULE_MMAP;
    }
    mmap_guard user_mapping_guard(user_mapping, page_size);
    RETURN_IF_ERROR(read_kernel_mem(mapping_ptr, after_map.data(), snapshot_bytes));

    uint32_t mapped_offset = 0;
    int match_count = 0;
    for (uint64_t slot = 0; slot != before_map.size() - 1; ++slot) {
        if (before_map[slot] != 0 || before_map[slot + 1] != 0) {
            continue;
        }
        if (after_map[slot] < kKernelAddrMin) {
            continue;
        }
        if (after_map[slot] == after_map[slot + 1]) {
            mapped_offset = static_cast<uint32_t>(slot) << 3;
            ++match_count;
        }
    }
    if (match_count != 1) {
        return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    }
    offset = mapped_offset;
    return put_offset_cache("address_space_i_mmap", mapped_offset);
}

} // namespace kernel_module
