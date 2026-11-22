// gendisk implementation.
//
#include <fcntl.h>
#include <unistd.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "kernel_module_kit_umbrella.h"
#include "maplesu_kernel_layout_private.h"

#include "offset_probe_private.h"
#include "offsets_internal.h"

namespace {

// One block device the discovery pass found under /sys/block: the node path
// below /dev/block and the partition number published in its sysfs directory.
struct PartInfo {
    std::string path;
    uint8_t part_no = 0;
};

// Walks /sys/block and reports the first whole disk that has an accessible
// /dev/block node and at least two partitions whose nodes are accessible too:
// the disk node path is published in device_path and its partitions, with the
// partition numbers read from sysfs, in out_parts.
bool auto_discover_block_devices(std::string& device_path, std::vector<PartInfo>& out_parts) {
    std::string sys_block_dir = "/sys/block/";
    if (!std::filesystem::exists(std::filesystem::path(sys_block_dir))) {
        return false;
    }
    std::vector<PartInfo> parts;
    for (const auto& entry : std::filesystem::directory_iterator(sys_block_dir)) {
        if (!entry.is_directory()) {
            continue;
        }
        std::string disk_name = entry.path().filename();
        if (disk_name.find("loop") != std::string::npos) {
            continue;
        }
        if (disk_name.find("ram") != std::string::npos) {
            continue;
        }
        std::string disk_path = "/dev/block/" + disk_name;
        if (access(disk_path.c_str(), R_OK) != 0) {
            continue;
        }
        for (const auto& part_entry : std::filesystem::directory_iterator(entry.path())) {
            if (!part_entry.is_directory()) {
                continue;
            }
            std::string part_name = part_entry.path().filename();
            if (part_name.find(disk_name) != 0) {
                continue;
            }
            const std::filesystem::path partition_attr = part_entry.path() / "partition";
            if (!std::filesystem::exists(partition_attr)) {
                continue;
            }
            std::ifstream partition_file(partition_attr, std::ios::in);
            int part_no = 0;
            if (!(partition_file >> part_no)) {
                continue;
            }
            std::string part_path = "/dev/block/" + part_name;
            if (access(part_path.c_str(), R_OK) != 0) {
                continue;
            }
            parts.push_back(PartInfo{part_path, static_cast<uint8_t>(part_no)});
        }
        if (parts.size() < 2) {
            continue;
        }
        device_path = disk_path;
        out_parts = parts;
        return true;
    }
    return false;
}

// Finds one block device that does not belong to the disk called disk_name:
// the entry must be a directory under /sys/block whose name does not contain
// the disk name, must report a non-zero size and must have an accessible
// /dev/block node. Its node path is published in out_device.
bool auto_discover_distinct_block_device(const std::string& disk_name, std::string& out_device) {
    std::string sys_block_dir = "/sys/block/";
    if (!std::filesystem::exists(std::filesystem::path(sys_block_dir))) {
        return false;
    }
    for (const auto& entry : std::filesystem::directory_iterator(sys_block_dir)) {
        if (!entry.is_directory()) {
            continue;
        }
        std::string name = entry.path().filename();
        if (name.find(disk_name) != std::string::npos) {
            continue;
        }
        std::ifstream size_file(entry.path() / "size", std::ios::in);
        uint64_t size = 0;
        if (!(size_file >> size) || size == 0) {
            continue;
        }
        std::string device_path = "/dev/block/" + name;
        if (access(device_path.c_str(), R_OK) != 0) {
            continue;
        }
        out_device = device_path;
        return true;
    }
    return false;
}

// Resolves the block_device and inode behind one open descriptor: walks
// current->files->fdt->fd[fd] into the struct file, reads its f_mapping, then
// the address_space host (the inode), and finally asks the kernel for the
// block_device that inode belongs to.
KModErr get_bdev_and_inode(int fd, uint64_t& out_bdev, uint64_t& out_inode) {
    uint32_t f_mapping_offset = 0;
    uint32_t host_offset = 0;
    KModErr err = kernel_module::get_file_f_mapping_offset(f_mapping_offset);
    if (is_failed(err)) {
        return err;
    }
    err = kernel_module::get_address_space_host_offset(host_offset);
    if (is_failed(err)) {
        return err;
    }
    uint64_t file_ptr = 0;
    err = get_current_task_file_ptr(fd, file_ptr);
    if (is_failed(err)) {
        return err;
    }
    uint64_t mapping = 0;
    err = kernel_module::read_kernel_mem(file_ptr + f_mapping_offset, &mapping, sizeof(mapping));
    if (is_failed(err)) {
        return err;
    }
    out_inode = 0;
    err = kernel_module::read_kernel_mem(mapping + host_offset, &out_inode, sizeof(out_inode));
    if (is_failed(err)) {
        return err;
    }
    out_bdev = 0;
    err = get_kernel_shellcode_u64_result(
            [out_inode](asmjit::a64::Assembler* a, asmjit::a64::GpX& result) -> KModErr {
                KModErr call_err = KModErr::ERR_MODULE_PARAM;
                kernel_module::export_symbol::I_BDEV(a, call_err, out_inode);
                if (is_ok(call_err)) {
                    result = asmjit::a64::regs::x0;
                }
                return call_err;
            },
            out_bdev);
    return err;
}

}  // namespace

namespace kernel_module {

// Locates the part0 field of struct gendisk (Linux >= 5.11.0) by reading the
// gendisk two block_devices point at: the whole-disk node of the discovered
// disk and one device from a different disk. The gendisk of a whole-disk
// block_device stores that device in part0, so the single slot whose value is
// the first block_device in the first gendisk and the second block_device in
// the other gendisk is part0.
KModErr get_gendisk_part0_ptr_offset(uint32_t& offset) {
    KernelFieldDescription field;
    bool available = false;
    KModErr btf_error = maplesu_resolve_btf_field("gendisk", "part0", 8, field, available);
    if (available) {
        if (is_ok(btf_error)) offset = field.offset_bytes;
        return btf_error;
    }
    if (is_kernel_version_less("5.11.0")) {
        return KModErr::ERR_MODULE_OFFSET_NOT_MATCH_LINUX_VER;
    }

    std::string device_path;
    std::vector<PartInfo> parts;
    if (!auto_discover_block_devices(device_path, parts)) {
        return KModErr::ERR_MODULE_OPEN_FILE;
    }

    const std::string disk_name = std::filesystem::path(device_path).filename();
    std::string other_device_path;
    if (!auto_discover_distinct_block_device(disk_name, other_device_path)) {
        return KModErr::ERR_MODULE_OPEN_FILE;
    }

    const int disk_fd = open(device_path.c_str(), O_RDONLY);
    const int other_fd = open(other_device_path.c_str(), O_RDONLY);
    fd_guard disk_guard(disk_fd);
    fd_guard other_guard(other_fd);
    if (disk_fd < 0 || other_fd < 0) {
        return KModErr::ERR_MODULE_OPEN_FILE;
    }

    uint64_t bdev_disk = 0;
    uint64_t bdev_other = 0;
    uint64_t inode_disk = 0;
    uint64_t inode_other = 0;
    RETURN_IF_ERROR(get_bdev_and_inode(disk_fd, bdev_disk, inode_disk));
    RETURN_IF_ERROR(get_bdev_and_inode(other_fd, bdev_other, inode_other));
    if (!bdev_disk || !bdev_other) {
        return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    }

    uint32_t bd_disk_offset = 0;
    RETURN_IF_ERROR(get_block_device_bd_disk_offset(bd_disk_offset));
    uint64_t gendisk = 0;
    uint64_t other_gendisk = 0;
    RETURN_IF_ERROR(read_kernel_mem(bdev_disk + bd_disk_offset, &gendisk, sizeof(gendisk)));
    RETURN_IF_ERROR(
            read_kernel_mem(bdev_other + bd_disk_offset, &other_gendisk, sizeof(other_gendisk)));
    if (!gendisk || !other_gendisk) {
        return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    }

    constexpr size_t kGendiskProbeSize = 1024;
    std::vector<uint8_t> gendisk_bytes(kGendiskProbeSize);
    std::vector<uint8_t> other_bytes(kGendiskProbeSize);
    RETURN_IF_ERROR(read_kernel_mem(gendisk, gendisk_bytes.data(), kGendiskProbeSize));
    RETURN_IF_ERROR(read_kernel_mem(other_gendisk, other_bytes.data(), kGendiskProbeSize));

    offset = 0;
    int32_t found_count = 0;
    for (size_t i = 0; i + sizeof(uint64_t) < kGendiskProbeSize; i += sizeof(uint64_t)) {
        const uint64_t part0_slot = *reinterpret_cast<const uint64_t*>(gendisk_bytes.data() + i);
        if (part0_slot != bdev_disk) {
            continue;
        }
        const uint64_t other_slot = *reinterpret_cast<const uint64_t*>(other_bytes.data() + i);
        if (other_slot != bdev_other) {
            continue;
        }
        offset = static_cast<uint32_t>(i);
        ++found_count;
    }
    return found_count == 1 ? KModErr::OK : KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
}

// Locates the part0 field of struct gendisk (Linux < 5.11.0) by reading the
// gendisk two block_devices point at: the whole-disk node of the discovered
// disk and one device from a different disk. Below 5.11.0 part0 is an
// embedded hd_struct, so the slot that holds the disk size in the first
// gendisk and the other device's size in the second one, preceded by a zero
// start sector in both, is part0.
KModErr get_gendisk_part0_offset(uint32_t& offset) {
    KernelFieldDescription field;
    bool available = false;
    KModErr btf_error = maplesu_resolve_btf_field("gendisk", "part0", 0, field, available);
    if (available) {
        if (is_failed(btf_error)) return btf_error;
        KernelFieldDescription start_sector;
        bool nested_available = false;
        btf_error = maplesu_resolve_btf_field("gendisk", "part0.start_sect", 8, start_sector, nested_available);
        if (is_ok(btf_error) && nested_available) offset = field.offset_bytes;
        return btf_error;
    }
    if (!is_kernel_version_less("5.11.0")) {
        return KModErr::ERR_MODULE_OFFSET_NOT_MATCH_LINUX_VER;
    }

    std::string device_path;
    std::vector<PartInfo> parts;
    if (!auto_discover_block_devices(device_path, parts)) {
        return KModErr::ERR_MODULE_OPEN_FILE;
    }

    const std::string disk_name = std::filesystem::path(device_path).filename();
    std::string other_device_path;
    if (!auto_discover_distinct_block_device(disk_name, other_device_path)) {
        return KModErr::ERR_MODULE_OPEN_FILE;
    }
    const std::string other_name = std::filesystem::path(other_device_path).filename();

    auto read_size_sectors = [](const std::string& name) -> uint64_t {
        std::string size_path = "/sys/block/" + name + "/size";
        std::ifstream size_file(size_path, std::ios::in);
        uint64_t size = 0;
        if (size_file >> size) {
            return size;
        }
        return 0;
    };
    const uint64_t disk_size = read_size_sectors(disk_name);
    const uint64_t other_size = read_size_sectors(other_name);
    if (disk_size == 0 || other_size == 0 || disk_size == other_size) {
        return KModErr::ERR_MODULE_OPEN_FILE;
    }

    const int disk_fd = open(device_path.c_str(), O_RDONLY);
    const int other_fd = open(other_device_path.c_str(), O_RDONLY);
    fd_guard disk_guard(disk_fd);
    fd_guard other_guard(other_fd);
    if (disk_fd < 0 || other_fd < 0) {
        return KModErr::ERR_MODULE_OPEN_FILE;
    }

    uint64_t bdev_disk = 0;
    uint64_t bdev_other = 0;
    uint64_t inode_disk = 0;
    uint64_t inode_other = 0;
    RETURN_IF_ERROR(get_bdev_and_inode(disk_fd, bdev_disk, inode_disk));
    RETURN_IF_ERROR(get_bdev_and_inode(other_fd, bdev_other, inode_other));
    if (!bdev_disk || !bdev_other) {
        return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    }

    uint32_t bd_disk_offset = 0;
    RETURN_IF_ERROR(get_block_device_bd_disk_offset(bd_disk_offset));
    uint64_t gendisk = 0;
    uint64_t other_gendisk = 0;
    RETURN_IF_ERROR(read_kernel_mem(bdev_disk + bd_disk_offset, &gendisk, sizeof(gendisk)));
    RETURN_IF_ERROR(
            read_kernel_mem(bdev_other + bd_disk_offset, &other_gendisk, sizeof(other_gendisk)));
    if (!gendisk || !other_gendisk) {
        return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    }

    constexpr size_t kGendiskProbeSize = 2048;
    std::vector<uint8_t> gendisk_bytes(kGendiskProbeSize);
    std::vector<uint8_t> other_bytes(kGendiskProbeSize);
    RETURN_IF_ERROR(read_kernel_mem(gendisk, gendisk_bytes.data(), kGendiskProbeSize));
    RETURN_IF_ERROR(read_kernel_mem(other_gendisk, other_bytes.data(), kGendiskProbeSize));

    offset = 0;
    int32_t found_count = 0;
    for (size_t i = sizeof(uint64_t); i + sizeof(uint64_t) < kGendiskProbeSize;
         i += sizeof(uint64_t)) {
        const uint64_t sectors_slot =
                *reinterpret_cast<const uint64_t*>(gendisk_bytes.data() + i);
        if (sectors_slot != disk_size) {
            continue;
        }
        const uint64_t other_sectors_slot =
                *reinterpret_cast<const uint64_t*>(other_bytes.data() + i);
        if (other_sectors_slot != other_size) {
            continue;
        }
        const size_t start_index = i - sizeof(uint64_t);
        const uint64_t start_slot =
                *reinterpret_cast<const uint64_t*>(gendisk_bytes.data() + start_index);
        const uint64_t other_start_slot =
                *reinterpret_cast<const uint64_t*>(other_bytes.data() + start_index);
        if (start_slot != 0 || other_start_slot != 0) {
            continue;
        }
        offset = static_cast<uint32_t>(start_index);
        ++found_count;
    }
    return found_count == 1 ? KModErr::OK : KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
}

}  // namespace kernel_module
