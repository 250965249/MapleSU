// block_device implementation.
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

// Locates the bd_part field of struct block_device (Linux < 5.11.0) by
// comparing three block_devices that belong to the same disk: the whole-disk
// node and two of its partitions. Each slot that looks like a kernel pointer is
// dereferenced and the three pointees are inspected for the hd_struct start
// sector of each device (0 for the whole disk, the sysfs start of each
// partition); the single slot whose pointees carry exactly those start sectors
// is bd_part.
KModErr get_block_device_bd_part_offset(uint32_t& offset) {
    KernelFieldDescription field;
    bool available = false;
    KModErr btf_error = maplesu_resolve_btf_field("block_device", "bd_part", 8, field, available);
    if (available) {
        if (is_ok(btf_error)) offset = field.offset_bytes;
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

    PartInfo part0 = parts[0];
    PartInfo part1 = parts[1];
    auto read_start_sector = [](const std::string& node_path) -> uint64_t {
        std::string name = std::filesystem::path(node_path).filename();
        std::string start_path = "/sys/class/block/" + name + "/start";
        std::ifstream start_file(start_path, std::ios::in);
        uint64_t start = 0;
        if (start_file >> start) {
            return start;
        }
        return 0;
    };
    uint64_t part0_start = read_start_sector(part0.path);
    uint64_t part1_start = read_start_sector(part1.path);

    const int disk_fd = open(device_path.c_str(), O_RDONLY);
    const int part0_fd = open(part0.path.c_str(), O_RDONLY);
    const int part1_fd = open(part1.path.c_str(), O_RDONLY);
    fd_guard disk_guard(disk_fd);
    fd_guard part0_guard(part0_fd);
    fd_guard part1_guard(part1_fd);
    if (disk_fd < 0 || part0_fd < 0 || part1_fd < 0) {
        return KModErr::ERR_MODULE_OPEN_FILE;
    }

    uint64_t bdev_disk = 0;
    uint64_t bdev_part0 = 0;
    uint64_t bdev_part1 = 0;
    uint64_t inode_disk = 0;
    uint64_t inode_part0 = 0;
    uint64_t inode_part1 = 0;
    RETURN_IF_ERROR(get_bdev_and_inode(disk_fd, bdev_disk, inode_disk));
    RETURN_IF_ERROR(get_bdev_and_inode(part0_fd, bdev_part0, inode_part0));
    RETURN_IF_ERROR(get_bdev_and_inode(part1_fd, bdev_part1, inode_part1));
    if (!bdev_disk || !bdev_part0 || !bdev_part1) {
        return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    }

    constexpr size_t kBlockDeviceProbeSize = 1024;
    std::vector<uint8_t> disk_bytes(kBlockDeviceProbeSize);
    std::vector<uint8_t> part0_bytes(kBlockDeviceProbeSize);
    std::vector<uint8_t> part1_bytes(kBlockDeviceProbeSize);
    RETURN_IF_ERROR(read_kernel_mem(bdev_disk, disk_bytes.data(), kBlockDeviceProbeSize));
    RETURN_IF_ERROR(read_kernel_mem(bdev_part0, part0_bytes.data(), kBlockDeviceProbeSize));
    RETURN_IF_ERROR(read_kernel_mem(bdev_part1, part1_bytes.data(), kBlockDeviceProbeSize));

    constexpr uint64_t kKernelPointerMin = 0xFFFF000000000000ull;
    offset = 0;
    int32_t found_count = 0;
    uint64_t scan_error = 0;
    constexpr size_t kObjectWordCount = 64;
    constexpr size_t kObjectReadSize = kObjectWordCount * sizeof(uint64_t);
    size_t i = 0;
    for (; i + sizeof(uint64_t) < kBlockDeviceProbeSize; i += sizeof(uint64_t)) {
        const uint64_t disk_slot = *reinterpret_cast<const uint64_t*>(disk_bytes.data() + i);
        const uint64_t part0_slot = *reinterpret_cast<const uint64_t*>(part0_bytes.data() + i);
        const uint64_t part1_slot = *reinterpret_cast<const uint64_t*>(part1_bytes.data() + i);
        if (disk_slot < kKernelPointerMin) {
            continue;
        }
        if (disk_slot == part0_slot || part0_slot == part1_slot || disk_slot == part1_slot) {
            continue;
        }
        if (disk_slot == bdev_disk) {
            continue;
        }
        if (disk_slot >= bdev_disk && disk_slot < bdev_disk + kBlockDeviceProbeSize) {
            continue;
        }
        if (part0_slot >= bdev_part0 && part0_slot < bdev_part0 + kBlockDeviceProbeSize) {
            continue;
        }
        if (part1_slot >= bdev_part1 && part1_slot < bdev_part1 + kBlockDeviceProbeSize) {
            continue;
        }

        std::vector<uint64_t> disk_object(kObjectWordCount);
        std::vector<uint64_t> part0_object(kObjectWordCount);
        std::vector<uint64_t> part1_object(kObjectWordCount);
        bool read_ok = false;
        {
            KModErr read_err =
                    safe_read_kaddr(disk_slot, read_ok, disk_object.data(), kObjectReadSize);
            scan_error = is_failed(read_err) ? static_cast<uint64_t>(read_err) : scan_error;
            if (is_failed(read_err)) {
                break;
            }
            if (!read_ok) {
                continue;
            }
        }
        {
            KModErr read_err =
                    safe_read_kaddr(part0_slot, read_ok, part0_object.data(), kObjectReadSize);
            scan_error = is_failed(read_err) ? static_cast<uint64_t>(read_err) : scan_error;
            if (is_failed(read_err)) {
                break;
            }
            if (!read_ok) {
                continue;
            }
        }
        {
            KModErr read_err =
                    safe_read_kaddr(part1_slot, read_ok, part1_object.data(), kObjectReadSize);
            scan_error = is_failed(read_err) ? static_cast<uint64_t>(read_err) : scan_error;
            if (is_failed(read_err)) {
                break;
            }
            if (!read_ok) {
                continue;
            }
        }
        for (size_t j = 0; j < disk_object.size(); ++j) {
            if (disk_object[j] == 0 && part0_object[j] == part0_start &&
                part1_object[j] == part1_start) {
                offset = static_cast<uint32_t>(i);
                ++found_count;
                break;
            }
        }
    }
    if (i + sizeof(uint64_t) < kBlockDeviceProbeSize) {
        return static_cast<KModErr>(scan_error);
    }
    return found_count == 1 ? KModErr::OK : KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
}

// Locates the bd_disk field of struct block_device by reading the
// block_devices of two devices that live on different disks: the whole-disk
// node of the discovered disk and one device of another disk. Every slot that
// holds a kernel pointer is dereferenced and its pointee is searched for the
// disk name, which identifies a gendisk; the single slot whose pointee on the
// first device contains that name is bd_disk.
KModErr get_block_device_bd_disk_offset(uint32_t& offset) {
    KernelFieldDescription field;
    bool available = false;
    KModErr btf_error = maplesu_resolve_btf_field("block_device", "bd_disk", 8, field, available);
    if (available) {
        if (is_ok(btf_error)) offset = field.offset_bytes;
        return btf_error;
    }
    std::string device_path;
    std::vector<PartInfo> parts;
    if (!auto_discover_block_devices(device_path, parts)) {
        return KModErr::ERR_MODULE_OPEN_FILE;
    }

    const std::string part0_path = parts[0].path;
    std::string other_device_path;
    const std::string disk_name = std::filesystem::path(device_path).filename();
    if (!auto_discover_distinct_block_device(disk_name, other_device_path)) {
        return KModErr::ERR_MODULE_OPEN_FILE;
    }

    const int disk_fd = open(device_path.c_str(), O_RDONLY);
    const int part0_fd = open(part0_path.c_str(), O_RDONLY);
    const int other_fd = open(other_device_path.c_str(), O_RDONLY);
    fd_guard disk_guard(disk_fd);
    fd_guard part0_guard(part0_fd);
    fd_guard other_guard(other_fd);
    if (disk_fd < 0 || part0_fd < 0 || other_fd < 0) {
        return KModErr::ERR_MODULE_OPEN_FILE;
    }

    struct stat disk_stat = {};
    fstat(disk_fd, &disk_stat);

    uint64_t bdev_disk = 0;
    uint64_t bdev_part0 = 0;
    uint64_t bdev_other = 0;
    uint64_t inode_disk = 0;
    uint64_t inode_part0 = 0;
    uint64_t inode_other = 0;
    RETURN_IF_ERROR(get_bdev_and_inode(disk_fd, bdev_disk, inode_disk));
    RETURN_IF_ERROR(get_bdev_and_inode(part0_fd, bdev_part0, inode_part0));
    RETURN_IF_ERROR(get_bdev_and_inode(other_fd, bdev_other, inode_other));
    if (!bdev_disk || !bdev_part0 || !bdev_other) {
        return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    }

    constexpr size_t kBlockDeviceProbeSize = 1280;
    std::vector<uint8_t> disk_bytes(kBlockDeviceProbeSize);
    std::vector<uint8_t> part0_bytes(kBlockDeviceProbeSize);
    std::vector<uint8_t> other_bytes(kBlockDeviceProbeSize);
    RETURN_IF_ERROR(read_kernel_mem(bdev_disk, disk_bytes.data(), kBlockDeviceProbeSize));
    RETURN_IF_ERROR(read_kernel_mem(bdev_part0, part0_bytes.data(), kBlockDeviceProbeSize));
    RETURN_IF_ERROR(read_kernel_mem(bdev_other, other_bytes.data(), kBlockDeviceProbeSize));

    constexpr uint64_t kKernelPointerMin = 0xFFFF000000000000ull;
    constexpr size_t kNameSearchWindow = 512;
    offset = 0;
    uint32_t found_offset = 0;
    int32_t found_count = 0;
    KModErr scan_error = KModErr::OK;
    bool scan_failed = false;
    for (size_t i = 0; i + sizeof(uint64_t) < kBlockDeviceProbeSize; i += sizeof(uint64_t)) {
        const uint64_t disk_slot = *reinterpret_cast<const uint64_t*>(disk_bytes.data() + i);
        const uint64_t part0_slot = *reinterpret_cast<const uint64_t*>(part0_bytes.data() + i);
        const uint64_t other_slot = *reinterpret_cast<const uint64_t*>(other_bytes.data() + i);
        if (disk_slot < kKernelPointerMin) {
            continue;
        }
        if (disk_slot != part0_slot) {
            continue;
        }
        if (disk_slot == other_slot) {
            continue;
        }
        if (disk_slot == bdev_disk) {
            continue;
        }

        std::vector<uint8_t> target_bytes(1024);
        bool read_ok = false;
        KModErr read_err = safe_read_kaddr(disk_slot, read_ok, target_bytes.data(),
                                           target_bytes.size());
        if (is_failed(read_err)) {
            scan_error = read_err;
            scan_failed = true;
            break;
        }
        if (!read_ok) {
            continue;
        }
        const std::string expected_name = disk_name;
        for (size_t j = 0; j + expected_name.size() < kNameSearchWindow; ++j) {
            if (memcmp(target_bytes.data() + j, expected_name.data(), expected_name.size()) == 0 &&
                target_bytes[j + expected_name.size()] == 0) {
                found_offset = static_cast<uint32_t>(i);
                ++found_count;
                break;
            }
        }
    }
    if (scan_failed) {
        return scan_error;
    }
    if (found_count != 1) {
        return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    }
    offset = found_offset;
    return KModErr::OK;
}

}  // namespace kernel_module
