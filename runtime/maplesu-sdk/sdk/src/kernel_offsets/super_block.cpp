// super_block implementation.
//
#include <fcntl.h>
#include <mntent.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>

#include <cstdint>
#include <cstdio>
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

// Magic numbers of the filesystem super blocks whose UUID layout this probe
// understands.  The UUID the kernel keeps in super_block::s_uuid is the same
// 16-byte value the filesystem stores in its own super block.
constexpr uint16_t kExtSuperMagic = 0xEF53;
constexpr uint32_t kF2fsSuperMagic = 0xF2F52010;

// Number of super-block bytes one probe snapshot reads; the fields the probes
// scan for all live in the first kilobyte.
constexpr uint32_t kSuperBlockSnapshotSize = 1024;

} // namespace

// Builds the path of one probe file: "temp<index>" followed by a fixed marker,
// placed inside the module's system-file directory under /data.
static std::string get_temp_file_path(int index) {
    std::stringstream name_stream;
    name_stream << "temp" << index << "oG54XQQPT30UOr3sXuDWJOl5orJeQys6";

    return (std::filesystem::path(maplesu::sdk::get_system_file_dir_path()) / name_stream.str())
        .string();
}

// Creates/recreates the two probe files: each is opened read-write, truncated to
// a distinct length and labelled system_file so the kernel side can read it and
// so its inode carries a super block to compare against.
static KModErr init_s_uuid_offset_test_file() {
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

// Finds the block device that backs the filesystem holding path: it walks the
// mount table and keeps the longest mount point that is a prefix of path, so the
// device reported is the one of the deepest mounted filesystem.
static std::string get_block_device_for_path(const std::string &path) {
    std::string best_dir;
    std::string best_dev;
    uint64_t best_len = 0;

    FILE *mount_file = setmntent("/proc/mounts", "r");
    if (mount_file == nullptr) {
        return "";
    }
    struct mntent *entry = nullptr;
    while ((entry = getmntent(mount_file)) != nullptr) {
        const std::string mount_dir(entry->mnt_dir);
        if (path.find(mount_dir, 0) == 0 && mount_dir.size() > best_len) {
            best_dir = mount_dir;
            best_dev = entry->mnt_fsname;
            best_len = mount_dir.size();
        }
    }
    endmntent(mount_file);
    return best_dev;
}

// Reads the filesystem UUID out of the super block of one block device.  The
// device is read in one 8 KiB chunk and the UUID is taken from the block layout
// the recorded magic number selects.  Reports whether a UUID was found.
static bool read_uuid_robust(const std::string &device_path, std::vector<uint8_t> &out_uuid) {
    fd_guard dev_fd(open(device_path.c_str(), O_RDONLY));
    if (dev_fd.get() < 0) {
        return false;
    }

    std::vector<uint8_t> block(8192);
    const int64_t bytes_read = read(dev_fd.get(), block.data(), block.size());
    dev_fd.reset(-1);

    if (bytes_read < 4096) {
        return false;
    }

    // ext4/ext2 layout: the super block starts one block in and keeps its UUID
    // 104 bytes after its magic number.
    if (*reinterpret_cast<const uint16_t *>(block.data() + 1080) == kExtSuperMagic) {
        out_uuid.assign(block.data() + 1128, block.data() + 1144);
        return true;
    }
    if (*reinterpret_cast<const uint16_t *>(block.data() + 56) == kExtSuperMagic) {
        out_uuid.assign(block.data() + 104, block.data() + 120);
        return true;
    }

    // f2fs layout: the super block can sit at the start of the device, at the
    // 4 KiB offset, or at the 5 KiB offset of a larger block.
    if (*reinterpret_cast<const uint32_t *>(block.data() + 1024) == kF2fsSuperMagic) {
        out_uuid.assign(block.data() + 2144, block.data() + 2160);
        return true;
    }
    if (*reinterpret_cast<const uint32_t *>(block.data()) == kF2fsSuperMagic) {
        out_uuid.assign(block.data() + 1120, block.data() + 1136);
        return true;
    }
    if (bytes_read >= 6256 &&
        *reinterpret_cast<const uint32_t *>(block.data() + 5120) == kF2fsSuperMagic) {
        out_uuid.assign(block.data() + 6240, block.data() + 6256);
        return true;
    }
    return false;
}

// Locates the dev field of struct super_block.  super_block::s_dev records the
// filesystem device number, and the kernel stores it in the encoding
// makedev(major, minor) built from the same st_dev stat reports, so the field is
// the one slot whose 32-bit value matches the encoded device of both probe
// files.  The two files are forced onto different filesystems so the value is
// unique per super block.
KModErr get_super_block_s_dev_offset(uint32_t &offset) {
    KernelFieldDescription field;
    bool available = false;
    KModErr btf_error = maplesu_resolve_btf_field("super_block", "s_dev", 4, field, available);
    if (available) {
        if (is_ok(btf_error)) offset = field.offset_bytes;
        return btf_error;
    }

    KModErr err = get_offset_cache("super_block_s_dev", offset);
    if (is_ok(err)) {
        return err;
    }

    uint32_t i_sb_offset = 0;
    err = get_inode_i_sb_offset(i_sb_offset);
    if (is_failed(err)) {
        return err;
    }

    RETURN_IF_ERROR(init_s_uuid_offset_test_file());

    std::string probe_path = get_temp_file_path(0);
    std::string shell_path("/system/bin/sh");
    if (access(shell_path.c_str(), R_OK) != 0) {
        shell_path.assign("/bin/sh");
    }

    fd_guard probe_fd(open(probe_path.c_str(), O_RDONLY));
    fd_guard shell_fd(open(shell_path.c_str(), O_RDONLY));
    if (probe_fd.get() < 0 || shell_fd.get() < 0) {
        return KModErr::ERR_MODULE_OPEN_FILE;
    }

    struct stat probe_stat{};
    struct stat shell_stat{};
    if (fstat(probe_fd.get(), &probe_stat) != 0 || fstat(shell_fd.get(), &shell_stat) != 0) {
        return KModErr::ERR_MODULE_READ_FILE;
    }

    const uint32_t probe_dev =
        static_cast<uint32_t>((major(probe_stat.st_dev) << 20) | minor(probe_stat.st_dev));
    const uint32_t shell_dev =
        static_cast<uint32_t>((major(shell_stat.st_dev) << 20) | minor(shell_stat.st_dev));
    if (probe_dev == shell_dev) {
        puts("[-] Error: File A and File B are on the same device. Need cross-filesystem "
             "validation.");
        return KModErr::ERR_MODULE_PARAM;
    }

    // Resolves one probe file's path to the super block of its inode.
    const auto read_super_block = [&i_sb_offset](const std::string &path,
                                                 uint64_t &out_sb_kaddr) -> KModErr {
        scoped_kpath kp{};
        RETURN_IF_ERROR(acquire_kpath(path, kp));
        uint32_t d_inode_offset = 0;
        RETURN_IF_ERROR(get_dentry_d_inode_offset(d_inode_offset));
        uint64_t inode = 0;
        RETURN_IF_ERROR(read_kernel_mem(kp.kp.dentry + d_inode_offset, &inode, sizeof(inode)));
        return read_kernel_mem(inode + i_sb_offset, &out_sb_kaddr, sizeof(out_sb_kaddr));
    };

    uint64_t probe_sb = 0;
    uint64_t shell_sb = 0;
    RETURN_IF_ERROR(read_super_block(probe_path, probe_sb));
    RETURN_IF_ERROR(read_super_block(shell_path, shell_sb));
    if (probe_sb < kKernelAddrMin || shell_sb < kKernelAddrMin) {
        return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    }

    std::vector<uint8_t> probe_block(kSuperBlockSnapshotSize);
    std::vector<uint8_t> shell_block(kSuperBlockSnapshotSize);
    RETURN_IF_ERROR(read_kernel_mem(probe_sb, probe_block.data(), kSuperBlockSnapshotSize));
    RETURN_IF_ERROR(read_kernel_mem(shell_sb, shell_block.data(), kSuperBlockSnapshotSize));

    offset = 0;
    int match_count = 0;
    for (uint64_t i = 0; i < 1020; i += 4) {
        if (*reinterpret_cast<const uint32_t *>(&probe_block[i]) != probe_dev) {
            continue;
        }
        if (*reinterpret_cast<const uint32_t *>(&shell_block[i]) != shell_dev) {
            continue;
        }
        offset = static_cast<uint32_t>(i);
        ++match_count;
    }
    if (match_count != 1) {
        return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    }
    return put_offset_cache("super_block_s_dev", offset);
}

// Locates the s_uuid field of struct super_block.  s_uuid holds the 16-byte
// filesystem UUID; the probe reads that UUID from the block device backing the
// probe file, snapshots the file's super block through its inode, and reports the
// first byte offset whose 16 bytes equal it.
KModErr get_super_block_s_uuid_offset(uint32_t &offset) {
    KernelFieldDescription field;
    bool available = false;
    KModErr btf_error = maplesu_resolve_btf_field("super_block", "s_uuid", 16, field, available);
    if (available) {
        if (is_ok(btf_error)) offset = field.offset_bytes;
        return btf_error;
    }

    KModErr err = get_offset_cache("super_block_s_uuid", offset);
    if (is_ok(err)) {
        return err;
    }

    err = init_s_uuid_offset_test_file();
    if (is_failed(err)) {
        return err;
    }

    uint32_t i_sb_offset = 0;
    RETURN_IF_ERROR(get_inode_i_sb_offset(i_sb_offset));

    std::string probe_path = get_temp_file_path(0);
    fd_guard create_fd(open(probe_path.c_str(), O_RDWR | O_CREAT, 0600));
    if (create_fd.get() < 0) {
        return KModErr::ERR_MODULE_OPEN_FILE;
    }

    const std::string device_path = get_block_device_for_path(probe_path);
    if (device_path.empty() || device_path.find("/dev/") == std::string::npos) {
        puts("get_block_device_for_path failed.");
        return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    }

    std::vector<uint8_t> uuid;
    if (!read_uuid_robust(device_path, uuid)) {
        puts("read_uuid_robust failed.");
        return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    }

    const int probe_raw_fd = open(probe_path.c_str(), O_RDONLY);
    if (probe_raw_fd < 0) {
        return KModErr::ERR_MODULE_OPEN_FILE;
    }
    fd_guard probe_fd(probe_raw_fd);

    scoped_kpath kp{};
    RETURN_IF_ERROR(acquire_kpath(probe_path, kp));

    uint32_t d_inode_offset = 0;
    RETURN_IF_ERROR(get_dentry_d_inode_offset(d_inode_offset));

    uint64_t inode = 0;
    RETURN_IF_ERROR(read_kernel_mem(kp.kp.dentry + d_inode_offset, &inode, sizeof(inode)));

    uint64_t sb_kaddr = 0;
    RETURN_IF_ERROR(read_kernel_mem(inode + i_sb_offset, &sb_kaddr, sizeof(sb_kaddr)));
    if (sb_kaddr < kKernelAddrMin) {
        return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
    }

    std::vector<uint8_t> sb_block(kSuperBlockSnapshotSize);
    RETURN_IF_ERROR(read_kernel_mem(sb_kaddr, sb_block.data(), kSuperBlockSnapshotSize));

    for (uint64_t i = 0; i != 1009; ++i) {
        if (memcmp(&sb_block[i], uuid.data(), 16) == 0) {
            offset = static_cast<uint32_t>(i);
            return put_offset_cache("super_block_s_uuid", offset);
        }
    }
    return KModErr::ERR_MODULE_OFFSET_NOT_FOUND;
}

} // namespace kernel_module
