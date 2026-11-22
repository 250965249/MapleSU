// resetprop -- persistent property storage implementation.
//
#include "persist.h"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace maplesu::payload::resetprop {
namespace {

// ---------------------------------------------------------------------------
// small filesystem helpers
// ---------------------------------------------------------------------------
bool write_all(int fd, const std::string& data) {
    const char* cursor = data.data();
    size_t remaining = data.size();
    while (remaining > 0) {
        const ssize_t written = ::write(fd, cursor, remaining);
        if (written < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        cursor += written;
        remaining -= static_cast<size_t>(written);
    }
    return true;
}

bool read_all(const std::string& path, std::string& out) {
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    out.clear();
    char buffer[4096];
    while (true) {
        const ssize_t n = ::read(fd, buffer, sizeof(buffer));
        if (n < 0) {
            if (errno == EINTR) continue;
            ::close(fd);
            return false;
        }
        if (n == 0) break;
        out.append(buffer, static_cast<size_t>(n));
    }
    ::close(fd);
    return true;
}

// Copies owner/mode of an existing record list onto the freshly written
// temporary file, so publishing it does not change the file's identity.
void clone_attr(const std::string& source, const std::string& target) {
    struct stat st {};
    if (::stat(source.c_str(), &st) != 0) return;
    ::chmod(target.c_str(), st.st_mode & 07777);
    ::chown(target.c_str(), st.st_uid, st.st_gid);
}

bool make_temp(const std::string& pattern, std::string& path, int& fd) {
    std::string buffer = pattern;
    std::vector<char> storage(buffer.begin(), buffer.end());
    storage.push_back('\0');
    fd = ::mkstemp(storage.data());
    if (fd < 0) return false;
    path.assign(storage.data());
    return true;
}

}  // namespace

// ---------------------------------------------------------------------------
// PersistentStore
// ---------------------------------------------------------------------------
PersistentStore::PersistentStore(std::string base_dir) : base_dir_(std::move(base_dir)) {}

bool PersistentStore::fail(const std::string& reason) const {
    last_error_ = reason;
    return false;
}

std::string PersistentStore::proto_path() const {
    return base_dir_ + "/" + kPersistProtoName;
}

bool PersistentStore::proto_present() const {
    struct stat st {};
    return ::stat(proto_path().c_str(), &st) == 0;
}

bool PersistentStore::proto_read(std::vector<PersistentRecord>& records) const {
    std::string bytes;
    if (!read_all(proto_path(), bytes)) {
        return fail(std::string("resetprop: read persistent properties: ") +
                    std::strerror(errno));
    }
    if (!decode_persistent_properties(bytes, records)) {
        return fail("resetprop: persistent_properties decode failed");
    }
    return true;
}

bool PersistentStore::proto_write(const std::vector<PersistentRecord>& records) {
    const std::string target = proto_path();
    std::string temp_path;
    int fd = -1;
    if (!make_temp(target + ".XXXXXX", temp_path, fd)) {
        return fail(std::string("resetprop: mkstemp: ") + std::strerror(errno));
    }
    const std::string bytes = encode_persistent_properties(records);
    const bool written = write_all(fd, bytes);
    const int saved_errno = errno;
    ::close(fd);
    if (!written) {
        ::unlink(temp_path.c_str());
        errno = saved_errno;
        return fail(std::string("resetprop: write persistent properties: ") +
                    std::strerror(errno));
    }
    clone_attr(target, temp_path);
    if (::rename(temp_path.c_str(), target.c_str()) != 0) {
        const int rename_errno = errno;
        ::unlink(temp_path.c_str());
        errno = rename_errno;
        return fail(std::string("resetprop: rename persistent properties: ") +
                    std::strerror(errno));
    }
    return true;
}

bool PersistentStore::file_get(const std::string& key, std::string& value) const {
    return read_all(base_dir_ + "/" + key, value);
}

bool PersistentStore::file_set(const std::string& key, const std::string& value) {
    const std::string target = base_dir_ + "/" + key;
    std::string temp_path;
    int fd = -1;
    if (!make_temp(base_dir_ + "/prop.XXXXXX", temp_path, fd)) {
        return fail(std::string("resetprop: mkstemp: ") + std::strerror(errno));
    }
    const bool written = write_all(fd, value);
    const int saved_errno = errno;
    ::close(fd);
    if (!written) {
        ::unlink(temp_path.c_str());
        errno = saved_errno;
        return fail(std::string("resetprop: write prop: ") + std::strerror(errno));
    }
    if (::rename(temp_path.c_str(), target.c_str()) != 0) {
        const int rename_errno = errno;
        ::unlink(temp_path.c_str());
        errno = rename_errno;
        return fail(std::string("resetprop: rename prop: ") + std::strerror(errno));
    }
    return true;
}

bool PersistentStore::file_erase(const std::string& key) {
    if (::unlink((base_dir_ + "/" + key).c_str()) != 0) {
        return fail(std::string("resetprop: unlink prop: ") + std::strerror(errno));
    }
    return true;
}

bool PersistentStore::get(const std::string& key, std::string& value) const {
    if (proto_present()) {
        std::vector<PersistentRecord> records;
        if (!proto_read(records)) return false;
        const auto found = std::lower_bound(
            records.begin(), records.end(), key,
            [](const PersistentRecord& record, const std::string& wanted) {
                return record.name < wanted;
            });
        if (found == records.end() || found->name != key || !found->has_value) {
            return false;
        }
        value = found->value;
        return true;
    }
    return file_get(key, value);
}

bool PersistentStore::set(const std::string& key, const std::string& value) {
    if (proto_present()) {
        std::vector<PersistentRecord> records;
        if (!proto_read(records)) return false;
        const auto found = std::lower_bound(
            records.begin(), records.end(), key,
            [](const PersistentRecord& record, const std::string& wanted) {
                return record.name < wanted;
            });
        if (found != records.end() && found->name == key) {
            found->value = value;
            found->has_value = true;
        } else {
            PersistentRecord record;
            record.has_name = true;
            record.has_value = true;
            record.name = key;
            record.value = value;
            records.insert(found, std::move(record));
        }
        return proto_write(records);
    }
    return file_set(key, value);
}

bool PersistentStore::erase(const std::string& key) {
    if (proto_present()) {
        std::vector<PersistentRecord> records;
        if (!proto_read(records)) return false;
        const auto found = std::lower_bound(
            records.begin(), records.end(), key,
            [](const PersistentRecord& record, const std::string& wanted) {
                return record.name < wanted;
            });
        if (found == records.end() || found->name != key) return false;
        records.erase(found);
        return proto_write(records);
    }
    return file_erase(key);
}

bool PersistentStore::for_each(std::vector<PersistentRecord>& records) const {
    records.clear();
    if (proto_present()) return proto_read(records);

    DIR* directory = ::opendir(base_dir_.c_str());
    if (directory == nullptr) {
        return fail(std::string("resetprop: open /data/property: ") +
                    std::strerror(errno));
    }
    while (dirent* entry = ::readdir(directory)) {
        const std::string name = entry->d_name;
        if (name == "." || name == "..") continue;
        const std::string path = base_dir_ + "/" + name;
        struct stat st {};
        if (::stat(path.c_str(), &st) != 0 || !S_ISREG(st.st_mode)) continue;
        std::string value;
        if (!read_all(path, value)) continue;
        PersistentRecord record;
        record.has_name = true;
        record.has_value = true;
        record.name = name;
        record.value = value;
        records.push_back(std::move(record));
    }
    ::closedir(directory);
    std::sort(records.begin(), records.end(),
              [](const PersistentRecord& left, const PersistentRecord& right) {
                  return left.name < right.name;
              });
    return true;
}

}  // namespace maplesu::payload::resetprop
