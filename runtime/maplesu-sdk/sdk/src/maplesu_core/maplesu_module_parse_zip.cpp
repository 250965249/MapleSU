// MapleSU module parse zip implementation.
//
#include "maplesu_module_parse_zip_private.h"

#include <cstdio>
#include <cstring>
#include <functional>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

#include "zip.h"

namespace maplesu::sdk {

//
// name, std::vector<uint8_t> entry body, [8192 x i8] read buffer, two bool
// state flags, std::function<bool(...)> callback (40 B functor + 4 pointers).
KModErr find_module_elf_in_zip(const char* module_zip_path, module_desc& out_desc,
                               std::string& out_elf_name) {
    bool has_elf = false;      // an entry whose bytes parse as a module ELF
    bool has_webroot = false;  // a "<dir>/webroot/<file>" asset entry

    std::string zip_path(module_zip_path);

    // so the scan visits the whole archive; the flags carry the result.
    std::function<bool(const std::string&, std::vector<uint8_t>&&)> on_entry =
        [&has_elf, &has_webroot, &out_desc, &out_elf_name](
            const std::string& name, std::vector<uint8_t>&& content) -> bool {
            // "./" prefixes are tolerated, so the component scan starts after
            // them.
            if (!name.empty() && name.back() != '/') {
                const std::size_t begin =
                    (name.size() > 1 && name[0] == '.' && name[1] == '/') ? 2 : 0;
                if (name.find('/', begin) == std::string::npos) {
                    // The parsed error is logged, then the bytes are parsed a
                    // code keeps both calls).
                    const KModErr parse_err =
                        parse_module_meta_from_elf_bytes(content, out_desc);
                    printf("%s, a:%s\n", name.c_str(), to_string(parse_err).c_str());
                    if (!has_elf) {
                        if (parse_module_meta_from_elf_bytes(content, out_desc) ==
                            KModErr::OK) {
                            has_elf = true;
                            out_elf_name = name;
                        }
                    }
                }
            }
            // path component must be exactly "webroot/" and at least one file
            // name has to follow it (`name.size() > slash + 9`).
            if (!name.empty() && name.back() != '/') {
                const std::size_t begin =
                    (name.size() > 1 && name[0] == '.' && name[1] == '/') ? 2 : 0;
                const std::size_t slash = name.find('/', begin);
                if (slash != std::string::npos) {
                    if (name.compare(slash + 1, 8, "webroot/") == 0 &&
                        name.size() > slash + 9) {
                        has_webroot = true;
                    }
                }
            }
            return true;
        };

    // is rendered into a 128-byte buffer using the current errno.
    int zip_err = 0;
    zip_t* zip = zip_open(zip_path.c_str(), 0, &zip_err);
    if (zip == nullptr) {
        char err_text[128];
        zip_error_to_str(err_text, sizeof(err_text), zip_err, errno);
        std::cerr << "Failed to open archive: " << err_text << std::endl;
        return KModErr::ERR_MODULE_PARSE_ZIP_FILE;
    }

    const zip_int64_t entry_count = zip_get_num_entries(zip, 0);
    for (zip_uint64_t index = 0; index != static_cast<zip_uint64_t>(entry_count);
         ++index) {
        zip_stat_t entry_stat;
        if (zip_stat_index(zip, index, 0, &entry_stat) != 0) {
            std::cerr << "zip_stat_index failed at index " << index << ": "
                      << zip_strerror(zip) << std::endl;
            zip_close(zip);
            return KModErr::ERR_MODULE_PARSE_ZIP_FILE;
        }

        const char* entry_name = zip_get_name(zip, index, 0);
        if (entry_name == nullptr) {
            std::cerr << "zip_get_name failed at index " << index << ": "
                      << zip_strerror(zip) << std::endl;
            zip_close(zip);
            return KModErr::ERR_MODULE_PARSE_ZIP_FILE;
        }

        std::string name(entry_name);
        if (!name.empty() && name.back() == '/') {
            continue;
        }

        zip_file_t* entry_file = zip_fopen_index(zip, index, 0);
        if (entry_file == nullptr) {
            std::cerr << "Failed to open file " << name << ": "
                      << zip_strerror(zip) << std::endl;
            zip_close(zip);
            return KModErr::ERR_MODULE_PARSE_ZIP_FILE;
        }

        // stat record carries ZIP_STAT_SIZE), then stream 8 KiB at a time.
        std::vector<uint8_t> content;
        content.reserve((entry_stat.valid & ZIP_STAT_SIZE)
                            ? static_cast<std::size_t>(entry_stat.size)
                            : 0);
        //   vector<uint8_t>::insert<unsigned char*>  (mangled ...insertIPhLi0EE)
        // i.e. the read buffer is byte-typed, not plain char.
        uint8_t read_buffer[8192];
        zip_int64_t read_size = 0;
        while ((read_size = zip_fread(entry_file, read_buffer,
                                      sizeof(read_buffer))) > 0) {
            content.insert(content.end(), read_buffer, read_buffer + read_size);
        }

        if (read_size != 0) {
            std::cerr << "Failed to read file " << name << ": "
                      << zip_file_strerror(entry_file) << std::endl;
            zip_fclose(entry_file);
            zip_close(zip);
            return KModErr::ERR_MODULE_PARSE_ZIP_FILE;
        }

        // failure through the owning archive.
        if (zip_fclose(entry_file) != 0) {
            std::cerr << "Failed to close file " << name << ": "
                      << zip_strerror(zip) << std::endl;
            zip_close(zip);
            return KModErr::ERR_MODULE_PARSE_ZIP_FILE;
        }

        // The reference code closes the archive inside this branch and again on
        // same tail, so reproduce that shape with an explicit label.
        if (!on_entry(name, std::move(content))) {
            zip_close(zip);
            goto scan_finished;
        }
    }

    zip_close(zip);

scan_finished:
    if (!has_elf) {
        return KModErr::ERR_MODULE_ELF_FILE_NOT_FOUND;
    }
    if (has_webroot) {
        out_desc.web_ui = true;
    }
    return KModErr::OK;
}

//
// The child parses the archive (module bytes may abort the process) and writes
// its KModErr + serialized descriptor through the pipes; the parent reads both,
// deserializes the descriptor, copies it into the caller's output and reaps the
// child.  All error codes are the SDK's existing enum values:
//   ERR_MODULE_PARSE_ZIP_FILE  -19945 (line 67 of module_err_def.h)
//   ERR_MODULE_ELF_FILE_NOT_FOUND -19944 (line 68)
//   ERR_READ_CHILD_ERRCODE     -19914 (line 98)
//   ERR_READ_CHILD_DATA        -19911 (line 101)
KModErr safe_parse_module_desc_from_zip_file(const char* module_zip_path,
                                             module_desc& out_desc) {
    fork_pipe_info pipe_info;
    KModErr result = KModErr::OK;

    if (fork_pipe_child_process(pipe_info)) {
        // ---- child -------------------------------------------------------
        // touches any module file.
        KModErr child_err = default_modules::module_root::set_current_root(true);
        if (child_err == KModErr::OK) {
            // the descriptor is written directly into out_desc (COW: the parent
            // reads it back through the serialization channel below).
            std::string elf_name;
            child_err = find_module_elf_in_zip(module_zip_path, out_desc, elf_name);
        }
        result = child_err;
        // of a missing descriptor block.
        write_errcode_from_child(pipe_info, result);

        // shared wire format.
        std::vector<module_desc> parsed_descs{out_desc};
        std::vector<uint8_t> transfer = serialize_module_descs(parsed_descs);
        write_transfer_data_from_child(pipe_info, transfer);

        pipe_info.close_all();
        _exit(0);
    }

    // ---- parent ----------------------------------------------------------
    if (!read_errcode_from_child(pipe_info, result)) {
        result = KModErr::ERR_READ_CHILD_ERRCODE;
    }

    std::vector<uint8_t> transfer;
    if (!read_transfer_data_from_child(pipe_info, transfer)) {
        result = KModErr::ERR_READ_CHILD_DATA;
    }

    // produced one.  The copy is 9232 bytes (sizeof(module_desc)).
    std::vector<module_desc> parsed_descs = deserialize_module_descs(transfer);
    if (!parsed_descs.empty()) {
        memcpy(&out_desc, parsed_descs.data(), sizeof(module_desc));
    }

    int child_status = 0;
    waitpid(pipe_info.child_pid, &child_status, 0);
    return result;
}

}  // namespace maplesu::sdk
