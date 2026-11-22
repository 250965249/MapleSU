#include "kernel_layout.h"
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>

using namespace maplesu::module_policy;

namespace {
const LayoutType& owner(const KernelLayoutDescription& layout, const char* name) {
    for (const auto& type : layout.types)
        if (type.name == name) return type;
    throw std::runtime_error(std::string("probe missing owner: ") + name);
}

const LayoutField& member(const LayoutType& type, const char* name) {
    for (const auto& field : type.fields)
        if (field.name == name) return field;
    throw std::runtime_error("probe missing member: " + type.name + "." + name);
}

void component(const LayoutType& type, const LayoutField& field) {
    std::cout << "{\"owner\":\"" << type.name << "\",\"member\":\"" << field.name
        << "\",\"ownerSizeBytes\":" << type.size << ",\"bitOffset\":" << field.bit_offset
        << ",\"bitWidth\":" << field.bit_size << "}";
}

void emit(const std::string& path, const LayoutType& type, const LayoutField& field) {
    const uint64_t offset = field.bit_offset;
    const uint32_t width = field.bit_size;
    if ((offset & 7) || (width & 7) || !width || offset + width > uint64_t(type.size) * 8)
        throw std::runtime_error("probe field bounds/alignment: " + path);
    std::cout << "\"" << path << "\":{\"owner\":\"" << type.name
        << "\",\"ownerSizeBytes\":" << type.size << ",\"bitOffset\":" << offset
        << ",\"bitWidth\":" << width << ",\"offsetBytes\":" << offset / 8
        << ",\"widthBytes\":" << width / 8
        << ",\"source\":\"target-btf\",\"resolver\":\"describe_task_credential_layout/KernelLayoutDescription\",\"components\":[";
    component(type, field);
    std::cout << "]}";
}
}

int main(int argc, char** argv) {
    if (argc != 2) return 2;
    std::ifstream input(argv[1], std::ios::binary);
    if (!input) return 2;
    std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    try {
        const auto layout = describe_task_credential_layout(bytes,
            {"cred", "comm", "seccomp.mode"}, {"suid", "sgid", "euid"});
        const auto& task = owner(layout, "task_struct");
        const auto& cred = owner(layout, "cred");
        std::cout << "{\"schema\":\"maplesu-kernel-layout-description-probe/2\","
            "\"resolutionBoundary\":\"Follows each complete task_struct.cred actual pointer graph; reachable task and cred layouts must agree\",\"fields\":{";
        emit("task_struct.cred", task, member(task, "cred"));
        std::cout << ',';
        emit("task_struct.comm", task, member(task, "comm"));
        std::cout << ',';
        emit("task_struct.seccomp.mode", task, member(task, "seccomp.mode"));
        for (const auto& name : {"suid", "sgid", "euid"}) {
            std::cout << ',';
            emit(std::string("cred.") + name, cred, member(cred, name));
        }
        std::cout << "}}\n";
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
