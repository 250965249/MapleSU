// module base kernel symbol kaddr implementation.
//
#define SymbolLookupSilentGuard_8dfccc5cf454087c7314725d3487e703 \
    SymbolLookupSilentGuard_c67c0e4fed21dd11b34c67e0a5b878c8

#include "kernel_module_kit_umbrella.h"
#include "maplesu_request_identity.h"
#include "../../../../ultra/authorization/kernel_read_metadata.h"

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <functional>
#include <new>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

// /proc/kallsyms 一行的解析结果。
// 即 { uint64_t addr; char type; std::string name; std::string module; }，
// _ZNSt6__ndk1...vectorIN12_GLOBAL__N_112KallsymsItemE... —— 即该类型定义在
// **全局**匿名命名空间（不是 kernel_module::(anonymous)），故本文件把它放在
// namespace kernel_module 之外。
namespace {
struct KallsymsItem {
    uint64_t addr = 0;      // 0x... 地址（from_chars 解析）
    char type = '\0';       // 't'/'T'/'w'/'W' ... 符号类型
    std::string name;       // 符号名（可能带 [module] 后缀时的裸名）
    std::string module;     // 模块名（行内 `[module]` 去掉方括号后）
};
}  // namespace

namespace kernel_module {

KModErr get_filldir64_addr(uint64_t & out_addr);
KModErr get_avc_denied_info(uint64_t & out_addr, uint64_t & out_extra);
KModErr get_append_package_kallsyms_kaddr(uint64_t & out_kaddr);

static KModErr __get_kallsyms_cache(const RequestIdentity& identity,
                                  const RequestOwnerBinding* owner,
                                  std::unordered_map<std::string, uint64_t>*& out);
static std::vector<std::pair<std::string, uint64_t>>
__find_kallsyms_cache(const std::unordered_map<std::string, uint64_t> & cache,
                      const char * name, SymbolMatchMode mode);
static KModErr __kallsyms_lookup_name(const char * name, uint64_t & out);
static KModErr __find_proc_kallsyms(const char * name, std::vector<SymbolHit> & out,
                                    SymbolMatchMode mode);
static bool __symbol_name_match(std::string_view name, std::string_view query,
                                SymbolMatchMode mode);
static std::string_view __strip_module_brackets(std::string_view text);

static KModErr __get_kallsyms_cache(const RequestIdentity& identity,
                                  const RequestOwnerBinding* owner,
                                  std::unordered_map<std::string, uint64_t>*& out) {
    struct Cache {
        RequestIdentity identity;
        std::unordered_map<std::string, uint64_t> values;
    };
    static thread_local Cache cache;
    out = nullptr;
    if (!identity.matches()) return KModErr::ERR_MODULE_ROOT_KEY;
    if (owner || !cache.identity.matches()) {
        cache.values.clear();
        cache.identity = identity;
    }
    if (cache.values.empty()) {
        std::unordered_map<std::string, uint64_t> seeds;
        uint64_t filldir64_addr = 0;
        const auto filldir_error = get_filldir64_addr(filldir64_addr);
        if (owner && is_failed(filldir_error)) return filldir_error;
        if (is_ok(filldir_error)) {
            seeds["filldir64"] = filldir64_addr;
        }
        if (!identity.matches()) {
            cache.values.clear();
            return KModErr::ERR_MODULE_ROOT_KEY;
        }
        uint64_t avc_denied_addr = 0, avc_denied_extra = 0;
        const auto avc_error = get_avc_denied_info(avc_denied_addr, avc_denied_extra);
        if (owner && is_failed(avc_error)) return avc_error;
        if (is_ok(avc_error)) {
            seeds["avc_denied"] = avc_denied_addr;
        }
        if (!identity.matches()) {
            cache.values.clear();
            return KModErr::ERR_MODULE_ROOT_KEY;
        }
        cache.values.insert(seeds.begin(), seeds.end());
    }
    if (!identity.matches() || (owner && !maplesu_request_owner_binding_matches(*owner))) {
        cache.values.clear();
        return KModErr::ERR_MODULE_ROOT_KEY;
    }
    out = &cache.values;
    return KModErr::OK;
}

// 符号名匹配。
//   1=starts_with、2=ends_with、3=find(...) != npos，default=false。
static bool __symbol_name_match(std::string_view name, std::string_view query,
                                SymbolMatchMode mode) {
    switch (mode) {
        case SymbolMatchMode::Exact:
            return name == query;
        case SymbolMatchMode::Prefix:
            return name.starts_with(query);
        case SymbolMatchMode::Suffix:
            return name.ends_with(query);
        case SymbolMatchMode::Substring:
            return name.find(query) != std::string_view::npos;
        default:
            return false;
    }
}

// 去掉模块名的方括号：`[foo]` -> `foo`，其它原样返回。
static std::string_view __strip_module_brackets(std::string_view text) {
    if (text.size() > 1 && text.front() == '[' && text.back() == ']') {
        return text.substr(1, text.size() - 2);
    }
    return text;
}

// 在 kallsyms 缓存里做符号名匹配，返回按「长度差、字典序」排好序的候选。
//
//   * 遍历 cache：key 转 string_view，find(':') 命中则 substr(pos+1) 去掉模块前缀，
//     就是这条 std::sort 的实例化；
static std::vector<std::pair<std::string, uint64_t>>
__find_kallsyms_cache(const std::unordered_map<std::string, uint64_t> & cache,
                      const char * name, SymbolMatchMode mode) {
    struct Candidate {
        const std::string * name;  // 指向 cache 里 key 的稳定地址
        uint64_t addr;             // cache 的 value
        uint64_t length_delta;     // 去模块前缀后的符号名长度 - 查询名长度
    };

    std::vector<std::pair<std::string, uint64_t>> result;
    if (!name || name[0] == '\0') return result;

    // 查询名的长度由 string_view 自己从 NUL 结尾串取（冻结形态走 __builtin_strlen，
    // 不是 fortify 的 __strlen_chk）。
    const std::string_view query(name);
    std::vector<Candidate> candidates;
    if (!cache.empty()) candidates.reserve(cache.size());

    for (const auto & entry : cache) {
        std::string_view symbol(entry.first);
        const size_t colon = symbol.find(':');
        if (colon != std::string_view::npos) symbol = symbol.substr(colon + 1);
        if (!__symbol_name_match(symbol, query, mode)) continue;
        candidates.push_back({&entry.first, entry.second, symbol.size() - query.size()});
    }

    std::sort(candidates.begin(), candidates.end(),
              [](const Candidate & a, const Candidate & b) {
                  if (a.length_delta != b.length_delta) return a.length_delta < b.length_delta;
                  return *a.name < *b.name;
              });

    result.reserve(candidates.size());
    for (const Candidate & candidate : candidates) {
        result.emplace_back(*candidate.name, candidate.addr);
    }
    return result;
}

// 一个 64 位常量赋值到 X 寄存器（不是本 TU 的函数，是 aarch64_asm_helper.h 的
// aarch64_asm_mov_x 被内联进 __kallsyms_lookup_name 的发射器 lambda 后留下的形状）。

// 通过「追加包（append package）里的 kallsyms_lookup_name 地址」在运行时解析符号。
//
//       aarch64_asm_set_x_cstr_ptr(a, x0, name);   // 名字嵌入代码流 + ADR 取址
//       aarch64_asm_mov_x(a, x11, kaddr);          // x11 = 追加包 lookup 地址
//       a->blr(x11);                               // 调它，结果留在 x0
//       return KModErr::OK;
//   };
//     返回值走 x0 寄存器由 arm64_module_asm_func_end 搬运。
static KModErr __kallsyms_lookup_name(const char * name, uint64_t & out) {
    out = 0;
    uint64_t lookup_kaddr = 0;
    KModErr err = get_append_package_kallsyms_kaddr(lookup_kaddr);
    if (is_failed(err)) return err;

    std::function<KModErr(asmjit::a64::Assembler *, asmjit::a64::GpX &)> build_call =
        [name, lookup_kaddr](asmjit::a64::Assembler * a, asmjit::a64::GpX &) -> KModErr {
        // 把符号名作为 C 字符串嵌进 .text（b 跳过数据 + ADR 取址），x0 = 名字指针。
        aarch64_asm_set_x_cstr_ptr(a, asmjit::a64::x0, name);
        // x11 = 追加包 kallsyms_lookup_name 地址；blr x11 调用，返回值在 x0。
        aarch64_asm_mov_x(a, asmjit::a64::x11, lookup_kaddr);
        a->blr(asmjit::a64::x11);
        return KModErr::OK;
    };

    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    asmjit::a64::Assembler * assembler = asm_ctx.assembler();
    arm64_module_asm_func_start(assembler);
    asmjit::a64::GpX return_reg = asmjit::a64::x0;
    err = build_call(assembler, return_reg);
    if (is_ok(err)) {
        arm64_module_asm_func_end(assembler, return_reg);
        err = execute_kernel_asm_func(aarch64_asm_to_bytes(assembler), out);
        if (is_failed(err)) return err;
        if (out == 0) return KModErr::ERR_MODULE_SYMBOL_NOT_EXIST;
        return KModErr::OK;
    }
    return err;
}

// 直接解析 /proc/kallsyms 逐行状态机（缓存未命中且模式非 Exact 时的慢路径）。
//
//   取 string_view(name)；有 ':' 时 module = __strip_module_brackets(左半)、
//   while (getline)：空行跳过；istringstream 解析
static KModErr __find_proc_kallsyms(const char * name, std::vector<SymbolHit> & out,
                                    SymbolMatchMode mode) {
    out.clear();
    if (!name || name[0] == '\0') return KModErr::ERR_MODULE_PARAM;

    const std::string_view name_view(name);
    std::string_view module_view;
    std::string_view symbol_view;
    const size_t colon = name_view.find(':');
    if (colon == std::string_view::npos) {
        symbol_view = name_view;
    } else {
        module_view = __strip_module_brackets(name_view.substr(0, colon));
        symbol_view = name_view.substr(colon + 1);
    }
    if (symbol_view.empty()) return KModErr::ERR_MODULE_PARAM;
    if (colon != std::string_view::npos && module_view.empty()) return KModErr::ERR_MODULE_PARAM;

    std::vector<KallsymsItem> items;
    std::ifstream kallsyms_file("/proc/kallsyms");
    if (!kallsyms_file.is_open()) return KModErr::ERR_MODULE_READ_FILE;

    // 随后才析构 ifstream。该 move 赋值里的 vector<KallsymsItem>::__clear
    std::vector<KallsymsItem> parsed;
    std::string line;
    while (std::getline(kallsyms_file, line)) {
        if (line.empty()) continue;
        std::istringstream line_stream(line);
        std::string addr_text;
        KallsymsItem item{};
        if (!(line_stream >> addr_text >> item.type >> item.name)) continue;
        item.addr = 0;
        const auto parsed_addr = std::from_chars(addr_text.data(),
                                                 addr_text.data() + addr_text.size(),
                                                 item.addr, 16);
        if (parsed_addr.ec != std::errc() ||
            parsed_addr.ptr != addr_text.data() + addr_text.size()) {
            continue;
        }
        std::string module_text;
        line_stream >> module_text;
        if (!line_stream.fail() && module_text.size() > 1 && module_text.front() == '[' &&
            module_text.back() == ']') {
            item.module.assign(module_text.begin() + 1, module_text.end() - 1);
        }
        parsed.push_back(std::move(item));
    }
    if (kallsyms_file.bad()) return KModErr::ERR_MODULE_READ_FILE;
    items = std::move(parsed);

    for (const KallsymsItem & item : items) {
        if (colon != std::string_view::npos) {
            if (item.module.empty()) continue;
            if (__strip_module_brackets(item.module) != module_view) continue;
        }
        if (!__symbol_name_match(item.name, symbol_view, mode)) continue;

        std::string full_name;
        if (!item.module.empty()) {
            const std::string_view module_name = __strip_module_brackets(item.module);
            full_name.reserve(module_name.size() + 1 + item.name.size());
            full_name.append(module_name);
            full_name.push_back(':');
            full_name.append(item.name);
        } else {
            full_name = item.name;
        }

        uint64_t kaddr = 0;
        const auto lookup_error = __kallsyms_lookup_name(full_name.c_str(), kaddr);
        if (is_failed(lookup_error)) {
            if (maplesu_request_owner_mode() && lookup_error != KModErr::ERR_MODULE_SYMBOL_NOT_EXIST)
                return lookup_error;
            continue;
        }
        if (kaddr == 0) continue;

        SymbolHit hit{};
        hit.addr = kaddr;
        snprintf(hit.name, sizeof(hit.name), "%s", full_name.c_str());
        out.emplace_back(std::move(hit));
    }
    if (out.empty()) return KModErr::ERR_MODULE_SYMBOL_NOT_EXIST;
    return KModErr::OK;
}

// 对外：按名字查一个符号，返回地址 + 命中名。
//
//       get_filldir64_addr 成功 -> cache["filldir64"] = addr
//       get_avc_denied_info 成功 -> cache["avc_denied"] = info1
//   hits 非空：strncpy(out.name, hits[0].first, 1023)+NUL，
static KModErr lookup_name_impl(const char * name, SymbolHit & out, SymbolMatchMode mode, bool report_missing) try {
    out.addr = 0;
    memset(out.name, 0, sizeof(out.name));
    if (!name || name[0] == '\0') return KModErr::ERR_MODULE_PARAM;

    RequestIdentity identity;
    if (!identity.capture()) return KModErr::ERR_MODULE_ROOT_KEY;
    RequestMetadataFacts facts{};
    const RequestOwnerBinding* owner = nullptr;
    if (identity.auth_state & 1) {
        bool supported = false;
        const auto error = maplesu_kernel_metadata_facts(facts, supported);
        if (is_failed(error)) return error;
        if (!supported) return KModErr::ERR_MODULE_TEST_CHANNEL;
        if (!identity.matches() || !maplesu_request_owner_binding_matches(facts.owner))
            return KModErr::ERR_MODULE_ROOT_KEY;
        owner = &facts.owner;
    }
    std::unordered_map<std::string, uint64_t>* cache_pointer = nullptr;
    const auto cache_error = __get_kallsyms_cache(identity, owner, cache_pointer);
    if (is_failed(cache_error)) return cache_error;
    auto& cache = *cache_pointer;
    SymbolHit candidate{};

    std::vector<std::pair<std::string, uint64_t>> hits = __find_kallsyms_cache(cache, name, mode);
    if (!hits.empty()) {
        const std::pair<std::string, uint64_t> & first = hits.front();
        strncpy(candidate.name, first.first.c_str(), sizeof(candidate.name) - 1);
        candidate.name[sizeof(candidate.name) - 1] = '\0';
        candidate.addr = first.second;
        if (!identity.matches() || (owner && !maplesu_request_owner_binding_matches(*owner))) {
            cache.clear();
            return KModErr::ERR_MODULE_ROOT_KEY;
        }
        out = candidate;
        return KModErr::OK;
    }
    if (owner && !(facts.capabilities & MAPLESU_CAP_EXEC)) return KModErr::ERR_MODULE_TEST_CHANNEL;

    strncpy(candidate.name, name, sizeof(candidate.name) - 1);
    candidate.name[sizeof(candidate.name) - 1] = '\0';
    KModErr err = __kallsyms_lookup_name(name, candidate.addr);
    if (err == KModErr::ERR_MODULE_SYMBOL_NOT_EXIST && mode != SymbolMatchMode::Exact) {
        std::vector<SymbolHit> proc_hits;
        err = __find_proc_kallsyms(name, proc_hits, mode);
        if (is_ok(err) && !proc_hits.empty()) {
            candidate = proc_hits.front();
        }
    }

    switch (err) {
        case KModErr::ERR_MODULE_SYMBOL_NOT_EXIST:
            if (report_missing && get_symbol_lookup_printf_silent_d8685f89f10ca8eb96df766c8babd6c3()) {
                printf("warning: '%s' symbol not found.\n", name);
            }
            return err;
        case KModErr::OK:
            if (!identity.matches()) {
                cache.clear();
                return KModErr::ERR_MODULE_ROOT_KEY;
            }
            if (candidate.addr != 0) {
                cache[std::string(candidate.name)] = candidate.addr;
            }
            if (!identity.matches()) {
                cache.clear();
                return KModErr::ERR_MODULE_ROOT_KEY;
            }
            out = candidate;
            return err;
        default:
            return err;
    }
} catch (const std::bad_alloc&) {
    out.addr = 0;
    memset(out.name, 0, sizeof(out.name));
    return KModErr::ERR_NO_MEM;
}

KModErr kallsyms_lookup_name(const char* name, SymbolHit& out, SymbolMatchMode mode) {
    return lookup_name_impl(name, out, mode, true);
}

// A local probe contract, not a shared printf flag: only a missing alternative
// is quiet. Authentication, malformed addresses and all final errors survive.
__attribute__((visibility("hidden"))) KModErr maplesu_lookup_optional_symbol(const char* name, uint64_t& out) {
    SymbolHit hit{};
    const auto error = lookup_name_impl(name, hit, SymbolMatchMode::Exact, false);
    out = hit.addr;
    return error;
}

// 对外：按名字查所有符号。
//
//   hits = __find_kallsyms_cache(...) 非空：
//       out.reserve(hits.size())；逐个 SymbolHit{addr, strncpy(name)} 
//   否则 mode==Exact：__kallsyms_lookup_name(name, addr)；
KModErr kallsyms_lookup_name_array(const char * name, std::vector<SymbolHit> & out,
                                   SymbolMatchMode mode) try {
    out.clear();
    if (!name || name[0] == '\0') return KModErr::ERR_MODULE_PARAM;

    RequestIdentity identity;
    if (!identity.capture()) return KModErr::ERR_MODULE_ROOT_KEY;
    RequestMetadataFacts facts{};
    const RequestOwnerBinding* owner = nullptr;
    if (identity.auth_state & 1) {
        bool supported = false;
        const auto error = maplesu_kernel_metadata_facts(facts, supported);
        if (is_failed(error)) return error;
        if (!supported) return KModErr::ERR_MODULE_TEST_CHANNEL;
        if (!identity.matches() || !maplesu_request_owner_binding_matches(facts.owner))
            return KModErr::ERR_MODULE_ROOT_KEY;
        owner = &facts.owner;
    }
    std::unordered_map<std::string, uint64_t>* cache_pointer = nullptr;
    const auto cache_error = __get_kallsyms_cache(identity, owner, cache_pointer);
    if (is_failed(cache_error)) return cache_error;
    auto& cache = *cache_pointer;
    std::vector<SymbolHit> candidates;

    std::vector<std::pair<std::string, uint64_t>> hits = __find_kallsyms_cache(cache, name, mode);
    if (!hits.empty()) {
        candidates.reserve(hits.size());
        for (const std::pair<std::string, uint64_t> & hit : hits) {
            SymbolHit symbol_hit{};
            symbol_hit.addr = hit.second;
            strncpy(symbol_hit.name, hit.first.c_str(), sizeof(symbol_hit.name) - 1);
            symbol_hit.name[sizeof(symbol_hit.name) - 1] = '\0';
            candidates.emplace_back(symbol_hit);
        }
        if (!identity.matches() || (owner && !maplesu_request_owner_binding_matches(*owner))) {
            cache.clear();
            return KModErr::ERR_MODULE_ROOT_KEY;
        }
        out = std::move(candidates);
        return KModErr::OK;
    }
    if (owner && !(facts.capabilities & MAPLESU_CAP_EXEC)) return KModErr::ERR_MODULE_TEST_CHANNEL;

    KModErr err = KModErr::OK;
    if (mode == SymbolMatchMode::Exact) {
        uint64_t kaddr = 0;
        err = __kallsyms_lookup_name(name, kaddr);
        if (is_ok(err) && kaddr != 0) {
            SymbolHit symbol_hit{};
            symbol_hit.addr = kaddr;
            strncpy(symbol_hit.name, name, sizeof(symbol_hit.name) - 1);
            symbol_hit.name[sizeof(symbol_hit.name) - 1] = '\0';
            candidates.emplace_back(std::move(symbol_hit));
        }
    } else {
        err = __find_proc_kallsyms(name, candidates, mode);
    }

    switch (err) {
        case KModErr::ERR_MODULE_SYMBOL_NOT_EXIST:
            if (get_symbol_lookup_printf_silent_d8685f89f10ca8eb96df766c8babd6c3()) {
                printf("'%s': symbol not found.\n", name);
            }
            return err;
        case KModErr::OK:
            if (!identity.matches()) {
                cache.clear();
                return KModErr::ERR_MODULE_ROOT_KEY;
            }
            for (const SymbolHit & hit : candidates) {
                if (hit.addr == 0) continue;
                if (hit.name[0] == '\0') continue;
                cache[std::string(hit.name)] = hit.addr;
            }
            if (!identity.matches()) {
                cache.clear();
                return KModErr::ERR_MODULE_ROOT_KEY;
            }
            out = std::move(candidates);
            return err;
        default:
            return err;
    }
} catch (const std::bad_alloc&) {
    out.clear();
    return KModErr::ERR_NO_MEM;
}

// 判断系统调用参数是否经 struct pt_regs 传递。
//
//   uint64_t addr = 0;
// 语义（推断，仅注释）：能查到 __arm64_sys_read 说明 >= 4.17 且 syscall 已带 wrapper；
bool is_syscall_args_in_ptregs() {
    SymbolLookupSilentGuard_c67c0e4fed21dd11b34c67e0a5b878c8 silent_guard;
    uint64_t sys_read_kaddr = 0;
    if (is_ok(kallsyms_lookup_name("__arm64_sys_read", sys_read_kaddr))) {
        return true;
    }
    return !is_kernel_version_less("4.17.0");
}

// 获取 avc_denied 的内核地址，以及它 ret 前可安装 HOOK 的地址。
//
// 说明（推断，仅注释）：hook_info 处是一条 B 指令，imm26 << 2 得到字节偏移，
// 即「ret 前」的目标地址，厂商标保护场景下用它绕开直接 hook 入口。
KModErr get_avc_denied_kaddr(uint64_t & func_entry_kaddr, uint64_t & ret_after_can_hook_kaddr) {
    uint64_t func_kaddr = 0;
    uint64_t hook_info = 0;
    KModErr err = get_avc_denied_info(func_kaddr, hook_info);
    if (is_failed(err)) return err;

    func_entry_kaddr = func_kaddr;
    uint32_t insn = 0;
    err = read_kernel_mem(hook_info, &insn, sizeof(insn));
    if (is_ok(err)) {
        const int32_t branch_offset = static_cast<int32_t>(insn << 6) >> 4;
        ret_after_can_hook_kaddr = hook_info + static_cast<uint64_t>(branch_offset);
    }
    return err;
}

}  // namespace kernel_module
