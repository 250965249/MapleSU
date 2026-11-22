// module proc cmdline implementation.
//
// 冻结成员里符号查找静音守卫的类名带本成员专属的 hash 后缀
// （_ZN56SymbolLookupSilentGuard_c67c0e4f...C2Ev/D2Ev），而公共头里的类名
// 是另一个 hash；翻译单元内改名以复现冻结成员的符号面。
#define SymbolLookupSilentGuard_8dfccc5cf454087c7314725d3487e703 \
    SymbolLookupSilentGuard_c67c0e4fed21dd11b34c67e0a5b878c8

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <functional>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

#include "kernel_module_kit_umbrella.h"

struct fd_guard {
    int fd = -1;

    void reset(int new_fd) {
        if (fd > -1) {
            ::close(fd);
        }
        fd = new_fd;
    }

    ~fd_guard() { reset(-1); }
};

// exec_kernel_shellcode_no_result —— 生成一段内核 shellcode 并执行（无返回值使用）。
//   aarch64_asm_ctx ctx = init_aarch64_asm();
//   Assembler* a = ctx.assembler();
//   arm64_module_asm_func_start(a);
//   err = emit(a);                       // 调用方提供发射闭包
//   if (is_ok(err)) {
//       arm64_module_asm_func_end(a);
//       execute_kernel_asm_func(aarch64_asm_to_bytes(a), result_addr);
//   }
static KModErr exec_kernel_shellcode_no_result(
    std::function<KModErr(asmjit::a64::Assembler*)> emit) {
    aarch64_asm_ctx asm_ctx = init_aarch64_asm();
    asmjit::a64::Assembler* a = asm_ctx.assembler();

    kernel_module::arm64_module_asm_func_start(a);
    KModErr err = emit(a);
    if (is_failed(err)) {
        return err;
    }
    kernel_module::arm64_module_asm_func_end(a);

    std::vector<uint8_t> func_bytes = aarch64_asm_to_bytes(a);
    uint64_t result_addr = 0;
    return kernel_module::execute_kernel_asm_func(func_bytes, result_addr);
}

// 全局匿名 namespace：kpath / scoped_kpath / acquire_kpath
// （mangling 无命名空间前缀，实测 _ZN12_GLOBAL__N_1…，故必须放全局匿名 namespace）
namespace {

// 内核 struct path（include/linux/path.h：{struct vfsmount *mnt; struct dentry *dentry;}）
struct kpath {
    uint64_t mnt = 0;
    uint64_t dentry = 0;
};

// 用内核态 kern_path() 拿到的 struct path 的作用域守卫。
//   if (path_buf_kaddr == 0) { memset(this, 0, 16); return; }
//   memset(this, 0, 24);                       // 先清状态，防重入/重复释放
//   exec_kernel_shellcode_no_result([buf](a) { path_put(a, err, buf); });
//   free_kernel_mem(path_buf_kaddr);
struct scoped_kpath {
    kpath path;
    uint64_t path_buf_kaddr = 0;

    void reset() {
        if (path_buf_kaddr == 0) {
            std::memset(static_cast<void*>(&path), 0, sizeof(path));
            return;
        }
        const uint64_t kaddr = path_buf_kaddr;
        std::memset(static_cast<void*>(this), 0, sizeof(*this));
        exec_kernel_shellcode_no_result([kaddr](asmjit::a64::Assembler* a) -> KModErr {
            KModErr err = KModErr::ERR_MODULE_PARAM;
            kernel_module::export_symbol::path_put(a, err, kaddr);
            return err;
        });
        kernel_module::free_kernel_mem(kaddr);
    }
    ~scoped_kpath() { reset(); }
};

// 在内核态对 path 调 kern_path()，把结果 struct path 写到内核缓冲 path_buf_kaddr，
// 成功后交给 out（out 接管该内核缓冲，析构时 path_put + free_kernel_mem）。
//   页面级内核缓冲 alloc_kernel_mem(get_page_size()) + fill00_kernel_mem
//   闭包里 aarch64_asm_set_x_cstr_ptr(a, x10, path) 把路径字符串嵌进代码段，
//   再用 export_symbol::kern_path(a, err, x10, LOOKUP_FOLLOW, path_buf_kaddr)。
KModErr acquire_kpath(const std::string& path, scoped_kpath& out) {
    const uint32_t page_size = kernel_module::get_page_size();
    uint64_t buf_kaddr = 0;
    KModErr err = kernel_module::alloc_kernel_mem(page_size, buf_kaddr);
    if (is_failed(err)) {
        return err;
    }
    err = kernel_module::fill00_kernel_mem(buf_kaddr, page_size, kernel_module::KernMemProt::KMP_RW);
    if (is_failed(err)) {
        kernel_module::free_kernel_mem(buf_kaddr);
        return err;
    }

    err = exec_kernel_shellcode_no_result(
        [buf_kaddr, &path](asmjit::a64::Assembler* a) -> KModErr {
            KModErr call_err = KModErr::ERR_MODULE_PARAM;
            aarch64_asm_set_x_cstr_ptr(a, asmjit::a64::x10, path);
            kernel_module::export_symbol::kern_path(
                a, call_err, asmjit::a64::x10,
                kernel_module::export_symbol::LookupFlags::LOOKUP_FOLLOW, buf_kaddr);
            return call_err;
        });
    if (is_failed(err)) {
        kernel_module::free_kernel_mem(buf_kaddr);
        return err;
    }

    kpath kp;
    err = kernel_module::read_kernel_mem(buf_kaddr, &kp, sizeof(kp));
    if (is_failed(err)) {
        kernel_module::free_kernel_mem(buf_kaddr);
        return err;
    }

    out.reset();
    out.path = kp;
    out.path_buf_kaddr = buf_kaddr;
    return KModErr::OK;
}

}  // namespace

// default_modules::module_proc_cmdline —— 模块主体
namespace default_modules {
namespace module_proc_cmdline {

// 命令行分隔符：' ' 与 '\t','\n','\v','\f','\r'（等价 isspace）。
// 判定必须写成“' ' 或 (uc - '\t') <= ('\r' - '\t')”的形态：冻结成员用
// cmp/ccmn 的双条件编码（cmp #0x20 + ccmn (uc-0xe),#0x5），写成区间 >=/<= 会被
// 折成位掩码形态，指令序列与冻结不同。
static bool is_cmdline_sep(char c) {
    const unsigned char uc = static_cast<unsigned char>(c);
    return uc == static_cast<unsigned char>(' ') ||
           (uc >= static_cast<unsigned char>('\t') && uc <= static_cast<unsigned char>('\r'));
}

// 单个命令行 token 的解析结果。
//   name      —— '=' 左侧（trim 后）；无 '=' 时等于 raw
//   value     —— '=' 右侧（unquote 后）
//   has_value —— 是否存在 '='
struct CmdlineItem {
    std::string raw;
    std::string name;
    std::string value;
    bool has_value = false;
    bool quoted = false;
};

//   s.erase(begin, find_if_not(sep)); s.erase(find_last_not_of(sep)+1, end);）
static std::string trim_copy(std::string s) {
    const std::string::iterator begin =
        std::find_if_not(s.begin(), s.end(), is_cmdline_sep);
    s.erase(s.begin(), begin);
    const std::string::iterator end =
        std::find_if_not(s.rbegin(), s.rend(), is_cmdline_sep).base();
    s.erase(end, s.end());
    return s;
}

//   s = trim_copy(s); if (s.size() > 1 && s.front() == '"' && s.back() == '"')
//       s = s.substr(1, s.size() - 2);）
static std::string unquote_copy(std::string s) {
    s = trim_copy(std::move(s));
    if (s.size() > 1 && s.front() == '"' && s.back() == '"') {
        s = s.substr(1, s.size() - 2);
    }
    return s;
}

static std::string lower_copy(std::string s) {
    for (char& c : s) {
        const unsigned char uc = static_cast<unsigned char>(c);
        if (uc >= static_cast<unsigned char>('A') && uc <= static_cast<unsigned char>('Z')) {
            c = static_cast<char>(uc | 0x20u);
        }
    }
    return s;
}

// 按「引号外空白」切 token；引号与反斜杠**原样保留**在 token 里
//   in_quotes；escaped 下的下一个字符无条件入 token；引号内的空白不切分。）
static std::vector<std::string> split_cmdline(const std::string& cmdline) {
    std::vector<std::string> tokens;
    const size_t n = cmdline.size();
    size_t i = 0;
    while (i < n) {
        while (i < n && is_cmdline_sep(cmdline[i])) {
            ++i;
        }
        if (i >= n) {
            break;
        }
        std::string token;
        bool in_quotes = false;
        bool escaped = false;
        while (i < n) {
            const char c = cmdline[i];
            if (escaped) {
                token.push_back(c);
                escaped = false;
                ++i;
                continue;
            }
            if (c == '\\') {
                token.push_back('\\');
                escaped = true;
                ++i;
                continue;
            }
            if (c == '"') {
                token.push_back('"');
                in_quotes = !in_quotes;
                ++i;
                continue;
            }
            if (!in_quotes && is_cmdline_sep(c)) {
                break;  // 空白留给外层跳过
            }
            token.push_back(c);
            ++i;
        }
        if (!token.empty()) {
            tokens.push_back(token);
        }
    }
    return tokens;
}

// init —— 见文件头说明。返回值即 KModErr；失败时打印
KModErr init() {
    KModErr ret = KModErr::OK;
    {
        SymbolLookupSilentGuard_8dfccc5cf454087c7314725d3487e703 silent_guard;

        uint64_t cmdline_kaddr = 0;
        ret = kernel_module::kallsyms_lookup_name("saved_command_line", cmdline_kaddr);
        if (is_ok(ret)) {
            uint64_t cmdline_ptr = 0;
            ret = kernel_module::read_kernel_mem(cmdline_kaddr, &cmdline_ptr, sizeof(cmdline_ptr));
            if (is_ok(ret)) {
                // --- 逐字节把内核字符串读出来（上限 64 KiB）-------------------
                std::string raw_cmdline;
                if (cmdline_ptr == 0) {
                    ret = KModErr::ERR_MODULE_PARAM;
                } else {
                    for (uint64_t i = 0;; ++i) {
                        if (i == 65536) {
                            ret = KModErr::ERR_MODULE_ALLOC_MEM;
                            break;
                        }
                        char ch = 0;
                        ret = kernel_module::read_kernel_mem(cmdline_ptr + i, &ch, 1);
                        if (is_failed(ret)) {
                            break;
                        }
                        if (ch == 0) {
                            break;
                        }
                        raw_cmdline.push_back(ch);
                    }
                }

                if (is_ok(ret)) {
                    if (raw_cmdline.empty()) {
                        puts("raw_cmdline is empty!");
                    } else {
                        // ---- 切 token -----------------------------------------
                        const std::vector<std::string> tokens = split_cmdline(raw_cmdline);

                        // ---- 逐 token 判定并重拼 sanitized --------------------
                        std::string sanitized;
                        bool changed = false;
                        bool first = true;
                        for (const std::string& token : tokens) {
                            CmdlineItem item;
                            item.raw = trim_copy(token);
                            const std::string::size_type eq_pos = item.raw.find('=');
                            if (eq_pos == std::string::npos) {
                                item.name = item.raw;
                                item.has_value = false;
                            } else {
                                item.name = trim_copy(item.raw.substr(0, eq_pos));
                                item.value = unquote_copy(item.raw.substr(eq_pos + 1));
                                item.has_value = true;

                                const std::string key_lower = lower_copy(trim_copy(item.name));
                                if (key_lower == "msm_kgsl.preempt_enable" ||
                                    key_lower == "androidboot.selinux") {
                                    changed = true;
                                    continue;
                                }
                                // 过滤 3：value 里内嵌 androidboot.<x>=…
                                //   p = value_lower.find("androidboot.");
                                //   if (p != npos) { q = value_lower.find('=', p);
                                //                    if (q != npos && q > p + 12) drop; }
                                //   （12 == strlen("androidboot.")）
                                const std::string value_lower = lower_copy(unquote_copy(item.value));
                                const std::string::size_type p = value_lower.find("androidboot.");
                                if (p != std::string::npos) {
                                    const std::string::size_type q = value_lower.find('=', p);
                                    if (q != std::string::npos && q > p + 12) {
                                        changed = true;
                                        continue;
                                    }
                                }
                            }

                            const std::string kept = trim_copy(item.raw);
                            if (!kept.empty()) {
                                if (!first) {
                                    sanitized.push_back(' ');
                                }
                                sanitized.append(kept);
                                first = false;
                            } else {
                                changed = true;
                            }
                        }

                        // changed ? sanitized : raw_cmdline
                        std::string result = changed ? sanitized : raw_cmdline;
                        // 两个同文本不同字面量）；第二次不可达，等价于一次检查。
                        if (!changed || result == raw_cmdline) {
                            puts("patch_kernel_handler ret: OK, no change");
                        } else if (result.size() > raw_cmdline.size()) {
                            puts("patch_kernel_handler ret: sanitized cmdline is longer than raw "
                                 "cmdline, skip");
                            ret = KModErr::ERR_MODULE_PARAM;
                        } else {
                            // ---- 覆盖内核 saved_command_line ----------------
                            ret = kernel_module::fill00_kernel_mem(
                                cmdline_ptr, static_cast<uint32_t>(raw_cmdline.size() + 1),
                                kernel_module::KernMemProt::KMP_RW);
                            if (is_ok(ret)) {
                                ret = kernel_module::write_kernel_mem(
                                    cmdline_ptr, result.data(),
                                    static_cast<uint32_t>(result.size() + 1),
                                    kernel_module::KernMemProt::KMP_RW);
                            }
                            if (is_ok(ret)) {
                                // ---- 同步 /proc/cmdline 的 inode i_size ------
                                const uint64_t new_size = result.size() + 1;
                                const char* const kProcCmdline = "/proc/cmdline";
                                {
                                    fd_guard fd;
                                    fd.fd = ::open(kProcCmdline, O_RDONLY);
                                    if (fd.fd < 0) {
                                        printf("open '%s' failed\n", kProcCmdline);
                                        ret = KModErr::ERR_MODULE_OPEN_DIR;
                                    } else {
                                        struct stat st {};
                                        if (::fstat(fd.fd, &st) != 0) {
                                            printf("fstat '%s' failed\n", kProcCmdline);
                                            ret = KModErr::ERR_MODULE_OPEN_DIR;
                                        } else if (st.st_size == 0) {
                                            ret = KModErr::OK;
                                        } else {
                                            // 内核态 kern_path("/proc/cmdline") → struct path
                                            scoped_kpath kp;
                                            const std::string path(kProcCmdline);
                                            ret = acquire_kpath(path, kp);
                                            if (is_ok(ret)) {
                                                uint32_t d_inode_off = 0;
                                                ret = kernel_module::get_dentry_d_inode_offset(
                                                    d_inode_off);
                                                if (is_ok(ret)) {
                                                    uint64_t inode = 0;
                                                    ret = kernel_module::read_kernel_mem(
                                                        kp.path.dentry + d_inode_off, &inode,
                                                        sizeof(inode));
                                                    if (is_ok(ret)) {
                                                        printf("inode:%lx\n",
                                                               static_cast<unsigned long>(inode));
                                                        uint32_t i_size_off = 0;
                                                        ret = kernel_module::get_inode_i_size_offset(
                                                            i_size_off);
                                                        if (is_ok(ret)) {
                                                            // 打印的仍是 inode 值而非偏移，照原样保留。
                                                            printf("i_size offset:%lx\n",
                                                                   static_cast<unsigned long>(inode));
                                                            ret = kernel_module::write_kernel_mem(
                                                                inode + i_size_off, &new_size,
                                                                sizeof(new_size),
                                                                kernel_module::KernMemProt::KMP_RW);
                                                            if (is_ok(ret)) {
                                                                // 成功：放弃 kpath 守卫
                                                                // （不 path_put，保住内核
                                                                //   对 inode 的引用）
                                                                std::memset(static_cast<void*>(&kp), 0,
                                                                            sizeof(kp));
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }  // scoped_kpath 析构
                                    }
                                }
                                if (is_ok(ret)) {
                                    puts("patch_kernel_handler ret: OK");
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if (is_failed(ret)) {
        printf("patch_kernel_handler ret: %s\n", to_string(ret).c_str());
    }
    return ret;
}

const char* get_module_eng_name() {
    return "module_proc_cmdline";
}

}  // namespace module_proc_cmdline
}  // namespace default_modules
