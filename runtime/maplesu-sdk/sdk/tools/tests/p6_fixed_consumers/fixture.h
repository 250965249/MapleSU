#pragma once
#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <string>
#include <string_view>
#include <vector>
#include <sys/types.h>
#include "module_err_def.h"

#define MAPLESU_EARLY_FIXED_OEM_MTK 1u
#define MAPLESU_EARLY_FIXED_OEM_OPLUS_GUARD 2u
#define MAPLESU_EARLY_FIXED_OEM_OPLUS_INTE 3u
#define MAPLESU_EARLY_FIXED_ROOT_ENV 4u
#define MAPLESU_EARLY_FIXED_EFFECT_ATTEMPTED 1u
static constexpr int kUltraErrSetSelinuxEnforce = -19933;
struct Request { uint32_t operation, mode, exploit; uint64_t value; };
struct Status { uint32_t version=1,sequence=9,enforcing=1,policyload=1,deny_unknown=0; };
static struct {
    bool helper=true;
    KModErr transport=KModErr::OK, root_error=KModErr::OK, storage_error=KModErr::OK;
    KModErr legacy_error=KModErr::ERR_MODULE_READ_FILE, work_error=KModErr::OK;
    int transport_errno=0, native_errno=0, fail_operation=0;
    int64_t business_code=0;
    uint64_t target_count=1;
    unsigned legacy_calls=0, roots=0, work_calls=0, remove_calls=0;
    unsigned properties=0, enforcement=0, adbd=0, cve=0, legacy_store=0;
    bool work_value=false, fail_work_enable=false;
    int enforcing=1;
    std::string boot_selinux="enforce";
    Status status;
    std::vector<Request> requests;
    std::vector<std::string> events;
} fixture;
static void reset() { fixture={}; std::filesystem::remove("/work/remove-mode"); errno=0; }
static int fixture_printf(const char*,...) { errno=EBADF; return 0; }
static int fixture_puts(const char*) { errno=EBUSY; return 0; }
#define printf fixture_printf
#define puts fixture_puts

namespace kernel_module {
struct RequestEarlyFixedResult { int64_t code=0; int32_t native_errno=0; uint32_t effects=0; uint64_t values[3]{}; };
struct RequestSharedBool { uint64_t id=0,address=0; };
static bool maplesu_request_helper_mode() { return fixture.helper; }
static KModErr maplesu_request_helper_fixed(uint32_t op,uint32_t mode,uint32_t exploit,
    uint64_t value,RequestEarlyFixedResult& out) {
    fixture.requests.push_back({op,mode,exploit,value});
    fixture.events.push_back("fixed-"+std::to_string(op));
    out={}; errno=fixture.transport_errno;
    if (fixture.fail_operation==static_cast<int>(op)) {
        out.code=fixture.business_code; out.native_errno=fixture.native_errno;
        out.effects=MAPLESU_EARLY_FIXED_EFFECT_ATTEMPTED;
        return fixture.transport;
    }
    out.effects=MAPLESU_EARLY_FIXED_EFFECT_ATTEMPTED;
    if(op<=3) out.values[0]=fixture.target_count;
    if(op==8) fixture.status.sequence=value;
    if(op==7) {
        out.values[0]=fixture.status.version | (uint64_t(fixture.status.sequence)<<32);
        out.values[1]=fixture.status.enforcing | (uint64_t(fixture.status.policyload)<<32);
        out.values[2]=fixture.status.deny_unknown;
    }
    return KModErr::OK;
}
// BUSINESS_ADAPTER
static KModErr maplesu_hook_shared_bool_store(const RequestSharedBool&,bool value) {
    ++fixture.legacy_store; return value ? KModErr::OK : KModErr::ERR_MODULE_PARAM;
}
struct caps_info { uint64_t inheritable=7,permitted=7,effective=7,bounding=7,ambient=7; };
static KModErr get_current_caps_snapshot(caps_info& caps,bool& ambient) { ++fixture.legacy_calls; caps={}; ambient=true; return fixture.legacy_error; }
static uint64_t get_cap_ability_max() { return 7; }
static KModErr get_task_struct_cred_offset(uint32_t& v) { v=1; return KModErr::OK; }
static KModErr get_cred_uid_offset(uint32_t& v) { v=2; return KModErr::OK; }
static KModErr get_cred_euid_offset(uint32_t& v) { v=3; return KModErr::OK; }
static KModErr get_task_struct_seccomp_offset(uint32_t& v) { v=4; return KModErr::OK; }
static KModErr get_cred_cap_inheritable_offset(uint32_t& v) { v=5; return KModErr::OK; }
static KModErr get_avc_denied_kaddr(uint64_t& a,uint64_t& r) { a=0x1000;r=0x1004;return KModErr::OK; }
static KModErr get_filldir64_addr(uint64_t& a) { a=0x2000;return KModErr::OK; }
enum class SymbolMatchMode { Prefix };
struct SymbolHit { uint64_t addr=0; char name[64]{}; };
static KModErr kallsyms_lookup_name(const char*,uint64_t& out) { ++fixture.legacy_calls;out=0x3000;return fixture.legacy_error; }
static KModErr kallsyms_lookup_name(const char* n,SymbolHit& out,SymbolMatchMode) { std::strcpy(out.name,n); return kallsyms_lookup_name(n,out.addr); }
struct OwnedHookActor {};
static bool is_kernel_version_less(const char*) { ++fixture.legacy_calls;return false; }
enum class KernMemProt { KMP_RW };
static KModErr read_kernel_mem(uint64_t,void* out,uint32_t size) { ++fixture.legacy_calls;std::memset(out,0,size);return fixture.legacy_error; }
static KModErr write_kernel_mem(uint64_t,const void*,uint32_t,KernMemProt) { ++fixture.legacy_calls;return fixture.legacy_error; }
}
enum class EarlySelinuxOperation : uint32_t { Prepare=5,Enable=6,ReadStatus=7,WriteSequence=8 };
using RequestEarlySelinuxResult=kernel_module::RequestEarlyFixedResult;
// SELINUX_ADAPTER
namespace maplesu::storage {
struct StorageLocator { char kernel_component[17]="ABCDEFGHIJKLMNO1";char system_component[18]="ABCDEFGHIJKLMNO1A"; };
struct StorageContext { StorageLocator locator;std::string module_id; };
static KModErr current_context(StorageContext& out) { out={};return fixture.storage_error; }
}
static KModErr patch_kernel_handler() { ++fixture.legacy_calls;errno=EIO;return fixture.legacy_error; }
static KModErr resolve_oplus_inte_ret0_patch_targets() { ++fixture.legacy_calls;errno=EIO;return fixture.legacy_error; }
static KModErr resolve_oplus_guard_ret0_patch_targets() { ++fixture.legacy_calls;errno=EIO;return fixture.legacy_error; }
static KModErr get_remove_bypass_mode_flag_path(std::string& path) { path="/work/remove-mode";return fixture.storage_error; }
static void rmmod(const char*) { ++fixture.remove_calls; }
static KModErr set_work_normal(bool value) {
    ++fixture.work_calls;fixture.work_value=value;
    if (fixture.fail_work_enable && value) {errno=EIO;return KModErr::ERR_MODULE_WRITE_FILE;}
    errno=EACCES;return fixture.work_error;
}
static KModErr set_current_root(bool) { ++fixture.roots;return fixture.root_error; }
static uid_t fixture_getuid() { return 0; }
static int fixture_prctl(int,...) { return 0; }
#define getuid fixture_getuid
#define prctl fixture_prctl
constexpr int PR_GET_SECCOMP=21,PR_GET_SECUREBITS=27;
struct SymbolLookupSilentGuard_c67c0e4fed21dd11b34c67e0a5b878c8 {};
struct KernelSymbolOffset {uint64_t avc_denied_ret_addr,filldir64_addr,compat_filldir_addr,hbt_filldir64_addr,iterate_dir_addr,audit_log_start_addr;};
struct PatchBase {PatchBase(uint32_t,uint32_t,uint32_t,uint32_t){}};
struct PatchAvcDenied {PatchAvcDenied(const PatchBase&,uint64_t){}KModErr patch_avc_denied(){++fixture.legacy_calls;return fixture.legacy_error;}};
struct PatchFilldir64 {PatchFilldir64(const PatchBase&,uint64_t){}KModErr patch_filldir64(const std::vector<std::string>&){++fixture.legacy_calls;return fixture.legacy_error;}};
struct PatchCompatFilldir {PatchCompatFilldir(const PatchBase&,uint64_t){}KModErr patch_compat_filldir(const std::vector<std::string>&){++fixture.legacy_calls;return fixture.legacy_error;}};
struct PatchAuditLogStart {PatchAuditLogStart(const PatchBase&,uint64_t){}KModErr patch_audit_log_start(){++fixture.legacy_calls;return fixture.legacy_error;}};
struct PatchMtkHbtFilldir64 {PatchMtkHbtFilldir64(const PatchBase&,uint64_t){}KModErr generate_hook_fake_filldir64_owned(const std::vector<std::string>&,uint64_t&,kernel_module::OwnedHookActor&){++fixture.legacy_calls;return fixture.legacy_error;}};
struct PatchIterateDir {PatchIterateDir(const PatchBase&,uint64_t){}KModErr patch_iterate_dir_owned(uint64_t,uint64_t,const kernel_module::OwnedHookActor&,bool&){++fixture.legacy_calls;return fixture.legacy_error;}};
struct GeneratedActorStaging {struct Identity{bool capture(){return true;}bool matches(){return true;}}identity;kernel_module::OwnedHookActor actor;bool transferred=false;};
namespace maplesu::sdk {
enum class InstallMode:uint32_t { Boot=0,HotLoad=1 };
enum class ExploitMethod:uint32_t { None=0,Magica=1,CVE2026_43499=2 };
static KModErr get_kernel_file_dir_name(std::string& out) { out="ABCDEFGHIJKLMNO1";return fixture.storage_error; }
}
namespace selinux_procattr {static int setcon(const char*){return 0;}static int setexeccon(const char*){return 0;}}
namespace resetprop::detail {static std::string& resetprop_bin_path_ref(){static std::string path;return path;}}
struct selinux_kernel_status {uint32_t version=0,sequence=0,enforcing=0,policyload=0,deny_unknown=0;};
struct SelinuxHookSwitch {bool fixed=false;uint64_t address=0;kernel_module::RequestSharedBool shared;};
struct SelinuxState {int32_t status=0;std::string boot_selinux;};
static constexpr uint64_t kKernelAddressFloor=0xffff000000000000ULL;
static constexpr char kDataDirFormat[]="/work/%s/",kResetpropBinName[]="resetprop";
static constexpr char kPatchSequencePrintFormat[]="patch:%s",kSelinuxStatusPrintFormat[]="status:%d",kBootSelinuxPrintFormat[]="boot:%s";
static constexpr char kBootSelinuxProp[]="boot-selinux",kSelinuxEnforceText[]="enforce",kKernelVersion4_14[]="4.14.0";
static constexpr char kInitSelinuxContext[]="init",kRestoreconAdbdConfigProp[]="restore-adbd",kRestoreconShellProp[]="restore-shell";
static constexpr char kProcSuidDumpable[]="/work/missing-suid-dumpable",kPropertyZero[]="0",kAdbForcedDisabledMarker[]="adb-marker",kForkFailFormat[]="fork:%s";
static KModErr get_selinux_kernel_status_page_kaddr(uint64_t& a) { ++fixture.legacy_calls;a=kKernelAddressFloor;return fixture.legacy_error; }
static KModErr prepare_selinux_status_hooks(SelinuxHookSwitch& out) { ++fixture.legacy_calls;out.address=kKernelAddressFloor;out.shared={1,kKernelAddressFloor};return fixture.legacy_error; }
static int get_selinux_enforce_status() {return fixture.enforcing;}
static std::string get_system_property(const char*) {return fixture.boot_selinux;}
static void CVE2026_43499_fix_selinux() {++fixture.cve;}
static void enforce_property_baseline() {++fixture.properties;fixture.events.push_back("properties");}
static KModErr commit_selinux_enforcing_state() {++fixture.enforcement;fixture.enforcing=1;fixture.status.enforcing=1;fixture.events.push_back("enforcing");return KModErr::OK;}
static void close_adbd() {++fixture.adbd;fixture.events.push_back("adbd");}
static void fork_execve_cmdline(const char*) {}
static pid_t fixture_fork() {return 101;}
static pid_t fixture_waitpid(pid_t p,int*,int) {return p;}
static unsigned fixture_sleep(unsigned) {return 0;}
[[noreturn]] static void fixture_exit(int) {std::abort();}
#define fork fixture_fork
#define waitpid fixture_waitpid
#define sleep fixture_sleep
#define _exit fixture_exit
