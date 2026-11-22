#![allow(clippy::unreadable_literal)]
use anyhow::{Result, bail};

use crate::ksu_uapi;
use std::cell::Cell;
use std::fs;
use std::io;
use std::os::fd::RawFd;
use std::sync::OnceLock;

// sigsys handler
std::thread_local! {
    #[allow(clippy::missing_const_for_thread_local)]
    static SVC_IN_FLIGHT: Cell<bool> = const { Cell::new(false) };
    #[allow(clippy::missing_const_for_thread_local)]
    static SIGSYS_OCCURRED: Cell<bool> = const { Cell::new(false) };
}

const SYS_SECCOMP: libc::c_int = 1;

fn with_svc_call<F, R>(call: F) -> R
where
    F: FnOnce() -> R,
{
    SVC_IN_FLIGHT.with(|in_flight| in_flight.set(true));
    let result = call();
    SVC_IN_FLIGHT.with(|in_flight| in_flight.set(false));
    result
}

fn take_sigsys_occurred() -> bool {
    SIGSYS_OCCURRED.with(|occurred| occurred.replace(false))
}

extern "C" fn sigsys_handler(
    _sig: libc::c_int,
    info: *mut libc::siginfo_t,
    ctx: *mut libc::c_void,
) {
    unsafe {
        if info.is_null() || ctx.is_null() || (*info).si_code != SYS_SECCOMP {
            return;
        }
        if SVC_IN_FLIGHT.with(Cell::get) {
            SIGSYS_OCCURRED.with(|occurred| occurred.set(true));
        }

        #[cfg(not(target_arch = "riscv64"))]
        let ucontext = ctx.cast::<libc::ucontext_t>();
        #[cfg(target_arch = "aarch64")]
        {
            (*ucontext).uc_mcontext.regs[0] = (-libc::EPERM) as u64;
        }
        #[cfg(target_arch = "x86_64")]
        {
            let rax = libc::REG_RAX as usize;
            (*ucontext).uc_mcontext.gregs[rax] = i64::from(-libc::EPERM);
        }
        #[cfg(target_arch = "riscv64")]
        {
            let ucontext = ctx.cast::<ksu_uapi::ucontext_t>();
            (*ucontext).uc_mcontext.__gregs[ksu_uapi::REG_A0 as usize] =
                (-libc::EPERM) as libc::c_ulong;
        }
    }
}

pub fn setup_sigsys_handler() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_flags = libc::SA_SIGINFO;
        sa.sa_sigaction = sigsys_handler as *const () as usize;
        libc::sigemptyset(std::ptr::addr_of_mut!(sa.sa_mask));
        if libc::sigaction(libc::SIGSYS, std::ptr::addr_of!(sa), std::ptr::null_mut()) != 0 {
            let error = std::io::Error::last_os_error();
            log::warn!("Failed to set SIGSYS handler: {error}");
        }
    }
}

const DRIVER_FD_NAME: &str = "anon_inode:[ksu_driver]";
const SU_DRIVER_FD_NAME: &str = "anon_inode:[ksu_driver_su]";

// Global driver fd cache
static DRIVER_FD: OnceLock<RawFd> = OnceLock::new();
static INFO_CACHE: OnceLock<ksu_uapi::ksu_get_info_cmd> = OnceLock::new();

fn scan_driver_fd() -> io::Result<Option<RawFd>> {
    let fd_dir = fs::read_dir("/proc/self/fd")?;
    let mut driver_fd = None;

    for entry in fd_dir.flatten() {
        if let Ok(fd_num) = entry.file_name().to_string_lossy().parse::<i32>() {
            let link_path = format!("/proc/self/fd/{fd_num}");
            if let Ok(target) = fs::read_link(&link_path) {
                let target_str = target.to_string_lossy();
                if target_str == SU_DRIVER_FD_NAME {
                    return Ok(Some(fd_num));
                }
                if target_str == DRIVER_FD_NAME {
                    driver_fd = Some(fd_num);
                }
            }
        }
    }

    Ok(driver_fd)
}

pub fn claim_inherited_driver_fd() -> io::Result<()> {
    if DRIVER_FD.get().is_none()
        && let Some(fd) = scan_driver_fd()?
    {
        let _ = DRIVER_FD.set(fd);
    }
    Ok(())
}

// Get cached driver fd
fn init_driver_fd() -> Option<RawFd> {
    let fd = scan_driver_fd().ok().flatten();
    if fd.is_none() {
        let mut fd = -1;
        with_svc_call(|| unsafe {
            libc::syscall(
                libc::SYS_reboot,
                ksu_uapi::KSU_INSTALL_MAGIC1,
                ksu_uapi::KSU_INSTALL_MAGIC2,
                0,
                &mut fd,
            )
        });
        if take_sigsys_occurred() {
            eprintln!("KernelSU driver install syscall was blocked by seccomp");
            log::error!("KernelSU driver install syscall was blocked by seccomp");
        }
        if fd >= 0 { Some(fd) } else { None }
    } else {
        fd
    }
}

// ioctl wrapper using libc
fn ksuctl<T>(request: u32, arg: *mut T) -> Result<i32> {
    let fd = *DRIVER_FD.get_or_init(|| init_driver_fd().unwrap_or(-1));
    if fd < 0 {
        bail!("could not retrieve kernelsu driver fd")
    }
    unsafe {
        let ret = libc::ioctl(fd as libc::c_int, request as i32, arg);
        if ret < 0 {
            return Err(anyhow::Error::new(io::Error::last_os_error()).context("ksuctl failed"));
        }
        Ok(ret)
    }
}

// API implementations
pub fn get_info() -> ksu_uapi::ksu_get_info_cmd {
    *INFO_CACHE.get_or_init(|| {
        let mut cmd = ksu_uapi::ksu_get_info_cmd {
            version: 0,
            flags: 0,
            features: 0,
            uapi_version: 0,
        };
        if ksuctl(ksu_uapi::KSU_IOCTL_GET_INFO, &raw mut cmd).is_err() {
            let _ = ksuctl(ksu_uapi::KSU_IOCTL_GET_INFO_LEGACY, &raw mut cmd);
        }
        cmd
    })
}

pub fn get_version() -> i32 {
    get_info().version as i32
}

pub fn is_late_load() -> bool {
    get_info().flags & ksu_uapi::KSU_GET_INFO_FLAG_LATE_LOAD != 0
}

pub fn is_lkm() -> bool {
    get_info().flags & ksu_uapi::KSU_GET_INFO_FLAG_LKM != 0
}

/// Whether the kernel runs module preinit actions on boot.
pub fn is_preinit_supported() -> bool {
    get_info().flags & ksu_uapi::KSU_GET_INFO_FLAG_PREINIT != 0
}

pub const fn uapi_version() -> u32 {
    ksu_uapi::KERNEL_SU_UAPI_VERSION
}

pub fn runtime_mode() -> &'static str {
    if is_late_load() {
        "late-load"
    } else if is_lkm() {
        "lkm"
    } else {
        "built-in"
    }
}

pub fn ensure_uapi_version_matched() -> anyhow::Result<()> {
    let kernel_uapi = get_info().uapi_version;
    let userspace_uapi = uapi_version();
    if kernel_uapi != userspace_uapi {
        bail!(
            "UAPI version mismatch: kernel={kernel_uapi}, ksud={userspace_uapi}. Please update KernelSU!"
        );
    }
    Ok(())
}

pub fn grant_root() -> Result<()> {
    ksuctl(ksu_uapi::KSU_IOCTL_GRANT_ROOT, std::ptr::null_mut::<u8>())?;
    Ok(())
}

fn report_event(event: u32) {
    let mut cmd = ksu_uapi::ksu_report_event_cmd { event };
    let _ = ksuctl(ksu_uapi::KSU_IOCTL_REPORT_EVENT, &raw mut cmd);
}

pub fn report_post_fs_data() {
    report_event(ksu_uapi::EVENT_POST_FS_DATA);
}

pub fn report_services() -> Result<bool> {
    let mut cmd = ksu_uapi::ksu_report_event_cmd {
        event: ksu_uapi::EVENT_SERVICES,
    };
    Ok(ksuctl(ksu_uapi::KSU_IOCTL_REPORT_EVENT, &raw mut cmd)? == 1)
}

pub fn report_boot_complete() {
    report_event(ksu_uapi::EVENT_BOOT_COMPLETED);
}

pub fn report_module_mounted() {
    report_event(ksu_uapi::EVENT_MODULE_MOUNTED);
}

pub fn check_kernel_safemode() -> bool {
    let mut cmd = ksu_uapi::ksu_check_safemode_cmd { in_safe_mode: 0 };
    let _ = ksuctl(ksu_uapi::KSU_IOCTL_CHECK_SAFEMODE, &raw mut cmd);
    cmd.in_safe_mode != 0
}

pub fn set_sepolicy(payload: *const u8, payload_len: u64) -> Result<i32> {
    let mut ioctl_cmd = crate::ksu_uapi::ksu_set_sepolicy_cmd {
        data_len: payload_len,
        data: payload as u64,
    };

    ksuctl(ksu_uapi::KSU_IOCTL_SET_SEPOLICY, &raw mut ioctl_cmd)
}

#[derive(Debug, Clone, Copy, Default)]
pub struct FeatureState {
    pub value: u64,
    pub supported: bool,
    /// Forced by boot config (ksu_config), the kernel refuses to change it
    pub forced: bool,
}

/// Get feature value and support status from kernel
pub fn get_feature(feature_id: u32) -> Result<FeatureState> {
    let mut cmd = ksu_uapi::ksu_get_feature_cmd {
        feature_id,
        value: 0,
        supported: 0,
    };
    ksuctl(ksu_uapi::KSU_IOCTL_GET_FEATURE, &raw mut cmd)?;
    let flags = u32::from(cmd.supported);
    Ok(FeatureState {
        value: cmd.value,
        // older kernels report 1 for supported, matching the flag
        supported: flags & ksu_uapi::KSU_FEATURE_FLAG_SUPPORTED != 0,
        forced: flags & ksu_uapi::KSU_FEATURE_FLAG_FORCED != 0,
    })
}

/// Set feature value in kernel
pub fn set_feature(feature_id: u32, value: u64) -> Result<()> {
    let mut cmd = ksu_uapi::ksu_set_feature_cmd { feature_id, value };
    ksuctl(ksu_uapi::KSU_IOCTL_SET_FEATURE, &raw mut cmd)?;
    Ok(())
}

pub fn get_wrapped_fd(fd: RawFd) -> Result<RawFd> {
    let mut cmd = ksu_uapi::ksu_get_wrapper_fd_cmd {
        fd: fd as u32,
        flags: 0,
    };
    let result = ksuctl(ksu_uapi::KSU_IOCTL_GET_WRAPPER_FD, &raw mut cmd)?;
    Ok(result)
}

pub fn get_sulog_fd() -> Result<RawFd> {
    let mut cmd = ksu_uapi::ksu_get_sulog_fd_cmd { flags: 0 };
    let result = ksuctl(ksu_uapi::KSU_IOCTL_GET_SULOG_FD, &raw mut cmd)?;
    Ok(result)
}

/// Get mark status for a process (pid=0 returns total marked count)
pub fn mark_get(pid: i32) -> Result<u32> {
    let mut cmd = ksu_uapi::ksu_manage_mark_cmd {
        operation: ksu_uapi::KSU_MARK_GET,
        pid,
        result: 0,
    };
    ksuctl(ksu_uapi::KSU_IOCTL_MANAGE_MARK, &raw mut cmd)?;
    Ok(cmd.result)
}

/// Mark a process (pid=0 marks all processes)
pub fn mark_set(pid: i32) -> Result<()> {
    let mut cmd = ksu_uapi::ksu_manage_mark_cmd {
        operation: ksu_uapi::KSU_MARK_MARK,
        pid,
        result: 0,
    };
    ksuctl(ksu_uapi::KSU_IOCTL_MANAGE_MARK, &raw mut cmd)?;
    Ok(())
}

/// Unmark a process (pid=0 unmarks all processes)
pub fn mark_unset(pid: i32) -> Result<()> {
    let mut cmd = ksu_uapi::ksu_manage_mark_cmd {
        operation: ksu_uapi::KSU_MARK_UNMARK,
        pid,
        result: 0,
    };
    ksuctl(ksu_uapi::KSU_IOCTL_MANAGE_MARK, &raw mut cmd)?;
    Ok(())
}

/// Refresh mark for all running processes
pub fn mark_refresh() -> Result<()> {
    let mut cmd = ksu_uapi::ksu_manage_mark_cmd {
        operation: ksu_uapi::KSU_MARK_REFRESH,
        pid: 0,
        result: 0,
    };
    ksuctl(ksu_uapi::KSU_IOCTL_MANAGE_MARK, &raw mut cmd)?;
    Ok(())
}

pub fn nuke_ext4_sysfs(mnt: &str) -> anyhow::Result<()> {
    let c_mnt = std::ffi::CString::new(mnt)?;
    let mut ioctl_cmd = ksu_uapi::ksu_nuke_ext4_sysfs_cmd {
        arg: c_mnt.as_ptr() as u64,
    };
    ksuctl(ksu_uapi::KSU_IOCTL_NUKE_EXT4_SYSFS, &raw mut ioctl_cmd)?;
    Ok(())
}

/// Wipe all entries from umount list
pub fn umount_list_wipe() -> Result<()> {
    let mut cmd = ksu_uapi::ksu_add_try_umount_cmd {
        arg: 0,
        flags: 0,
        mode: ksu_uapi::KSU_UMOUNT_WIPE,
    };
    ksuctl(ksu_uapi::KSU_IOCTL_ADD_TRY_UMOUNT, &raw mut cmd)?;
    Ok(())
}

/// Add mount point to umount list
pub fn umount_list_add(path: &str, flags: u32) -> anyhow::Result<()> {
    let c_path = std::ffi::CString::new(path)?;
    let mut cmd = ksu_uapi::ksu_add_try_umount_cmd {
        arg: c_path.as_ptr() as u64,
        flags,
        mode: ksu_uapi::KSU_UMOUNT_ADD,
    };
    ksuctl(ksu_uapi::KSU_IOCTL_ADD_TRY_UMOUNT, &raw mut cmd)?;
    Ok(())
}

/// Delete mount point from umount list
pub fn umount_list_del(path: &str) -> anyhow::Result<()> {
    let c_path = std::ffi::CString::new(path)?;
    let mut cmd = ksu_uapi::ksu_add_try_umount_cmd {
        arg: c_path.as_ptr() as u64,
        flags: 0,
        mode: ksu_uapi::KSU_UMOUNT_DEL,
    };
    ksuctl(ksu_uapi::KSU_IOCTL_ADD_TRY_UMOUNT, &raw mut cmd)?;
    Ok(())
}

/// Set current process's process group to init_group (pgid = 0)
pub fn set_init_pgrp() -> Result<()> {
    ksuctl(
        ksu_uapi::KSU_IOCTL_SET_INIT_PGRP,
        std::ptr::null_mut::<u8>(),
    )?;
    Ok(())
}

/// Look up the addresses of kernel symbols, exported or not.
///
/// Returns one entry per name, `None` when the running kernel has no such
/// symbol.
pub fn lookup_symbols(names: &[&str]) -> Result<Vec<Option<u64>>> {
    let mut result = Vec::with_capacity(names.len());
    for chunk in names.chunks(ksu_uapi::KSU_LOOKUP_SYMBOLS_MAX as usize) {
        let c_names = chunk
            .iter()
            .map(|name| std::ffi::CString::new(*name))
            .collect::<Result<Vec<_>, _>>()?;
        let ptrs: Vec<u64> = c_names.iter().map(|name| name.as_ptr() as u64).collect();
        let mut addrs = vec![0u64; chunk.len()];
        let mut cmd = ksu_uapi::ksu_lookup_symbols_cmd {
            names: ptrs.as_ptr() as u64,
            addrs: addrs.as_mut_ptr() as u64,
            count: chunk.len() as u32,
            flags: 0,
        };
        ksuctl(ksu_uapi::KSU_IOCTL_LOOKUP_SYMBOLS, &raw mut cmd)?;
        result.extend(addrs.into_iter().map(|addr| (addr != 0).then_some(addr)));
    }
    Ok(result)
}

pub fn set_ksu_no_new_privs() -> anyhow::Result<()> {
    let result = ksuctl(
        ksu_uapi::KSU_IOCTL_DISABLE_ESCAPE_TO_ROOT,
        std::ptr::null_mut::<u8>(),
    )?;
    if result != 0 {
        bail!("unexpected result: {result}");
    }
    Ok(())
}
// ══════════════════════════════════════════════════════════════════════════
// MapleSU W18b（0006b）· webadmin ksud API surface
//
// 7K 的 `webadmin_ksud.rs`（2540+1645 行，已在 0006 入库）依赖下面这批 ksucalls
// 辅助函数：7K `userspace/ksud/src/ksucalls.rs:678-1055` 逐字移植（含注释）。
// 说明：本文件是该区间在 pinned 7K 源上的原样切片，未做语义改写；
//      UAPI 常量来自同树 `applied/uapi/`（0002 已把 STEALTH_* 重编号到 33-36）。
// ══════════════════════════════════════════════════════════════════════════

pub fn allow_list_uids() -> Vec<u32> {
    list_uids(true)
}

/// 有"非 root 配置"的 uid 列表（allow_su == false 的那些条目）。
///
/// 用户可能给某个没授权的 App 单独设了「卸载模块」这类非 root 策略，
/// 网页列表要把它们标成"已配置"，否则界面上看起来像没设置过。
/// 里面会混进默认非 root 模板（key = "$"，uid 9999），由调用方按包名过滤掉。
pub fn deny_list_uids() -> Vec<u32> {
    list_uids(false)
}

fn list_uids(allow: bool) -> Vec<u32> {
    list_uids_checked(allow).unwrap_or_default()
}

pub fn allow_list_uids_checked() -> anyhow::Result<Vec<u32>> {
    list_uids_checked(true)
}

fn list_uids_checked(allow: bool) -> anyhow::Result<Vec<u32>> {
    use ksu_uapi::{
        KSU_IOCTL_NEW_GET_ALLOW_LIST, KSU_IOCTL_NEW_GET_DENY_LIST, ksu_new_get_allow_list_cmd,
    };
    let req = if allow {
        KSU_IOCTL_NEW_GET_ALLOW_LIST
    } else {
        KSU_IOCTL_NEW_GET_DENY_LIST
    };
    // 先问总数
    let mut probe: ksu_new_get_allow_list_cmd = unsafe { std::mem::zeroed() };
    probe.count = 0;
    ksuctl(req, &raw mut probe)?;
    let total = probe.total_count as usize;
    if total == 0 {
        return Ok(Vec::new());
    }
    // 结构体尾部是柔性数组（uids[0]），所以手工多分配 total*4 字节。
    // ⚠️ 必须按 u32 分配：Vec<u8> 只保证 1 字节对齐，转成结构体指针后写字段就是"错位写"
    //    （clippy 的 cast_ptr_alignment 报的就是这个 —— 是真的隐患，不是风格问题）
    let base = std::mem::size_of::<ksu_new_get_allow_list_cmd>();
    let total = total.min(4096);
    let need = base + total * std::mem::size_of::<u32>();
    let mut buf: Vec<u32> = vec![0; need.div_ceil(std::mem::size_of::<u32>())];
    let cmd = buf.as_mut_ptr().cast::<ksu_new_get_allow_list_cmd>();
    unsafe {
        (*cmd).count = total as u16;
        (*cmd).total_count = 0;
    }
    ksuctl(req, cmd)?;
    let n = unsafe { (*cmd).count as usize }.min(total);
    let ptr = unsafe { (*cmd).uids.as_ptr() };
    Ok(unsafe { std::slice::from_raw_parts(ptr, n) }.to_vec())
}

/// 读"管理器 App 的 appid"（内核允许 root 调这个）
pub fn manager_appid() -> anyhow::Result<u32> {
    let mut cmd: ksu_uapi::ksu_get_manager_appid_cmd = unsafe { std::mem::zeroed() };
    ksuctl(ksu_uapi::KSU_IOCTL_GET_MANAGER_APPID, &raw mut cmd)?;
    Ok(cmd.appid)
}

/// 以「管理器 App 的 uid + 带管理器权限的 fd」执行一次隐身 ioctl。
///
/// 为什么要这么绕（2026-09-17 在设备上逐步定位）：
///   1. 内核里 `STEALTH_GET/SET` 的权限是 `only_manager`
///      （`current_uid() % 100000 == 管理器 appid`）—— 守护进程是 root，直接被拒；
///   2. 于是 fork 一个子进程 `setresuid` 成管理器 uid；
///   3. 但**光切 uid 还不够**：句柄（fd）本身也带权限位。守护进程的 fd 是从
///      App 的 root 会话继承来的（权限 0），所以还是 EPERM；
///   4. 关键点：内核在 `setresuid(管理器uid)` 那一刻会**给这个进程新装一个
///      带管理器权限的 `[ksu_driver]` fd**（hook/setuid_hook.c）。
///      所以子进程里：先把继承来的旧 fd 关掉，再重新扫一遍 /proc/self/fd，
///      拿到的就是那个"有权限"的新 fd —— 用它调 ioctl 才通。
///
/// 子进程里只做 syscall 与 _exit，不做堆分配（多线程进程 fork 后的安全做法）。
#[allow(clippy::comparison_chain)] // fork 的父子判断用 if/else if 最直观；子进程分支以 _exit 结束，塞进 match 反而更难读
fn stealth_ioctl_as_manager(enabled: Option<bool>) -> anyhow::Result<Option<bool>> {
    let appid = manager_appid()?;
    if appid == u32::MAX || appid == 0 {
        anyhow::bail!("拿不到管理器 appid");
    }
    let inherited = DRIVER_FD.get().copied().unwrap_or(-1);

    unsafe {
        let pid = libc::fork();
        if pid == 0 {
            // ── 子进程 ──
            if libc::setresuid(appid, appid, appid) != 0 {
                libc::_exit(10);
            }
            // 关掉继承来的旧句柄，免得扫到它
            if inherited >= 0 {
                libc::close(inherited);
            }
            // setresuid 时内核给我们装的新句柄
            let Ok(Some(fd)) = scan_driver_fd() else {
                libc::_exit(11);
            };
            // 已经在外面那层 unsafe 里了，这里不用再包一层
            let mut cmd: ksu_uapi::ksu_stealth_cmd = std::mem::zeroed();
            // Some(开/关) → SET；None → GET（读当前状态）
            let op = enabled.map_or(ksu_uapi::KSU_IOCTL_STEALTH_GET, |v| {
                cmd.enabled = u8::from(v);
                ksu_uapi::KSU_IOCTL_STEALTH_SET
            });
            let ret = libc::ioctl(fd, op as libc::c_int, &mut cmd);
            if ret != 0 {
                libc::_exit(12);
            }
            libc::_exit(i32::from(cmd.enabled == 0));
        } else if pid > 0 {
            let mut status: libc::c_int = 0;
            libc::waitpid(pid, &raw mut status, 0);
            if !libc::WIFEXITED(status) {
                anyhow::bail!("子进程异常退出");
            }
            match libc::WEXITSTATUS(status) {
                0 => Ok(Some(true)),
                1 => Ok(Some(false)), // GET 时为"关闭"
                c => anyhow::bail!(
                    "隐身 ioctl 失败（子进程退出码 {c}：10=切uid失败 11=没拿到新句柄 12=ioctl被拒）"
                ),
            }
        } else {
            anyhow::bail!("fork 失败");
        }
    }
}

/// 管理器世代号（断代闸门）。
///
/// ⚠️ 必须与内核侧一致：`kernel/Kbuild` 的 `KSU_MANAGER_MIN_GEN`（= 2）以及
/// 管理器 APK 里的 `assets/ksu_manager_gen2` 条目、App JNI 的 `KSU_MANAGER_GEN`。
/// 内核只要求 >= 1（安全阀比闸门宽松），但三处保持一致最好维护。
pub const KSU_MANAGER_GEN: u32 = 2;

/// 断代闸门的安全阀：用**新命令**直接读写隐身（内核权限 stealth_valve_allowed）。
///
/// 为什么 ksud 需要它：
///   · 老内核没有这条命令 → -ENOTTY，调用方自然回退到老路径（行为不变）；
///   · 新内核上如果管理器**没被认主**（比如设备上装的是老版本 APK），
///     `manager_appid()` 拿不到 / 老命令被 only_manager 拒 → 网页管理器
///     就再也没法开关隐身了；而 ksud 是 root，安全阀对 root 放行。
///   · 老版本管理器 APK 里没有这条命令（它的代码是编译死的），
///     所以"老 APK 关不掉隐身"这条验收不受影响。
fn stealth_ioctl_valve(enabled: Option<bool>) -> anyhow::Result<Option<bool>> {
    let mut cmd: ksu_uapi::ksu_stealth_gen_cmd = unsafe { std::mem::zeroed() };
    cmd.manager_gen = KSU_MANAGER_GEN;
    let op = enabled.map_or(ksu_uapi::KSU_IOCTL_STEALTH_GET_G, |v| {
        cmd.enabled = u8::from(v);
        ksu_uapi::KSU_IOCTL_STEALTH_SET_G
    });
    ksuctl(op, &raw mut cmd)?;
    Ok(Some(cmd.enabled != 0))
}

/// 以管理器身份读隐身状态（拿不到管理器身份时退回安全阀）
pub fn stealth_get_authed() -> anyhow::Result<bool> {
    if let Ok(Some(v)) = stealth_ioctl_as_manager(None) {
        return Ok(v);
    }
    Ok(stealth_ioctl_valve(None)?.unwrap_or(false))
}

/// 以管理器身份写隐身开关（拿不到管理器身份时退回安全阀）
pub fn stealth_set_authed(enabled: bool) -> anyhow::Result<()> {
    if stealth_ioctl_as_manager(Some(enabled)).is_ok() {
        return Ok(());
    }
    stealth_ioctl_valve(Some(enabled))?;
    Ok(())
}

/// 数据目录迁移门控用：**读**内核当前隐身开关（安全阀命令，只读、不落盘）。
///
/// 老内核（≤ v0.13.150）不认识命令号 27 → `-ENOTTY` → 这里返回 `Err`；
/// 调用方（`migrate::probe_datadir_with`）把"任何错误"都当成**拿不准** ⇒ **不迁移**。
///
/// # Errors
/// 拿不到内核句柄 / 命令不被支持 / 权限不足。
pub fn stealth_probe_get() -> anyhow::Result<bool> {
    Ok(stealth_ioctl_valve(None)?.unwrap_or(false))
}

/// 数据目录迁移门控用：**写**隐身开关（安全阀命令）。
///
/// 关键点：内核收到这条命令后一定会把它**自己那个数据目录**里的 `stealth` 文件
/// 同步重写一遍（见 `kernel/manager/stealth.c` 的 `ksu_stealth_set`），
/// 所以我们拿它当"内核到底在读写哪个目录"的笔迹探测 —— 探测时用**同值写回**，
/// 语义上等于空操作（新目录不存在时会顺手把正确的那份写出来，反而是好事）。
///
/// # Errors
/// 拿不到内核句柄 / 命令不被支持 / 权限不足 / 内核写盘失败。
pub fn stealth_probe_set(enabled: bool) -> anyhow::Result<()> {
    stealth_ioctl_valve(Some(enabled))?;
    Ok(())
}

// ══════════════════════════════════════════════════════════════════
// AppProfile（超级用户的"授权 / 撤销 / root 配置"）
//
// 权限同样是 only_manager（见 kernel/supercall/dispatch.c 的分发表），
// root 直接调会被 EPERM —— 所以复用上面那套「fork + setresuid(管理器uid)
// + 关旧句柄 + 重扫新句柄」的办法，只是这次要把内核回写的结构体带回来。
// ══════════════════════════════════════════════════════════════════

/// 入参结构体字节上限（app_profile 是 784 字节，留足余量）
const MANAGER_IOCTL_MAX: usize = 4096;

/// 以管理器身份跑一次 ioctl。
///
/// 返回 `Ok(Some(字节))` = 成功（内核回写后的结构体）；`Ok(None)` = 内核回 `-ENOENT`
/// （GET 时表示"这个 uid 还没有 profile"，是正常情况，不是错误）。
///
/// 子进程**不做任何堆分配**（多线程进程 fork 后的安全做法）：
/// 入参放栈上的定长数组，结果用管道回传。
/// 退出码：10=切 uid 失败 11=没拿到管理器句柄 12=被内核拒绝 20=-ENOENT 13=回传失败
fn ioctl_as_manager(req: u32, input: &[u8]) -> anyhow::Result<Option<Vec<u8>>> {
    anyhow::ensure!(input.len() <= MANAGER_IOCTL_MAX, "入参结构体太大");
    if unsafe { libc::getuid() == 0 && libc::geteuid() == 0 } {
        let mut output = input.to_vec();
        match ksuctl(req, output.as_mut_ptr()) {
            Ok(_) => return Ok(Some(output)),
            Err(error) => {
                let errno = error.downcast_ref::<std::io::Error>().and_then(std::io::Error::raw_os_error);
                if errno == Some(libc::ENOENT) {
                    return Ok(None);
                }
                // Older kernels still require the recognized Manager identity.
                if errno != Some(libc::EPERM) && errno != Some(libc::EACCES) {
                    return Err(error);
                }
            }
        }
    }
    let appid = manager_appid()?;
    if appid == u32::MAX || appid == 0 {
        anyhow::bail!("拿不到管理器 appid");
    }
    let inherited = DRIVER_FD.get().copied().unwrap_or(-1);
    let len = input.len();

    let mut fds = [0i32; 2];
    unsafe {
        if libc::pipe(fds.as_mut_ptr()) != 0 {
            anyhow::bail!("pipe 失败: {}", io::Error::last_os_error());
        }
    }
    let [rd, wr] = fds;
    let mut out = vec![0u8; len];

    unsafe {
        let pid = libc::fork();
        if pid == 0 {
            // ── 子进程 ──
            libc::close(rd);
            let mut buf = [0u8; MANAGER_IOCTL_MAX];
            std::ptr::copy_nonoverlapping(input.as_ptr(), buf.as_mut_ptr(), len);
            if libc::setresuid(appid, appid, appid) != 0 {
                libc::_exit(10);
            }
            // 关掉继承来的旧句柄，免得扫到它（它没有管理器权限位）
            if inherited >= 0 {
                libc::close(inherited);
            }
            // setresuid 那一刻内核给我们装的新句柄
            let Ok(Some(fd)) = scan_driver_fd() else {
                libc::_exit(11);
            };
            let ret = libc::ioctl(fd, req as libc::c_int, buf.as_mut_ptr());
            if ret != 0 {
                let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                libc::_exit(if errno == libc::ENOENT { 20 } else { 12 });
            }
            let mut off = 0usize;
            while off < len {
                let n = libc::write(wr, buf.as_ptr().add(off).cast::<libc::c_void>(), len - off);
                if n <= 0 {
                    libc::_exit(13);
                }
                off += n as usize;
            }
            libc::close(wr);
            libc::_exit(0);
        } else if pid < 0 {
            libc::close(rd);
            libc::close(wr);
            anyhow::bail!("fork 失败: {}", io::Error::last_os_error());
        }

        libc::close(wr);
        // 入参很小（远小于 64KB 管道容量），父进程随后再读不会死锁
        let mut off = 0usize;
        while off < len {
            let n = libc::read(
                rd,
                out.as_mut_ptr().add(off).cast::<libc::c_void>(),
                len - off,
            );
            if n <= 0 {
                break;
            }
            off += n as usize;
        }
        libc::close(rd);
        let mut status: libc::c_int = 0;
        libc::waitpid(pid, &raw mut status, 0);
        if !libc::WIFEXITED(status) {
            anyhow::bail!("管理器身份子进程异常退出");
        }
        match libc::WEXITSTATUS(status) {
            0 => {}
            20 => return Ok(None),
            c => anyhow::bail!(
                "ioctl 失败（子进程退出码 {c}: 10=切uid失败 11=没拿到管理器句柄 12=被内核拒绝 13=回传失败）"
            ),
        }
        anyhow::ensure!(off == len, "ioctl 结果回传不完整（{off}/{len}）");
    }
    Ok(Some(out))
}

const fn struct_bytes<T>(v: &T) -> &[u8] {
    let p = std::ptr::from_ref(v).cast::<u8>();
    unsafe { std::slice::from_raw_parts(p, std::mem::size_of::<T>()) }
}

fn struct_from_bytes<T: Copy>(b: &[u8]) -> anyhow::Result<T> {
    anyhow::ensure!(b.len() >= std::mem::size_of::<T>(), "结构体字节数不足");
    // 这些都是 C 的 POD 结构（全是整数 / 定长字符数组 / bool），全零是合法初值
    let mut v: T = unsafe { std::mem::zeroed() };
    unsafe {
        std::ptr::copy_nonoverlapping(
            b.as_ptr(),
            std::ptr::addr_of_mut!(v).cast::<u8>(),
            std::mem::size_of::<T>(),
        );
    }
    Ok(v)
}

/// 把 Rust 字符串写进定长 `char[N]`（截断 + 结尾补 0）
pub fn write_cstr(buf: &mut [libc::c_char], s: &str) {
    let n = s.len().min(buf.len().saturating_sub(1));
    for (i, b) in s.as_bytes()[..n].iter().enumerate() {
        buf[i] = *b as libc::c_char;
    }
    if let Some(last) = buf.get_mut(n) {
        *last = 0;
    }
}

/// 读某个 App 的 AppProfile。
///
/// `Ok(None)` = 内核里没有这个 uid 的条目（= 没授权过、也没单独配过），
/// 此时界面按"默认值"展示（不给 root、非 root 用默认）。
pub fn get_app_profile(uid: u32, key: &str) -> anyhow::Result<Option<ksu_uapi::app_profile>> {
    let mut cmd: ksu_uapi::ksu_get_app_profile_cmd = unsafe { std::mem::zeroed() };
    cmd.profile.version = ksu_uapi::KSU_APP_PROFILE_VER;
    cmd.profile.curr_uid = uid as i32;
    write_cstr(&mut cmd.profile.key[..], key);
    match ioctl_as_manager(ksu_uapi::KSU_IOCTL_GET_APP_PROFILE, struct_bytes(&cmd))? {
        None => Ok(None),
        Some(out) => {
            let got: ksu_uapi::ksu_get_app_profile_cmd = struct_from_bytes(&out)?;
            Ok(Some(got.profile))
        }
    }
}

/// 写 AppProfile（授权 / 撤销 root、改 root 配置都走这里）
pub fn set_app_profile(profile: &ksu_uapi::app_profile) -> anyhow::Result<()> {
    let mut cmd: ksu_uapi::ksu_set_app_profile_cmd = unsafe { std::mem::zeroed() };
    cmd.profile = *profile;
    match ioctl_as_manager(ksu_uapi::KSU_IOCTL_SET_APP_PROFILE, struct_bytes(&cmd))? {
        Some(_) => Ok(()),
        None => anyhow::bail!("内核说没有这个 profile"),
    }
}

/// 从定长 `char[N]` 读回 Rust 字符串
#[allow(clippy::unnecessary_cast)] // 见下面那段注释：x86_64 上 c_char 是 i8，这个 cast 不能删
pub fn read_cstr(buf: &[libc::c_char]) -> String {
    let bytes: Vec<u8> = buf
        .iter()
        .take_while(|c| **c != 0)
        // ⚠️ `libc::c_char` 在 aarch64 上是 u8、在 x86_64 上是 **i8**。
        //    原来直接 `.copied().collect::<Vec<u8>>()`，于是 x86_64 target **编不过**
        //    （E0277: Vec<u8> cannot be built from i8）—— 本项目的 x86_64 ksud 一直是
        //    上游编译的旧产物。2026-09-20「彻底切割」需要重编 x86_64 那份（否则
        //    APK 里的 x86_64 libksud.so 还带着旧包名/旧路径），顺手把这一行修好：
        //    `as u8` 在 aarch64 上是恒等转换，不影响 arm64 行为。
        .map(|c| *c as u8)
        .collect();
    String::from_utf8_lossy(&bytes).to_string()
}
