use anyhow::{Context, Error, Ok, Result, bail};
use rustix::fs::{Mode, OFlags, open};
use rustix::process::setpgid;
use rustix::stdio::{dup2_stderr, dup2_stdin, dup2_stdout};
use std::{
    ffi::{CStr, CString, c_char, c_void},
    fs::{File, OpenOptions, create_dir_all, remove_file, write},
    io::{
        ErrorKind::{AlreadyExists, NotFound},
        Write,
    },
    path::Path,
    process::Command,
};

use crate::defs::KSU_TEMP_BACKUP_DIR_NAME;
use crate::{assets, boot_patch, defs, ksucalls, module, restorecon};
#[allow(unused_imports)]
use std::fs::{Permissions, set_permissions};
use std::os::unix::prelude::PermissionsExt;

use std::path::PathBuf;

use crate::boot_patch::BootRestoreArgs;

use rustix::{
    process,
    thread::{LinkNameSpaceType, move_into_link_name_space},
};

type PropertyReadCallback = unsafe extern "C" fn(*mut c_void, *const c_char, *const c_char, u32);

unsafe extern "C" {
    fn __system_property_find(name: *const c_char) -> *const c_void;
    fn __system_property_read_callback(
        property_info: *const c_void,
        callback: PropertyReadCallback,
        cookie: *mut c_void,
    );
}

#[macro_export]
macro_rules! debug_select {
    ($debug:expr, $release:expr) => {{
        #[cfg(debug_assertions)]
        {
            $debug
        }
        #[cfg(not(debug_assertions))]
        {
            $release
        }
    }};
}

pub fn ensure_clean_dir(dir: impl AsRef<Path>) -> Result<()> {
    let path = dir.as_ref();
    log::debug!("ensure_clean_dir: {}", path.display());
    if path.exists() {
        log::debug!("ensure_clean_dir: {} exists, remove it", path.display());
        std::fs::remove_dir_all(path)?;
    }
    Ok(std::fs::create_dir_all(path)?)
}

pub fn ensure_file_exists<T: AsRef<Path>>(file: T) -> Result<()> {
    match File::options().write(true).create_new(true).open(&file) {
        std::result::Result::Ok(_) => Ok(()),
        Err(err) => {
            if err.kind() == AlreadyExists && file.as_ref().is_file() {
                Ok(())
            } else {
                Err(Error::from(err))
                    .with_context(|| format!("{} is not a regular file", file.as_ref().display()))
            }
        }
    }
}

pub fn ensure_dir_exists<T: AsRef<Path>>(dir: T) -> Result<()> {
    let result = create_dir_all(&dir);
    if dir.as_ref().is_dir() && result.is_ok() {
        Ok(())
    } else {
        bail!("{} is not a regular directory", dir.as_ref().display())
    }
}

pub fn ensure_binary<T: AsRef<Path>>(
    path: T,
    contents: &[u8],
    ignore_if_exist: bool,
) -> Result<()> {
    if ignore_if_exist && path.as_ref().exists() {
        return Ok(());
    }

    ensure_dir_exists(path.as_ref().parent().ok_or_else(|| {
        anyhow::anyhow!(
            "{} does not have parent directory",
            path.as_ref().to_string_lossy()
        )
    })?)?;

    if let Err(e) = remove_file(path.as_ref())
        && e.kind() != NotFound
    {
        return Err(Error::from(e))
            .with_context(|| format!("failed to unlink {}", path.as_ref().display()));
    }

    write(&path, contents)?;
    set_permissions(&path, Permissions::from_mode(0o755))?;
    Ok(())
}

unsafe extern "C" fn property_read_callback(
    cookie: *mut c_void,
    _name: *const c_char,
    value: *const c_char,
    _serial: u32,
) {
    if cookie.is_null() || value.is_null() {
        return;
    }

    let result = unsafe { &mut *cookie.cast::<Option<String>>() };
    let value = unsafe { CStr::from_ptr(value) };
    *result = Some(value.to_string_lossy().into_owned());
}

pub fn getprop(name: &str) -> Option<String> {
    let name = CString::new(name).ok()?;
    let property_info = unsafe { __system_property_find(name.as_ptr()) };
    if property_info.is_null() {
        return None;
    }

    let mut value = None;
    unsafe {
        __system_property_read_callback(
            property_info,
            property_read_callback,
            std::ptr::addr_of_mut!(value).cast(),
        );
    }
    value
}

pub fn is_safe_mode() -> bool {
    let safemode = getprop("persist.sys.safemode")
        .as_ref()
        .is_some_and(|prop| prop == "1")
        || getprop("ro.sys.safemode")
            .as_ref()
            .is_some_and(|prop| prop == "1");
    log::info!("safemode: {safemode}");
    if safemode {
        return true;
    }
    let safemode = ksucalls::check_kernel_safemode();
    log::info!("kernel_safemode: {safemode}");
    safemode
}

pub fn get_zip_uncompressed_size(zip_path: &str) -> Result<u64> {
    let mut zip = zip::ZipArchive::new(std::fs::File::open(zip_path)?)?;
    let mut total: u64 = 0;
    for i in 0..zip.len() {
        total += zip.by_index(i)?.size();
    }
    Ok(total)
}

pub fn switch_mnt_ns(pid: i32) -> Result<()> {
    use rustix::{
        fd::AsFd,
        fs::{Mode, OFlags, open},
    };
    let path = format!("/proc/{pid}/ns/mnt");
    let fd = open(path, OFlags::RDONLY, Mode::from_raw_mode(0))?;
    let current_dir = std::env::current_dir();
    move_into_link_name_space(fd.as_fd(), Some(LinkNameSpaceType::Mount))?;
    if let std::result::Result::Ok(current_dir) = current_dir {
        let _ = std::env::set_current_dir(current_dir);
    }
    Ok(())
}

fn switch_cgroup(grp: &str, pid: u32) {
    let path = Path::new(grp).join("cgroup.procs");
    if !path.exists() {
        return;
    }

    let fp = OpenOptions::new().append(true).open(path);
    if let std::result::Result::Ok(mut fp) = fp {
        let _ = write!(fp, "{pid}");
    }
}

pub fn switch_cgroups() {
    let pid = std::process::id();
    switch_cgroup("/acct", pid);
    switch_cgroup("/dev/cg2_bpf", pid);
    switch_cgroup("/sys/fs/cgroup", pid);

    if getprop("ro.config.per_app_memcg")
        .as_ref()
        .is_none_or(|prop| prop != "false")
    {
        switch_cgroup("/dev/memcg/apps", pid);
    }
}

pub fn umask(mask: u32) {
    process::umask(rustix::fs::Mode::from_raw_mode(mask));
}

pub fn has_magisk() -> bool {
    which::which("magisk").is_ok()
}

fn link_ksud_to_bin() -> Result<()> {
    let ksu_bin = PathBuf::from(defs::DAEMON_PATH);
    let ksu_bin_link = PathBuf::from(defs::DAEMON_LINK_PATH);
    if ksu_bin.exists() && !ksu_bin_link.exists() {
        std::os::unix::fs::symlink(&ksu_bin, &ksu_bin_link)?;
    }
    Ok(())
}

pub fn install(
    libadbroot: Option<PathBuf>,
    data_path: Option<PathBuf>,
    // MapleSU W12b: 切换事务内调用时为 true —— 源（Lite）策略里没有 ksu_file
    // 类型，标签失败不能当作安装失败，否则重启后内核在、ksud 缺失。
    stage_for_switch: bool,
) -> Result<()> {
    ensure_dir_exists(defs::ADB_DIR)?;
    let _ = std::fs::remove_file(defs::DAEMON_PATH);
    std::fs::copy(
        // We should use /proc/self/exe, DO NOT resolve the real path
        // So that if someone execute /data/adb/ksud install, ksud won't be removed unexpectedly
        "/proc/self/exe",
        defs::DAEMON_PATH,
    )?;
    match restorecon::lsetfilecon(defs::DAEMON_PATH, restorecon::KSU_CON) {
        std::result::Result::Ok(()) => {}
        Err(e) if stage_for_switch => {
            // 保留当前标签，写待办标记；B 内核开机第一次 post-fs-data 的
            // restorecon() 会把标签补上并删除该标记（见 restorecon.rs）。
            std::fs::write(
                std::path::Path::new(defs::WORKING_DIR).join(".pending_label"),
                restorecon::KSU_CON,
            )?;
            log::warn!("stage_for_switch: deferring daemon label ({e:#})");
        }
        Err(e) => return Err(e).context("failed to label ksud"),
    }
    // install binary assets
    assets::ensure_binaries(false).with_context(|| "Failed to extract assets")?;

    link_ksud_to_bin()?;

    if let Some(libadbroot) = libadbroot {
        ensure_dir_exists(defs::LIBRARY_DIR)?;
        let _ = std::fs::remove_file(defs::LIBADBROOT_PATH);
        let _ = std::fs::copy(libadbroot, defs::LIBADBROOT_PATH);
    }

    if let Some(data_path) = data_path {
        let backup_path = data_path.join(KSU_TEMP_BACKUP_DIR_NAME);
        if backup_path.is_dir() {
            for ent in backup_path.read_dir()? {
                let ent = ent?;
                if ent.file_type().is_ok_and(|v| v.is_file()) {
                    let name = ent.file_name().to_string_lossy().to_string();
                    let target = format!("{}{name}", defs::KSU_BACKUP_DIR);
                    if name.starts_with(defs::KSU_BACKUP_FILE_PREFIX)
                        && std::fs::rename(ent.path(), &target).is_err()
                    {
                        std::fs::copy(ent.path(), &target).with_context(|| {
                            format!("failed to move {} -> {target}", ent.path().display())
                        })?;
                        log::info!("move boot backup {name}");
                    }
                }
            }
            std::fs::remove_dir_all(&backup_path)?;
        }
    }

    Ok(())
}

pub fn uninstall(package_name: &str) -> Result<()> {
    if Path::new(defs::MODULE_DIR).exists() {
        println!("- Uninstall modules..");
        module::uninstall_all_modules()?;
        module::prune_modules()?;
    }
    // W18b（0008b）：顺序修正 —— 先还原启动镜像、再备份用户数据、最后才删。
    // 7K 依据：userspace/ksud/src/utils.rs:626-700（旧顺序先删 WORKING_DIR，
    // 会把 restore 依赖的原厂备份一起删掉）。
    println!("- Restore boot image.. (your data is NOT deleted yet)");
    boot_patch::restore(BootRestoreArgs {
        file_only: false,
        boot: None,
        flash: true,
        out: None,
        out_name: None,
    })?;

    // 删之前先备份用户数据；备份失败 → 中止（不删、不重启）
    match backup_user_data()? {
        Some(dir) => println!(
            "- YOU CAN GET IT BACK LATER with: ksud restore-user-data\n\
             - backup kept at: {}",
            dir.display()
        ),
        None => println!("- No user data found to back up"),
    }

    println!("- Removing directories..");
    std::fs::remove_dir_all(defs::WORKING_DIR).ok();
    std::fs::remove_file(defs::DAEMON_PATH).ok();
    std::fs::remove_dir_all(defs::MODULE_DIR).ok();
    std::fs::remove_dir_all(defs::PREINIT_DIR_VOLD).ok();
    std::fs::remove_dir_all(defs::PREINIT_DIR_WATCHDOG).ok();
    std::fs::remove_dir_all(defs::PREINIT_DIR_DEFAULT).ok();
    println!("- Uninstall KernelSU manager..");
    Command::new("pm")
        .args(["uninstall", package_name])
        .spawn()?;
    println!("- Rebooting in 5 seconds..");
    std::thread::sleep(std::time::Duration::from_secs(5));
    Command::new("reboot").spawn()?;
    Ok(())
}

pub fn reset_std() -> Result<()> {
    let null_fd = open("/dev/null", OFlags::RDWR, Mode::empty())?;
    dup2_stdin(&null_fd)?;
    dup2_stdout(&null_fd)?;
    dup2_stderr(&null_fd)?;
    Ok(())
}

pub fn daemonize_with<F: FnOnce() -> Result<()>>(use_init_pgrp: bool, configure: F) -> Result<()> {
    if !create_daemon_impl(use_init_pgrp, configure)? {
        unsafe { libc::_exit(0) }
    }
    Ok(())
}

pub fn daemonize(use_init_pgrp: bool) -> Result<()> {
    daemonize_with(use_init_pgrp, || Ok(()))
}

pub fn create_daemon(use_init_pgrp: bool) -> Result<bool> {
    create_daemon_with(use_init_pgrp, || Ok(()))
}

pub fn create_daemon_with<F: FnOnce() -> Result<()>>(
    use_init_pgrp: bool,
    configure: F,
) -> Result<bool> {
    create_daemon_impl(use_init_pgrp, configure)
}

fn create_daemon_impl<F: FnOnce() -> Result<()>>(
    use_init_pgrp: bool,
    configure: F,
) -> Result<bool> {
    unsafe {
        let pid = libc::fork();
        if pid < 0 {
            bail!("fork error {}", std::io::Error::last_os_error());
        } else if pid > 0 {
            let mut status: i32 = -1;
            loop {
                if libc::waitpid(pid, &raw mut status, 0) < 0 {
                    if *libc::__errno() != libc::EINTR {
                        libc::_exit(1);
                    }
                } else {
                    break;
                }
            }
            if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
                bail!("child exited with unexpected status {status}")
            }
            return Ok(false);
        }
    }

    let do_configure = || -> Result<()> {
        detach_process_group(use_init_pgrp);
        switch_cgroups();
        configure()?;
        reset_std()?;

        unsafe {
            let pid = libc::fork();
            if pid < 0 {
                bail!("fork error {}", std::io::Error::last_os_error());
            } else if pid > 0 {
                libc::_exit(0);
            }
        }
        Ok(())
    };

    if let Err(e) = do_configure() {
        log::error!("failed to configure daemon: {e:?}");
        unsafe {
            libc::_exit(1);
        }
    }

    Ok(true)
}

pub fn detach_process_group(use_init_pgrp: bool) {
    if use_init_pgrp {
        if let Err(e) = ksucalls::set_init_pgrp() {
            log::error!("failed to switch to init group: {e:?}");
        } else {
            return;
        }
    }
    if let Err(e2) = setpgid(None, None) {
        log::error!("failed to set process group: {e2:?}");
    }
}

// ══════════════════════════════════════════════════════════════════════
// MapleSU W18b（0008b）· 卸载前备份 / restore-user-data
// 移植自 7K `userspace/ksud/src/utils.rs:400-530`（逐字，仅改：
//   · `crate::migrate::KEY_FILES` → 本地常量（不采用 migrate.rs）；
//   · 备份目录名 `sevenk_` → `ksu_`（我们的数据目录是 /data/adb/ksu）。
// 失败语义：任一项备份失败 → bail，**什么都不删**（绝不假装备份过了）。
// ══════════════════════════════════════════════════════════════════════

/// 卸载前必须保住的关键文件（7K migrate.rs:109-115 的同值清单）。
const KEY_FILES: [&str; 3] = [".allowlist", "stealth", "stealth_code"];

/// 🔴1（v2.4）：卸载之前把**用户数据**备份到 `/data/adb/sevenk_uninstall_backup_<ts>/`。
///
/// 为什么必须备份：`.allowlist`（授权名单）/ `stealth`（隐身标志）/ `stealth_code`（拨号密令）
/// / `module_configs/` 这些是**用户自己攒出来的东西**；`uninstall()` 下一步就会
/// `remove_dir_all(WORKING_DIR)` 把它们一起抹掉。旧代码**一个字节都不备份**：
/// 用户重装后授权、密令、模块配置全没了（密令丢了甚至可能退不出隐身，
/// 而 `StealthCodeStore` 的注释还写着它"能跨卸载"）。
///
/// 备份目录刻意放在 `ADB_DIR` 下、**不在 `WORKING_DIR` 里**，
/// 所以后面删 `WORKING_DIR` 不会连备份一起删掉。
/// 任何一项备份失败都 `bail!` —— 绝不"假装备份过了"然后继续删。
fn backup_user_data() -> Result<Option<PathBuf>> {
    let working = Path::new(defs::WORKING_DIR);
    if !working.is_dir() {
        return Ok(None);
    }
    let stamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    let dest = Path::new(defs::ADB_DIR).join(format!("ksu_uninstall_backup_{stamp}"));
    ensure_dir_exists(&dest)?;

    let mut copied = 0usize;
    let mut failed: Vec<String> = Vec::new();

    // 关键文件（丢了 = 掉授权 / 退不出隐身）
    for name in KEY_FILES {
        let src = working.join(name);
        if src.is_file() {
            match std::fs::copy(&src, dest.join(name)) {
                std::result::Result::Ok(_) => copied += 1,
                Err(e) => failed.push(format!("{name}: {e}")),
            }
        }
    }
    // 整目录：模块配置 / profile（SELinux 规则 + 模板）。
    // ⚠️ **刻意不备份 `log/`**：那是 sulog 的原始日志，可能有几十 MB，
    // 既不值得留、也会把"卸载"拖慢；真要看日志的用户在卸载前自己导。
    for (dir, name) in [
        (defs::MODULE_CONFIG_DIR, "module_configs"),
        (defs::PROFILE_DIR, "profile"),
    ] {
        let src = Path::new(dir);
        if src.is_dir() {
            match copy_dir_all(src, &dest.join(name)) {
                std::result::Result::Ok(()) => copied += 1,
                Err(e) => failed.push(format!("{name}/: {e}")),
            }
        }
    }
    // 二进制特性开关（纯配置，丢了只是回默认，顺手留一份）
    let feature = working.join(".feature_config");
    if feature.is_file() {
        match std::fs::copy(&feature, dest.join(".feature_config")) {
            std::result::Result::Ok(_) => copied += 1,
            Err(e) => failed.push(format!(".feature_config: {e}")),
        }
    }

    if !failed.is_empty() {
        bail!(
            "failed to back up user data to {}: {}\n\
             Refusing to continue the uninstall (nothing has been deleted yet).",
            dest.display(),
            failed.join("; ")
        );
    }
    if copied == 0 {
        let _ = std::fs::remove_dir_all(&dest);
        return Ok(None);
    }
    println!("- User data backed up to: {}", dest.display());
    println!("- (keep that folder if you ever want your grants / secret code back)");
    Ok(Some(dest))
}

/// 递归复制目录（备份用；软链接等其它类型**跳过**，不跟随）。
fn copy_dir_all(src: &Path, dst: &Path) -> Result<()> {
    ensure_dir_exists(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let target = dst.join(entry.file_name());
        if file_type.is_dir() {
            copy_dir_all(&entry.path(), &target)?;
        } else if file_type.is_file() {
            std::fs::copy(entry.path(), &target)?;
        }
    }
    Ok(())
}

/// 🔴2（v2.11）`ksud restore-user-data` 的 Android 侧入口：把 `defs` 里的真实路径填进
/// 纯 std 的实现（[`crate::restore_user_data`]，宿主上有单测整条覆盖）。
///
/// 审计点名的缺口：`backup_user_data()` 一直在备份，但**全仓没有一处读回它** ✗
/// ⇒ "备份了但用户拿不回来" = 等于没备份。现在补上命令行 + App 一键恢复。
pub fn restore_user_data(from: Option<&Path>) -> Result<()> {
    let paths = crate::restore_user_data::RestorePaths {
        adb: PathBuf::from(defs::ADB_DIR),
        working: PathBuf::from(defs::WORKING_DIR),
        module_configs: PathBuf::from(defs::MODULE_CONFIG_DIR),
        profile: PathBuf::from(defs::PROFILE_DIR),
    };
    // 先看看有哪些备份（`--from` 写错时把候选列表打出来，省得用户猜）
    let available = crate::restore_user_data::list_uninstall_backups(&paths.adb);
    if available.is_empty() {
        println!("- No uninstall backup found under {}", paths.adb.display());
        println!("- (backups are created automatically by `ksud uninstall`)");
    } else {
        println!("- Found {} uninstall backup(s):", available.len());
        for p in &available {
            println!("    {}", p.display());
        }
    }

    let rep = crate::restore_user_data::restore_user_data(&paths, from)?;
    println!("{}", rep.summary());
    println!("- RESTART REQUIRED: the kernel only reads the allowlist / stealth flag at boot.");
    println!("- Nothing was deleted (only overwritten or added).");
    Ok(())
}

/// 🔴2（v2.11）删目录，**失败要报错**（不存在算成功）。
///
/// 🟡（v2.11）统一走 `symlink_metadata` **分流**（防御性）：
///   · 软链 ⇒ 只 `remove_file` 删**链接本身**（绝不顺着它 `remove_dir_all` 把目标目录也删了 ✗）；
///   · 真实目录 ⇒ `remove_dir_all`；
///   · 别的类型（普通文件…）⇒ `remove_file`。
/// 当前调用点传进来的都是我们自己建的目录（无触发路径），但"删除"这种事**一次都不许赌**。
fn remove_dir_all_checked(dir: &str) -> Result<()> {
    // ⚠️ 这里的 `Ok` 是 anyhow 导入的那个**函数**（见文件头的 `use`），
    // 所以匹配 Result 时必须写全 `std::result::Result::Ok`。
    let meta = match std::fs::symlink_metadata(dir) {
        std::result::Result::Ok(m) => m,
        Err(e) if e.kind() == NotFound => return Ok(()),
        Err(e) => return Err(Error::from(e)).with_context(|| format!("failed to stat {dir}")),
    };
    if meta.file_type().is_symlink() {
        // 软链 ⇒ 只删链接本身（绝不顺着它把目标目录也删了）
        return match std::fs::remove_file(dir) {
            std::result::Result::Ok(()) => Ok(()),
            Err(e) if e.kind() == NotFound => Ok(()),
            Err(e) => {
                Err(Error::from(e)).with_context(|| format!("failed to remove symlink {dir}"))
            }
        };
    }
    if meta.is_dir() {
        return match std::fs::remove_dir_all(dir) {
            std::result::Result::Ok(()) => Ok(()),
            Err(e) if e.kind() == NotFound => Ok(()),
            Err(e) => Err(Error::from(e)).with_context(|| format!("failed to remove {dir}")),
        };
    }
    // 别的类型（普通文件…）：删文件本身
    match std::fs::remove_file(dir) {
        std::result::Result::Ok(()) => Ok(()),
        Err(e) if e.kind() == NotFound => Ok(()),
        Err(e) => Err(Error::from(e)).with_context(|| format!("failed to remove file {dir}")),
    }
}

/// 🔴1（v2.4）：删文件，**失败要报错**（不存在算成功）。
fn remove_file_checked(file: &str) -> Result<()> {
    match std::fs::remove_file(file) {
        std::result::Result::Ok(()) => Ok(()),
        Err(e) if e.kind() == NotFound => Ok(()),
        Err(e) => Err(Error::from(e)).with_context(|| format!("failed to remove {file}")),
    }
}

/// 🔴3（v2.4）：只在目录**空了**才删它。
///
/// `/data/adb/modules` 与面具**共用**：双 root 机器上里面还躺着面具的模块，
/// 整目录删 = 不可逆地清掉别人的东西。所以这里只在自己那一份已经清完之后
/// 顺手把空壳目录删掉；目录非空就原样保留。
fn remove_dir_if_empty(dir: &str) -> Result<()> {
    match std::fs::remove_dir(dir) {
        std::result::Result::Ok(()) => Ok(()),
        Err(e) if e.kind() == NotFound => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::DirectoryNotEmpty => {
            println!("- Keeping {dir}: it still contains modules that are not ours");
            Ok(())
        }
        Err(e) => Err(Error::from(e)).with_context(|| format!("failed to remove {dir}")),
    }
}
