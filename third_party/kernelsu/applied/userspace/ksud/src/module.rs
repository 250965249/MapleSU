#[allow(clippy::wildcard_imports)]
use crate::utils::*;
use crate::{
    assets, defs, hot_install, ksucalls, metamodule,
    restorecon::{restore_syscon, setsyscon},
    sepolicy,
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use const_format::concatcp;
use is_executable::is_executable;
use java_properties::PropertiesIter;
use log::{debug, error, info, warn};
use regex_lite::Regex;

use std::{
    collections::{BTreeMap, HashMap},
    env::var as env_var,
    fs::{File, Permissions, canonicalize, remove_dir_all, set_permissions},
    io::Cursor,
    path::{Path, PathBuf},
    process::Command,
    str::FromStr,
    time::Instant,
};
use std::{
    fs::rename,
    io::Write,
};
use zip_extensions::inflate::zip_extract::zip_extract_file_to_memory;

use crate::defs::{MODULE_DIR, MODULE_UPDATE_DIR};
use crate::module::ModuleType::{Active, All};
use std::os::unix::{prelude::PermissionsExt, process::CommandExt};

#[path = "module_install_transaction.rs"]
mod install_transaction;
use install_transaction::metadata_lock;
#[path = "module_removal_transaction.rs"]
mod removal_transaction;

const INSTALLER_CONTENT: &str = include_str!("./installer.sh");
const INSTALL_MODULE_SCRIPT: &str = concatcp!(
    INSTALLER_CONTENT,
    "\n",
    "install_module",
    "\n",
    "exit 0",
    "\n"
);

/// Validate module_id format and security
/// Module ID must match: ^[a-zA-Z][a-zA-Z0-9._-]+$
/// - Must start with a letter (a-zA-Z)
/// - Followed by one or more alphanumeric, dot, underscore, or hyphen characters
/// - Minimum length: 2 characters
pub fn validate_module_id(module_id: &str) -> Result<()> {
    let re = Regex::new(r"^[a-zA-Z][a-zA-Z0-9._-]+$")?;
    if re.is_match(module_id) {
        Ok(())
    } else {
        Err(anyhow!(
            "Invalid module ID: '{module_id}'. Must match /^[a-zA-Z][a-zA-Z0-9._-]+$/"
        ))
    }
}

/// Get common environment variables for script execution
pub fn get_common_script_envs(module_id: Option<&str>) -> Vec<(&'static str, String)> {
    let mut envs = vec![
        ("ASH_STANDALONE", "1".to_string()),
        ("KSU", "true".to_string()),
        ("KSU_KERNEL_VER_CODE", ksucalls::get_version().to_string()),
        ("KSU_VER_CODE", defs::VERSION_CODE.to_string()),
        ("KSU_VER", defs::VERSION_NAME.to_string()),
        ("KSU_UAPI_VER", ksucalls::uapi_version().to_string()),
        ("KSU_RUNTIME_MODE", ksucalls::runtime_mode().to_string()),
        (
            "PATH",
            format!(
                "{}:{}",
                env_var("PATH").unwrap_or_default(),
                defs::BINARY_DIR.trim_end_matches('/')
            ),
        ),
    ];

    if let Some(id) = module_id {
        if validate_module_id(id).is_ok() {
            envs.push(("KSU_MODULE", id.to_string()));
        } else {
            error!("Invalid module_id provided: {id}");
        }
    }

    if ksucalls::is_late_load() {
        envs.push(("KSU_LATE_LOAD", "1".to_string()));
    }

    envs
}

fn exec_install_script(
    module_file: &str, is_metamodule: bool, module_id: &str, temporary_dir: &Path,
) -> Result<()> {
    let realpath = std::fs::canonicalize(module_file)
        .with_context(|| format!("realpath: {module_file} failed"))?;

    // Get install script from metamodule module
    let install_script =
        metamodule::get_install_script(is_metamodule, INSTALLER_CONTENT, INSTALL_MODULE_SCRIPT)?;

    let parent = std::process::id() as libc::pid_t;
    let mut command = Command::new(assets::BUSYBOX_PATH);
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::getppid() != parent {
                return Err(std::io::Error::from_raw_os_error(libc::ECANCELED));
            }
            Ok(())
        });
    }
    let result = command
        .args(["sh", "-c", &install_script])
        .envs(get_common_script_envs(Some(module_id)))
        .env("OUTFD", "1")
        .env("KSUD_MANAGED_INSTALL", "1")
        .env_remove("KSUD_MODULE_LIVE_EVENT")
        .env("KSUD_INSTALL_TMPDIR", temporary_dir)
        .env("ZIPFILE", realpath)
        .status()?;
    ensure!(result.success(), "Failed to install module script");
    Ok(())
}

// Check if Android boot is completed before installing modules
fn ensure_boot_completed() -> Result<()> {
    // ensure getprop sys.boot_completed == 1
    if getprop("sys.boot_completed").as_deref() != Some("1") {
        bail!("Android is Booting!");
    }
    Ok(())
}

#[derive(PartialEq, Eq)]
pub enum ModuleType {
    All,
    Active,
    Updated,
}

#[allow(clippy::needless_pass_by_value)]
pub fn foreach_module(
    module_type: ModuleType,
    mut f: impl FnMut(&Path) -> Result<()>,
) -> Result<()> {
    let modules_dir = Path::new(match module_type {
        ModuleType::Updated => MODULE_UPDATE_DIR,
        _ => defs::MODULE_DIR,
    });
    let dir = std::fs::read_dir(modules_dir)?;
    for entry in dir.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            warn!("{} is not a directory, skip", path.display());
            continue;
        }

        if install_transaction::skip_uncommitted(&path, module_type == ModuleType::Updated) {
            continue;
        }
        if module_type == Active && path.join(defs::DISABLE_FILE_NAME).exists() {
            info!("{} is disabled, skip", path.display());
            continue;
        }
        if module_type == Active && removal_transaction::is_removed(&path) {
            warn!("{} is removed, skip", path.display());
            continue;
        }

        f(&path)?;
    }

    Ok(())
}

fn foreach_active_module(f: impl FnMut(&Path) -> Result<()>) -> Result<()> {
    foreach_module(Active, f)
}

pub fn load_sepolicy_rule() -> Result<()> {
    foreach_active_module(|path| {
        let rule_file = path.join("sepolicy.rule");
        if !rule_file.exists() {
            return Ok(());
        }
        info!("load policy: {}", rule_file.display());

        if sepolicy::apply_file(&rule_file).is_err() {
            warn!("Failed to load sepolicy.rule for {}", rule_file.display());
        }
        Ok(())
    })?;

    Ok(())
}

#[derive(Clone, Copy)]
pub enum ScriptWait {
    NoWait,
    Forever,
    Until(Instant),
}

struct SigchldBlock {
    set: libc::sigset_t,
    previous: libc::sigset_t,
}

impl SigchldBlock {
    fn block() -> std::io::Result<Self> {
        // Initialize both sets before passing them to libc.
        let mut set = unsafe { std::mem::zeroed() };
        let mut previous = unsafe { std::mem::zeroed() };
        unsafe {
            libc::sigemptyset(&raw mut set);
            libc::sigaddset(&raw mut set, libc::SIGCHLD);
            if libc::sigprocmask(libc::SIG_BLOCK, &raw const set, &raw mut previous) != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        Ok(Self { set, previous })
    }

    fn wait_until(&self, pid: libc::pid_t, deadline: Instant) -> std::io::Result<bool> {
        loop {
            // Only reap the script being waited for. Other children can also send SIGCHLD.
            let result = unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) };
            if result == pid {
                return Ok(true);
            }
            if result < 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(error);
            }

            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(false);
            }
            let timeout = libc::timespec {
                tv_sec: remaining.as_secs() as libc::time_t,
                tv_nsec: remaining.subsec_nanos().into(),
            };
            // SIGCHLD stays blocked between waitpid and sigtimedwait to avoid lost wakeups.
            if unsafe {
                libc::sigtimedwait(
                    &raw const self.set,
                    std::ptr::null_mut(),
                    &raw const timeout,
                )
            } < 0
            {
                let error = std::io::Error::last_os_error();
                match error.raw_os_error() {
                    Some(libc::EAGAIN) => return Ok(false),
                    Some(libc::EINTR) => {}
                    _ => return Err(error),
                }
            }
        }
    }
}

impl Drop for SigchldBlock {
    fn drop(&mut self) {
        // Restore the parent's signal mask on success, timeout, and every error path.
        if unsafe {
            libc::sigprocmask(
                libc::SIG_SETMASK,
                &raw const self.previous,
                std::ptr::null_mut(),
            )
        } != 0
        {
            warn!(
                "Failed to restore signal mask: {}",
                std::io::Error::last_os_error()
            );
        }
    }
}

pub fn exec_script<T: AsRef<Path>>(path: T, wait: ScriptWait) -> Result<()> {
    exec_script_with(path, wait, |_| {})
}

/// Like `exec_script`, letting the caller adjust the command before it is spawned.
pub fn exec_script_with<T: AsRef<Path>>(
    path: T,
    wait: ScriptWait,
    configure: impl FnOnce(&mut Command),
) -> Result<()> {
    info!("exec {}", path.as_ref().display());

    let is_module_script = path.as_ref().starts_with(defs::MODULE_DIR);
    // Extract module_id from path if it matches /data/adb/modules/{id}/...
    let module_id = if is_module_script {
        path.as_ref()
            .strip_prefix(defs::MODULE_DIR)
            .ok()
            .and_then(|p| p.components().next())
            .and_then(|c| c.as_os_str().to_str())
            .map(ToString::to_string)
    } else {
        None
    };

    // Validate and log module_id extraction
    let validated_module_id = module_id
        .as_ref()
        .and_then(|id| match validate_module_id(id) {
            Ok(()) => {
                debug!("Module ID extracted from script path: '{id}'");
                Some(id.as_str())
            }
            Err(e) => {
                warn!(
                    "Invalid module ID '{id}' extracted from script path '{}': {e}",
                    path.as_ref().display(),
                );
                None
            }
        });

    if is_module_script && module_id.is_none() {
        debug!(
            "Failed to extract module_id from script path '{}'. Script will run without KSU_MODULE environment variable.",
            path.as_ref().display()
        );
    }

    let sigchld = SigchldBlock::block().context("Failed to block SIGCHLD")?;
    let original_sigmask = sigchld.previous;
    let mut command = Command::new(assets::BUSYBOX_PATH);
    unsafe {
        command.pre_exec(move || {
            if libc::sigprocmask(
                libc::SIG_SETMASK,
                &raw const original_sigmask,
                std::ptr::null_mut(),
            ) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            detach_process_group(true);
            // ignore the error?
            switch_cgroups();
            Ok(())
        })
    };
    command
        .current_dir(path.as_ref().parent().unwrap())
        .arg("sh")
        .arg(path.as_ref())
        .envs(get_common_script_envs(validated_module_id));
    configure(&mut command);

    let result = match wait {
        ScriptWait::NoWait => command.spawn().map(|_| ()),
        ScriptWait::Forever => command.status().map(|_| ()),
        ScriptWait::Until(deadline) => command.spawn().and_then(|child| {
            // Once the shared deadline has passed, launch later scripts without waiting.
            if deadline > Instant::now()
                && !sigchld.wait_until(child.id() as libc::pid_t, deadline)?
            {
                warn!("Timed out waiting for script: {}", path.as_ref().display());
            }
            Ok(())
        }),
    };
    result.map_err(|e| anyhow!("Failed to exec {}: {e}", path.as_ref().display()))
}

pub fn exec_stage_script(stage: &str, wait: ScriptWait) -> Result<()> {
    let metamodule_dir = metamodule::get_metamodule_path().and_then(|path| canonicalize(path).ok());

    foreach_active_module(|module| {
        if metamodule_dir.as_ref().is_some_and(|meta_dir| {
            canonicalize(module).is_ok_and(|resolved| resolved == *meta_dir)
        }) {
            return Ok(());
        }

        let script_path = module.join(format!("{stage}.sh"));
        if !script_path.exists() {
            return Ok(());
        }

        exec_script(&script_path, wait)
    })?;

    Ok(())
}

pub fn exec_common_scripts(dir: &str, wait: ScriptWait) -> Result<()> {
    let script_dir = Path::new(defs::ADB_DIR).join(dir);
    if !script_dir.exists() {
        info!("{} not exists, skip", script_dir.display());
        return Ok(());
    }

    let dir = std::fs::read_dir(&script_dir)?;
    for entry in dir.flatten() {
        let path = entry.path();

        if !is_executable(&path) {
            warn!("{} is not executable, skip", path.display());
            continue;
        }

        exec_script(path, wait)?;
    }

    Ok(())
}

pub fn load_system_prop() -> Result<()> {
    foreach_active_module(|module| {
        let system_prop = module.join("system.prop");
        if !system_prop.exists() {
            return Ok(());
        }
        info!("load {} system.prop", module.display());

        crate::resetprop::load_system_prop_file(&system_prop)?;

        Ok(())
    })?;

    Ok(())
}

pub fn prune_modules() -> Result<()> {
    let mut ids = removal_transaction::pending_ids()?;
    foreach_module(All, |module| {
        if removal_transaction::is_removed(module)
            && let Some(id) = module.file_name().and_then(|name| name.to_str())
        {
            ids.insert(id.to_owned());
        }
        Ok(())
    })?;

    let mut first_error = None;
    for id in ids {
        let result = (|| -> Result<()> {
            let Some(_lock) = install_transaction::mutation_lock(&id, false)? else {
                info!("Module {id} operation in progress, skip removal this time");
                return Ok(());
            };
            let Some(mut removal) = removal_transaction::Removal::open(&id, false)? else {
                return Ok(());
            };
            info!("remove module: {id}");
            removal.run_callbacks()?;
            let _metadata = metadata_lock(&id)?;
            removal.remove()
        })();
        if let Err(error) = result {
            warn!("Failed to remove module {id}: {error:#}");
            if first_error.is_none() { first_error = Some(error); }
        }
    }
    if let Some(error) = first_error { return Err(error); }

    let remaining_modules: Vec<_> = std::fs::read_dir(defs::MODULE_DIR)?
        .filter_map(std::result::Result::ok)
        .filter(|entry| entry.path().join("module.prop").exists())
        .collect();
    if remaining_modules.is_empty() { info!("no remaining modules."); }
    Ok(())
}

pub(super) fn removal_callback_ancestry(module_id: &str) -> String {
    let mut held = std::env::var("KSUD_REMOVAL_CALLBACK_IDS").unwrap_or_default();
    if !held.split(':').any(|id| id == module_id) {
        if !held.is_empty() { held.push(':'); }
        held.push_str(module_id);
    }
    held
}

// Kernels before this UAPI only look for modules.rc under /metadata/watchdog and /metadata.
const PREINIT_VOLD_UAPI_VERSION: u32 = 6;

// Prefer /metadata/vold/ when the kernel reads it, else /metadata/watchdog/, else /metadata.
pub fn preinit_ksu_dir() -> &'static str {
    if ksucalls::get_info().uapi_version >= PREINIT_VOLD_UAPI_VERSION
        && Path::new("/metadata/vold").is_dir()
    {
        defs::PREINIT_DIR_VOLD
    } else if Path::new("/metadata/watchdog").is_dir() {
        defs::PREINIT_DIR_WATCHDOG
    } else {
        defs::PREINIT_DIR_DEFAULT
    }
}

/// SELinux context to label the preinit files with, matching the host dir so
/// init's restorecon does not fight us.
pub fn preinit_con(dir: &str) -> &'static str {
    if dir == defs::PREINIT_DIR_VOLD {
        defs::VOLD_METADATA_FILE_CON
    } else {
        defs::METADATA_FILE_CON
    }
}

fn collect_rc_files<P: AsRef<Path>>(
    dir: P,
    mod_id: Option<&str>,
    out: &mut dyn Write,
) -> Result<()> {
    let dir = dir.as_ref();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Ok(());
    };
    let mut entries: Vec<_> = entries.flatten().collect();
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let Ok(meta) = entry.metadata() else { continue };
        if meta.is_file() && path.extension().and_then(|s| s.to_str()) == Some("rc") {
            if let Some(mod_id) = mod_id {
                writeln!(out, "# === from {mod_id}:{} ===", path.display())?;
            } else {
                // Although the rc file itself is not executable, we still use its executable bit as a switch.
                if !is_executable(&path) {
                    continue;
                }
                writeln!(out, "# === from {} ===", path.display())?;
            }
            let content = std::fs::read(&path)
                .with_context(|| format!("Failed to read rc {}", path.display()))?;
            out.write_all(&content)?;
            writeln!(out)?;
        }
    }
    Ok(())
}

/// Enabled modules for the next boot, by id. modules_update/ wins over modules/, and a disabled or
/// removed module is skipped even if the other dir has an enabled copy.
fn next_boot_modules() -> BTreeMap<String, PathBuf> {
    let mut modules: BTreeMap<String, Option<PathBuf>> = BTreeMap::new();
    for src_dir in [defs::MODULE_UPDATE_DIR, defs::MODULE_DIR] {
        let Ok(entries) = std::fs::read_dir(src_dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let module_path = entry.path();
            if !module_path.is_dir() {
                continue;
            }
            let Some(id) = module_path.file_name().and_then(|s| s.to_str()) else {
                continue;
            };
            if install_transaction::skip_uncommitted(
                &module_path, src_dir == defs::MODULE_UPDATE_DIR,
            ) {
                continue;
            }
            let id = id.to_string();
            if module_path.join(defs::DISABLE_FILE_NAME).exists()
                || module_path.join(defs::REMOVE_FILE_NAME).exists()
                || removal_transaction::is_removed(&Path::new(MODULE_DIR).join(&id))
            {
                modules.insert(id, None);
                continue;
            }
            modules.entry(id).or_insert(Some(module_path));
        }
    }
    modules
        .into_iter()
        .filter_map(|(id, path)| path.map(|path| (id, path)))
        .collect()
}

/// Rebuild PREINITDIR/modules.rc by concatenating *.rc from every enabled
/// module. The kernel-side read hook splices this file into init.rc on the
/// next boot.
fn regenerate_preinit_rc(
    preinit_str: &str,
    modules: &BTreeMap<String, PathBuf>,
    con: &str,
) -> Result<()> {
    let preinit_dir = Path::new(preinit_str);
    std::fs::create_dir_all(preinit_dir)
        .with_context(|| format!("Failed to create {}", preinit_dir.display()))?;

    let tmp_path_buf = preinit_dir.join(defs::MODULES_RC_TMP_FILE);
    let out_path_buf = preinit_dir.join(defs::MODULES_RC_FILE);
    let tmp_path = tmp_path_buf.as_path();
    let out_path = out_path_buf.as_path();

    {
        let mut tmp = File::create(tmp_path)
            .with_context(|| format!("Failed to create {}", tmp_path.display()))?;

        // collect common initrc first
        collect_rc_files(Path::new(defs::ADB_DIR).join("initrc.d"), None, &mut tmp)?;
        // then modules in alphabetical order, with their effective module path in the next boot
        for (id, path) in modules {
            collect_rc_files(path.join(defs::MODULE_INIT_RC_DIR), Some(id), &mut tmp)?;
        }
        tmp.sync_all()?;
    }

    std::fs::rename(tmp_path, out_path).with_context(|| {
        format!(
            "Failed to rename {} -> {}",
            tmp_path.display(),
            out_path.display()
        )
    })?;

    // SELinux label so the kernel's filp_open in init context can read it.
    if let Err(e) = crate::restorecon::lsetfilecon(out_path, con) {
        debug!("set context on {} failed: {e}", out_path.display());
    }

    Ok(())
}

/// Rebuild what the kernel picks up from the preinit partition on the next boot: modules.rc and
/// the modules' preinit dirs.
pub fn regenerate_preinit() -> Result<()> {
    let preinit_str = preinit_ksu_dir();
    let con = preinit_con(preinit_str);
    // The candidates we are not using this boot; clean any leftover from them.
    let stale_strs: Vec<&str> = [
        defs::PREINIT_DIR_VOLD,
        defs::PREINIT_DIR_WATCHDOG,
        defs::PREINIT_DIR_DEFAULT,
    ]
    .into_iter()
    .filter(|d| *d != preinit_str)
    .collect();
    let modules = next_boot_modules();

    let rc = regenerate_preinit_rc(preinit_str, &modules, con);
    // Clear stale modules.rc at the other candidate paths.
    for stale in &stale_strs {
        std::fs::remove_file(Path::new(stale).join(defs::MODULES_RC_FILE)).ok();
    }

    let stale_dirs: Vec<&Path> = stale_strs.iter().map(Path::new).collect();
    let preinit = crate::preinit::sync(
        Path::new(preinit_str),
        &stale_dirs,
        &modules,
        con,
        crate::ksucalls::is_preinit_supported(),
    );
    rc.and(preinit)
}

pub(super) fn recover_module_installations() -> Result<()> {
    install_transaction::recover_before_boot()
}

pub fn handle_updated_modules() -> Result<()> {
    recover_module_installations()?;
    let modules_root = Path::new(MODULE_DIR);
    let mut first_error = None;
    foreach_module(ModuleType::Updated, |updated_module| {
        let Some(id) = updated_module.file_name().and_then(|name| name.to_str()) else {
            return Ok(());
        };
        let result = (|| -> Result<()> {
            validate_module_id(id)?;
            let Some(_lock) = install_transaction::mutation_lock(id, false)? else {
                info!("Module {id} operation in progress, skip update this time");
                return Ok(());
            };
            let _metadata = metadata_lock(id)?;
            let module_dir = modules_root.join(id);
            if removal_transaction::is_removed(&module_dir) {
                return Ok(());
            }
            if module_dir.join(defs::DISABLE_FILE_NAME).exists() {
                ensure_file_exists(updated_module.join(defs::DISABLE_FILE_NAME))?;
            }
            if module_dir.exists() { remove_dir_all(&module_dir)?; }
            rename(updated_module, &module_dir)?;
            Ok(())
        })();
        if let Err(error) = result {
            warn!("Failed to update module {id}: {error:#}");
            if first_error.is_none() { first_error = Some(error); }
        }
        Ok(())
    })?;
    if let Some(error) = first_error { return Err(error); }
    Ok(())
}

fn install_module_to_system(zip: &str) -> Result<String> {
    ensure_boot_completed()?;

    // print banner
    println!(include_str!("banner"));

    assets::ensure_binaries(false).with_context(|| "Failed to extract assets")?;

    // first check if working dir is usable
    ensure_dir_exists(defs::WORKING_DIR).with_context(|| "Failed to create working dir")?;
    ensure_dir_exists(defs::BINARY_DIR).with_context(|| "Failed to create bin dir")?;

    // read the module_id from zip, if failed it will return early.
    let mut buffer: Vec<u8> = Vec::new();
    let entry_path = PathBuf::from_str("module.prop")?;
    let zip_path = PathBuf::from_str(zip)?;
    let zip_path = zip_path.canonicalize()?;
    zip_extract_file_to_memory(&zip_path, &entry_path, &mut buffer)?;

    let mut module_prop = HashMap::new();
    PropertiesIter::new_with_encoding(Cursor::new(buffer), encoding_rs::UTF_8).read_into(
        |k, v| {
            module_prop.insert(k, v);
        },
    )?;
    info!("module prop: {module_prop:?}");

    let Some(module_id) = module_prop.get("id") else {
        bail!("module id not found in module.prop!");
    };
    let module_id = module_id.trim();

    // Validate module_id format
    validate_module_id(module_id)
        .with_context(|| format!("Invalid module ID in module.prop: '{module_id}'"))?;

    // Check if this module is a metamodule
    let is_metamodule = metamodule::is_metamodule(&module_prop);

    // Check if it's safe to install regular module
    if !is_metamodule && let Err(is_disabled) = metamodule::check_install_safety() {
        println!("\n❌ Installation Blocked");
        println!("┌────────────────────────────────");
        println!("│ A metamodule with custom installer is active");
        println!("│");
        if is_disabled {
            println!("│ Current state: Disabled");
            println!("│ Action required: Re-enable or uninstall it, then reboot");
        } else {
            println!("│ Current state: Pending changes");
            println!("│ Action required: Reboot to apply changes first");
        }
        println!("└─────────────────────────────────\n");
        bail!("Metamodule installation blocked");
    }

    // All modules (including metamodules) are installed to MODULE_UPDATE_DIR
    let updated_dir = Path::new(defs::MODULE_UPDATE_DIR).join(module_id);

    if is_metamodule {
        info!("Installing metamodule: {module_id}");

        ensure_unique_metamodule(module_id)?;
    }

    let zip_uncompressed_size = get_zip_uncompressed_size(zip)?;
    info!(
        "zip uncompressed size: {}",
        humansize::format_size(zip_uncompressed_size, humansize::DECIMAL)
    );
    println!(
        "- Module size: {}",
        humansize::format_size(zip_uncompressed_size, humansize::DECIMAL)
    );

    // Ensure module directory exists and set SELinux context
    ensure_dir_exists(defs::MODULE_UPDATE_DIR)?;
    setsyscon(defs::MODULE_UPDATE_DIR)?;

    let mut transaction = install_transaction::InstallTransaction::begin(module_id)?;

    // Prepare target directory
    println!("- Installing to {}", updated_dir.display());
    ensure_clean_dir(&updated_dir)?;
    info!("target dir: {}", updated_dir.display());

    // Extract zip to target directory
    println!("- Extracting module files");
    let file = File::open(zip)?;
    let mut archive = zip::ZipArchive::new(file)?;
    archive.extract(&updated_dir)?;
    // Only installer.sh may request a hot install, not a file shipped in the zip
    std::fs::remove_file(updated_dir.join(defs::HOT_INSTALL_MARKER)).ok();

    // Set permission and selinux context for $MOD/system
    let module_system_dir = updated_dir.join("system");
    if module_system_dir.exists() {
        set_permissions(&module_system_dir, Permissions::from_mode(0o755))?;
        restore_syscon(&module_system_dir)?;
    }

    // Execute install script
    println!("- Running module installer");
    exec_install_script(zip, is_metamodule, module_id, &transaction.temporary_dir())?;
    transaction.publish_metadata(is_metamodule)?;
    transaction.commit()?;
    let metadata_guard = transaction.take_metadata_guard();

    if let Some(request) = hot_install::take_request(&updated_dir)
        && hot_install::apply(module_id, is_metamodule, &request, metadata_guard)
    {
        println!("- Module installed successfully, no reboot required!");
        info!("Module {module_id} installed successfully!");
        return Ok(module_id.to_owned());
    }

    println!("- Module installed successfully!");
    info!("Module {module_id} installed successfully!");

    Ok(module_id.to_owned())
}

pub(super) fn duplicate_metamodule_error(existing_id: &str) -> Result<()> {
    println!("\n❌ Installation Failed");
    println!("┌────────────────────────────────");
    println!("│ A metamodule is already installed");
    println!("│   Current metamodule: {existing_id}");
    println!("│");
    println!("│ Only one metamodule can be active at a time.");
    println!("│");
    println!("│ To install this metamodule:");
    println!("│   1. Uninstall the current metamodule");
    println!("│   2. Reboot your device");
    println!("│   3. Install the new metamodule");
    println!("└─────────────────────────────────\n");
    bail!("Cannot install multiple metamodules");
}

pub(super) fn ensure_unique_metamodule(module_id: &str) -> Result<()> {
    // Check if there's already a metamodule installed
    if metamodule::has_metamodule()
        && let Some(existing_path) = metamodule::get_metamodule_path()
    {
        let existing_id = read_module_prop(&existing_path)
            .ok()
            .and_then(|m| m.get("id").cloned())
            .unwrap_or_else(|| "unknown".to_string());

        if existing_id != module_id {
            return duplicate_metamodule_error(&existing_id);
        }
    }
    Ok(())
}

pub fn install_module(zip: &str) -> Result<()> {
    ksucalls::ensure_uapi_version_matched()?;

    let module_id = install_module_to_system(zip).inspect_err(|e| println!("- Error: {e}"))?;
    if let Err(e) = regenerate_preinit() {
        warn!("regenerate preinit failed: {e:#}");
    }
    if let Some((state, message)) = crate::preinit::status_of(&module_id)
        && state != "ok"
    {
        println!("! preinit will not take effect: {state} {message}");
    }
    Ok(())
}

pub fn undo_uninstall_module(id: &str) -> Result<()> {
    validate_module_id(id)?;
    {
        let _lock = install_transaction::mutation_lock(id, true)?
            .context("Missing module mutation lock")?;
        let _metadata = metadata_lock(id)?;
        let module_path = Path::new(defs::MODULE_DIR).join(id);
        ensure!(module_path.exists(), "Module {id} not found");
        removal_transaction::cancel(id)?;
    }
    info!("Removed the remove mark for module {id}");
    if let Err(e) = regenerate_preinit() {
        warn!("regenerate preinit failed: {e:#}");
    }
    Ok(())
}

pub fn uninstall_module(id: &str) -> Result<()> {
    mark_module_for_removal(id)?;
    info!("Module {id} marked for removal");
    if let Err(e) = regenerate_preinit() {
        warn!("regenerate preinit failed: {e:#}");
    }
    Ok(())
}

fn mark_module_for_removal(id: &str) -> Result<()> {
    validate_module_id(id)?;
    let _lock = install_transaction::mutation_lock(id, true)?
        .context("Missing module mutation lock")?;
    let _metadata = metadata_lock(id)?;
    let module_path = Path::new(defs::MODULE_DIR).join(id);
    ensure!(module_path.exists(), "Module {id} not found");
    removal_transaction::mark(id).context("Failed to create remove file")
}

pub fn run_action(id: &str) -> Result<()> {
    validate_module_id(id)?;
    ksucalls::ensure_uapi_version_matched()?;

    let action_script_path = format!("/data/adb/modules/{id}/action.sh");
    exec_script(&action_script_path, ScriptWait::Forever)
}

pub fn enable_module(id: &str) -> Result<()> {
    validate_module_id(id)?;

    {
        let _metadata = metadata_lock(id)?;
        let module_path = Path::new(defs::MODULE_DIR).join(id);
        ensure!(module_path.exists(), "Module {id} not found");

        let disable_path = module_path.join(defs::DISABLE_FILE_NAME);
        if disable_path.exists() {
            std::fs::remove_file(&disable_path).with_context(|| {
                format!("Failed to remove disable file: {}", disable_path.display())
            })?;
            info!("Module {id} enabled");
        }
    }

    if let Err(e) = regenerate_preinit() {
        warn!("regenerate preinit failed: {e:#}");
    }

    Ok(())
}

pub fn disable_module(id: &str) -> Result<()> {
    validate_module_id(id)?;
    {
        let _metadata = metadata_lock(id)?;
        let module_path = Path::new(defs::MODULE_DIR).join(id);
        ensure!(module_path.exists(), "Module {id} not found");

        let disable_path = module_path.join(defs::DISABLE_FILE_NAME);
        ensure_file_exists(disable_path)?;
    }

    info!("Module {id} disabled");

    if let Err(e) = regenerate_preinit() {
        warn!("regenerate preinit failed: {e:#}");
    }

    Ok(())
}

pub fn disable_all_modules() -> Result<()> {
    let result = mark_all_modules(defs::DISABLE_FILE_NAME);
    if let Err(e) = regenerate_preinit() {
        warn!("regenerate preinit failed: {e:#}");
    }
    result
}

pub fn uninstall_all_modules() -> Result<()> {
    info!("Uninstalling all modules");
    let result = mark_all_modules(defs::REMOVE_FILE_NAME);
    if let Err(e) = regenerate_preinit() {
        warn!("regenerate preinit failed: {e:#}");
    }
    result
}

fn mark_all_modules(flag_file: &str) -> Result<()> {
    // we assume the module dir is already mounted
    let dir = std::fs::read_dir(defs::MODULE_DIR)?;
    let mut first_error = None;
    for entry in dir {
        let result = (|| -> Result<()> {
            let entry = entry?;
            if !entry.file_type()?.is_dir() { return Ok(()); }
            let name = entry.file_name();
            let id = name.to_str().context("Invalid module directory name")?;
            validate_module_id(id)?;
            if flag_file == defs::REMOVE_FILE_NAME {
                mark_module_for_removal(id)?;
            } else {
                let _metadata = metadata_lock(id)?;
                let path = Path::new(defs::MODULE_DIR).join(id);
                ensure!(path.is_dir(), "Module {id} not found");
                ensure_file_exists(path.join(flag_file))
                    .with_context(|| format!("Failed to mark module {id}"))?;
            }
            Ok(())
        })();
        if let Err(error) = result {
            warn!("Failed to mark modules {flag_file}: {error:#}");
            if first_error.is_none() { first_error = Some(error); }
        }
    }
    if let Some(error) = first_error { return Err(error); }
    Ok(())
}

/// Read module.prop from the given module path and return as a HashMap
pub fn read_module_prop(module_path: &Path) -> Result<HashMap<String, String>> {
    let module_prop = module_path.join("module.prop");
    ensure!(
        module_prop.exists(),
        "module.prop not found in {}",
        module_path.display()
    );

    let content = std::fs::read(&module_prop)
        .with_context(|| format!("Failed to read module.prop: {}", module_prop.display()))?;

    let mut prop_map: HashMap<String, String> = HashMap::new();
    PropertiesIter::new_with_encoding(Cursor::new(content), encoding_rs::UTF_8)
        .read_into(|k, v| {
            prop_map.insert(k, v);
        })
        .with_context(|| format!("Failed to parse module.prop: {}", module_prop.display()))?;

    Ok(prop_map)
}

/// Resolve a module icon path to an absolute on-disk path
fn resolve_module_icon_path(
    module_prop_map: &mut HashMap<String, String>,
    key: &str,
    module_path: &Path,
) {
    if let Some(icon_value) = module_prop_map.get(key) {
        let icon_value = icon_value.trim();
        if icon_value.is_empty() {
            return;
        }
        let path = std::path::Path::new(icon_value);
        if path.is_absolute() {
            log::warn!(
                "Rejected {} with absolute path for module {}: {}",
                key,
                module_prop_map.get("id").map_or("", String::as_str),
                icon_value
            );
            return;
        }
        let has_parent = path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir));
        if has_parent {
            log::warn!(
                "Rejected {} with parent traversal for module {}: {}",
                key,
                module_prop_map.get("id").map_or("", String::as_str),
                icon_value
            );
            return;
        }
        let candidate = module_path.join(path);
        if candidate.exists() && candidate.is_file() {
            if let Some(s) = candidate.to_str() {
                module_prop_map.insert(key.to_owned(), s.to_string());
            }
        } else {
            log::debug!(
                "{} not found for module {}: {}",
                key,
                module_prop_map.get("id").map_or("", String::as_str),
                candidate.display()
            );
        }
    }
}

fn list_module(path: &str) -> Vec<HashMap<String, String>> {
    // Load all module configs once to minimize I/O overhead
    let all_configs = match crate::module_config::get_all_module_configs() {
        Ok(configs) => configs,
        Err(e) => {
            warn!("Failed to load module configs: {e}");
            HashMap::new()
        }
    };

    let preinit_states = crate::preinit::module_states();

    // first check enabled modules
    let dir = std::fs::read_dir(path);
    let Ok(dir) = dir else {
        return Vec::new();
    };

    let mut modules: Vec<HashMap<String, String>> = Vec::new();

    for entry in dir.flatten() {
        let path = entry.path();
        info!("path: {}", path.display());

        if install_transaction::skip_uncommitted(&path, false)
            || !path.join("module.prop").exists()
        {
            continue;
        }

        let mut module_prop_map = match read_module_prop(&path) {
            Ok(prop) => prop,
            Err(e) => {
                warn!("Failed to read module.prop for {}: {e}", path.display());
                continue;
            }
        };

        // If id is missing or empty, use directory name as fallback
        if !module_prop_map.contains_key("id") || module_prop_map["id"].is_empty() {
            if let Some(id) = entry.file_name().to_str() {
                info!("Use dir name as module id: {id}");
                module_prop_map.insert("id".to_owned(), id.to_owned());
            } else {
                info!("Failed to get module id from dir name");
                continue;
            }
        }

        // Add enabled, update, remove, web, action flags
        let enabled = !path.join(defs::DISABLE_FILE_NAME).exists();
        let update = path.join(defs::UPDATE_FILE_NAME).exists();
        let remove = removal_transaction::is_removed(&path);
        let web = path.join(defs::MODULE_WEB_DIR).exists();
        let action = path.join(defs::MODULE_ACTION_SH).exists();
        let need_mount = path.join("system").exists() && !path.join("skip_mount").exists();

        module_prop_map.insert("enabled".to_owned(), enabled.to_string());
        module_prop_map.insert("update".to_owned(), update.to_string());
        module_prop_map.insert("remove".to_owned(), remove.to_string());
        module_prop_map.insert("web".to_owned(), web.to_string());
        module_prop_map.insert("action".to_owned(), action.to_string());
        module_prop_map.insert("mount".to_owned(), need_mount.to_string());
        if let Some(state) = module_prop_map
            .get("id")
            .and_then(|id| preinit_states.get(id.as_str()))
        {
            module_prop_map.insert("preinit".to_owned(), state.clone());
        }

        resolve_module_icon_path(&mut module_prop_map, "actionIcon", &path);
        resolve_module_icon_path(&mut module_prop_map, "webuiIcon", &path);

        // Apply module config overrides and extract managed features
        if let Some(module_id) = module_prop_map.get("id")
            && let Some(config) = all_configs.get(module_id.as_str())
        {
            // Apply override.description
            if let Some(desc) = config.get("override.description") {
                module_prop_map.insert("description".to_owned(), desc.clone());
            }

            // Extract managed features from manage.* config entries
            let managed_features: Vec<String> = config
                .iter()
                .filter_map(|(k, v)| {
                    if k.starts_with("manage.") && crate::module_config::parse_bool_config(v) {
                        k.strip_prefix("manage.")
                            .map(std::string::ToString::to_string)
                    } else {
                        None
                    }
                })
                .collect();

            if !managed_features.is_empty() {
                module_prop_map.insert("managedFeatures".to_owned(), managed_features.join(","));
            }
        }

        modules.push(module_prop_map);
    }

    modules
}

pub fn list_modules() -> Result<()> {
    let mut modules = list_module(defs::MODULE_DIR);
    removal_transaction::append_pending_rows(&mut modules)?;
    println!("{}", serde_json::to_string_pretty(&modules)?);
    Ok(())
}

/// Get all managed features from active modules
/// Modules declare managed features via config system (manage.<feature>=true)
/// Returns: HashMap<ModuleId, Vec<ManagedFeature>>
pub fn get_managed_features() -> Result<HashMap<String, Vec<String>>> {
    let mut managed_features_map: HashMap<String, Vec<String>> = HashMap::new();

    foreach_active_module(|module_path| {
        // Get module ID
        let Some(module_id) = module_path.file_name().and_then(|n| n.to_str()) else {
            warn!(
                "Failed to get module id from path: {}",
                module_path.display()
            );
            return Ok(());
        };

        // Read module config
        let config = match crate::module_config::merge_configs(module_id) {
            Ok(c) => c,
            Err(e) => {
                warn!("Failed to merge configs for module '{module_id}': {e}");
                return Ok(()); // Skip this module
            }
        };

        // Extract manage.* config entries
        let mut feature_list = Vec::new();
        for (key, value) in &config {
            if key.starts_with("manage.") {
                // Parse feature name
                if let Some(feature_name) = key.strip_prefix("manage.")
                    && crate::module_config::parse_bool_config(value)
                {
                    feature_list.push(feature_name.to_string());
                }
            }
        }

        if !feature_list.is_empty() {
            managed_features_map.insert(module_id.to_string(), feature_list);
        }

        Ok(())
    })?;

    Ok(managed_features_map)
}
// ══════════════════════════════════════════════════════════════════════════
// MapleSU W18b（0006b）· 模块网页（module webui / webadmin）执行 API
//
// 7K `userspace/ksud/src/module.rs` 的模块网页支持（ExecOptions / 进程捕获 /
// 包名与包信息 / action 捕获 / 模块内执行），逐字切片移植。
// ══════════════════════════════════════════════════════════════════════════

/// 模块网页传过来的执行选项（对齐 KernelSU 的 `options`：`cwd` 与 `env`）。
///
/// ⚠️ 管理器 App 是把它们**拼进 shell 命令行**（`cd x; export K=V;`）；
/// 我们直接设 `current_dir()` / `envs()` —— 语义一样，但不会因为路径或环境变量里
/// 带空格、引号、`;` 而被 shell 拆开（免注入）。
#[derive(Default, Clone, Debug)]
pub struct ExecOptions {
    pub cwd: Option<String>,
    pub env: Vec<(String, String)>,
}

/// 解析模块网页给的 options JSON（坏 JSON 当空处理，与 App 的 `optString` 宽松行为一致）
pub fn parse_exec_options(options_json: &str) -> ExecOptions {
    let mut out = ExecOptions::default();
    let trimmed = options_json.trim();
    if trimmed.is_empty() || trimmed == "{}" {
        return out;
    }
    let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed) else {
        return out;
    };
    if let Some(cwd) = v.get("cwd").and_then(|c| c.as_str()) {
        let c = cwd.trim();
        if !c.is_empty()
            && c.len() <= 4096
            && !c.contains('\0')
            && std::path::Path::new(c).is_absolute()
        {
            out.cwd = Some(c.to_string());
        }
    }
    if let Some(env) = v.get("env").and_then(|e| e.as_object()) {
        for (k, val) in env {
            // 环境变量名必须合法；值限长（别让模块塞几百 MB 进来）
            let name_ok = !k.is_empty()
                && k.len() <= 128
                && k.chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
            if !name_ok {
                warn!("模块网页给的 env 名字不合法，已忽略：{k}");
                continue;
            }
            let sval = match val {
                serde_json::Value::String(sv) => sv.clone(),
                other => other.to_string(),
            };
            if sval.len() > 8192 || sval.contains('\0') {
                warn!("模块网页给的 env 值太长或含 NUL，已忽略：{k}");
                continue;
            }
            out.env.push((k.clone(), sval));
        }
    }
    out
}

/// 跑一段 busybox sh 并把 stdout/stderr **抓回来**（网页管理器要显示输出）。
///
/// 与 `exec_script` 的区别：这里**不继承**调用方的标准输出，而是开管道读回来；
/// 并且带超时 —— 超时会杀掉**整个进程组**（脚本里 fork 的子进程也一起收掉）。
fn run_busybox_capture(
    args: &[&str],
    cwd: &Path,
    module_id: Option<&str>,
    timeout: std::time::Duration,
    extra_env: &[(String, String)],
) -> Result<(i32, String, String)> {
    use std::io::Read as _;
    use std::process::Stdio;

    let mut command = &mut Command::new(assets::BUSYBOX_PATH);
    #[cfg(unix)]
    {
        command = unsafe {
            command.pre_exec(|| {
                detach_process_group(true);
                switch_cgroups();
                Ok(())
            })
        };
    }
    let mut child = command
        .current_dir(cwd)
        .args(args)
        .envs(get_common_script_envs(module_id))
        .envs(extra_env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow!("跑不起来 {args:?}: {e}"))?;
    let pid = child.id();

    // stdout / stderr 各用一个线程读，免得管道写满把子进程卡死
    let h_out = child.stdout.take().map(|mut o| {
        std::thread::spawn(move || {
            let mut s = String::new();
            let _ = o.read_to_string(&mut s);
            s
        })
    });
    let h_err = child.stderr.take().map(|mut e| {
        std::thread::spawn(move || {
            let mut s = String::new();
            let _ = e.read_to_string(&mut s);
            s
        })
    });

    let start = std::time::Instant::now();
    let mut code: i32 = -1;
    let mut timed_out = false;
    loop {
        match child.try_wait() {
            Ok(Some(st)) => {
                code = st.code().unwrap_or(-1);
                break;
            }
            Ok(None) => {
                if start.elapsed() > timeout {
                    timed_out = true;
                    // 负号 = 杀整个进程组
                    unsafe { libc::kill(-(pid as i32), libc::SIGKILL) };
                    let _ = child.kill();
                    let _ = child.wait();
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(80));
            }
            Err(e) => return Err(e.into()),
        }
    }

    let stdout = h_out.and_then(|h| h.join().ok()).unwrap_or_default();
    let mut stderr = h_err.and_then(|h| h.join().ok()).unwrap_or_default();
    if timed_out {
        use std::fmt::Write as _;
        let _ = write!(stderr, "\n[超时 {} 秒，已强制结束]", timeout.as_secs());
    }
    Ok((code, stdout, stderr))
}

/// 列出已安装的包名（`kind`：user=第三方 / system=系统 / 其它=全部）
/// —— 给模块网页的 `ksu.listPackages()` 用
pub fn list_package_names(kind: &str) -> Result<Vec<String>> {
    let flag = match kind {
        "user" => " -3",
        "system" => " -s",
        _ => "",
    };
    let cmd = format!("/system/bin/pm list packages{flag}");
    let (code, out, err) = run_busybox_capture(
        &["sh", "-c", cmd.as_str()],
        Path::new("/"),
        None,
        std::time::Duration::from_secs(30),
        &[],
    )?;
    ensure!(code == 0, "pm list packages 失败（{code}）：{err}");
    let mut names: Vec<String> = out
        .lines()
        .filter_map(|l| l.trim().strip_prefix("package:"))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    names.sort();
    names.dedup();
    Ok(names)
}

/// 一批包的详细信息（给模块网页的 `ksu.getPackagesInfo()` 用）。
///
/// 说明：管理器 App 里这个接口能给出应用名（appLabel），但那是 Android 框架的便利；
/// 我们这边只能拿到 `pm` / `dumpsys` 能给的字段，所以 **appLabel 用包名兜底**。
pub fn packages_info(names: &[String]) -> Result<Vec<serde_json::Value>> {
    if names.is_empty() {
        return Ok(Vec::new());
    }
    // 包名逐个校验（要拼进 shell，必须挡住注入）
    let safe: Vec<&String> = names
        .iter()
        .filter(|n| {
            !n.is_empty()
                && n.len() <= 255
                && n.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_')
        })
        .collect();

    // ① 一次拿到「包名 → uid + APK 路径」（`pm list packages -U -f` 的输出形如
    //    `package:/data/app/xx/base.apk=com.foo uid:10123`）和系统包名单（判断 isSystem）
    let (uid_map, apk_map, system_set) = {
        let (code, out, _) = run_busybox_capture(
            &["sh", "-c", "/system/bin/pm list packages -U -f"],
            Path::new("/"),
            None,
            std::time::Duration::from_secs(30),
            &[],
        )?;
        let mut uids: std::collections::HashMap<String, i64> = std::collections::HashMap::default();
        let mut apks: std::collections::HashMap<String, PathBuf> =
            std::collections::HashMap::default();
        if code == 0 {
            for line in out.lines() {
                let line = line.trim();
                let Some(rest) = line.strip_prefix("package:") else {
                    continue;
                };
                let mut it = rest.split_whitespace();
                let Some(first) = it.next() else { continue };
                // 带 -f 时是 "路径=包名"，不带时就是包名。
                // ⚠️ 必须从**最后一个** '=' 切：APK 路径里就可能带 '='
                //    （真机踩过：/data/app/~~SZR17Ey5KIEUYHBrwNvJvQ==/base.apk=com.xxx
                //     从第一个 '=' 切会把路径截断，于是那个 App 的名字解析不出来）
                let (apk, pkg) = match first.rsplit_once('=') {
                    Some((path, pkg)) => (Some(path), pkg),
                    None => (None, first),
                };
                let uid = it
                    .find_map(|tok| tok.strip_prefix("uid:"))
                    .and_then(|v| v.parse::<i64>().ok());
                if let Some(u) = uid {
                    uids.insert(pkg.to_string(), u);
                }
                if let Some(path) = apk {
                    apks.insert(pkg.to_string(), PathBuf::from(path));
                }
            }
        }
        let (scode, sout, _) = run_busybox_capture(
            &["sh", "-c", "/system/bin/pm list packages -s"],
            Path::new("/"),
            None,
            std::time::Duration::from_secs(30),
            &[],
        )?;
        let mut sys: std::collections::HashSet<String> = std::collections::HashSet::default();
        if scode == 0 {
            for line in sout.lines() {
                if let Some(p) = line.trim().strip_prefix("package:") {
                    sys.insert(p.trim().to_string());
                }
            }
        }
        (uids, apks, sys)
    };

    // ② 一次 shell 把所有包的信息抓回来（比每个包一次 exec 快得多）
    let mut script = String::new();
    for n in &safe {
        script.push_str("/system/bin/echo \"=== ");
        script.push_str(n);
        script.push_str("\"; /system/bin/dumpsys package ");
        script.push_str(n);
        script.push_str(" 2>/dev/null | /system/bin/grep -E 'versionName=|versionCode=' | /system/bin/head -2; ");
    }
    let (_, out, _) = run_busybox_capture(
        &["sh", "-c", script.as_str()],
        Path::new("/"),
        None,
        std::time::Duration::from_secs(60),
        &[],
    )?;

    // ③ 解析
    let mut result: Vec<serde_json::Value> = Vec::new();
    let mut cur: Option<String> = None;
    let mut fields: std::collections::HashMap<String, String> =
        std::collections::HashMap::default();
    let flush = |pkg: &str,
                 f: &std::collections::HashMap<String, String>,
                 sys: &std::collections::HashSet<String>,
                 uids: &std::collections::HashMap<String, i64>,
                 apks: &std::collections::HashMap<String, PathBuf>,
                 out: &mut Vec<serde_json::Value>| {
        if pkg.is_empty() {
            return;
        }
        if f.is_empty() {
            out.push(serde_json::json!({
                "packageName": pkg,
                "error": "Package not found or inaccessible",
            }));
            return;
        }
        let vcode = f
            .get("versionCode")
            .and_then(|s| s.split_whitespace().next())
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(0);
        let uid = uids.get(pkg).copied();
        // 应用名：自己解析 APK 里的 `<application android:label>`（拿不到就退回包名）
        let app_label = apks
            .get(pkg)
            .and_then(|p| crate::res_label::label_from_apk(p))
            .unwrap_or_else(|| pkg.to_string());
        out.push(serde_json::json!({
            "packageName": pkg,
            "appLabel": app_label,
            "versionName": f.get("versionName").cloned().unwrap_or_default(),
            "versionCode": vcode,
            "isSystem": sys.contains(pkg),
            "uid": uid,
        }));
    };
    for line in out.lines() {
        let line = line.trim();
        if let Some(name) = line.strip_prefix("=== ") {
            if let Some(prev) = cur.take() {
                flush(&prev, &fields, &system_set, &uid_map, &apk_map, &mut result);
            }
            fields.clear();
            cur = Some(name.trim().to_string());
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let k = k.trim();
            if k == "versionName" || k == "versionCode" || k == "userId" {
                fields.insert(k.to_string(), v.trim().to_string());
            }
        }
    }
    if let Some(prev) = cur.take() {
        flush(&prev, &fields, &system_set, &uid_map, &apk_map, &mut result);
    }
    Ok(result)
}

/// 网页管理器：跑模块的 `action.sh`，把输出带回去
pub fn run_action_capture(id: &str) -> Result<(i32, String, String)> {
    validate_module_id(id)?;
    let path = Path::new(defs::MODULE_DIR)
        .join(id)
        .join(defs::MODULE_ACTION_SH);
    ensure!(path.exists(), "这个模块没有动作脚本（action.sh）");
    ksucalls::ensure_uapi_version_matched()?;
    info!("run action capture: {}", path.display());
    run_busybox_capture(
        &["sh", path.to_string_lossy().as_ref()],
        path.parent().unwrap_or_else(|| Path::new("/")),
        Some(id),
        std::time::Duration::from_secs(120),
        &[],
    )
}

/// 模块网页里的 `ksu.exec`：以 root 在**模块目录**里跑一条命令，把输出带回去
/// （语义对齐管理器 App 的 WebView 桥：cwd = 模块目录、带 KSU_MODULE 等环境变量）
pub fn exec_in_module(id: &str, cmd: &str, options_json: &str) -> Result<(i32, String, String)> {
    validate_module_id(id)?;
    let dir = Path::new(defs::MODULE_DIR).join(id);
    ensure!(dir.exists(), "模块目录不存在：{id}");
    ksucalls::ensure_uapi_version_matched()?;
    let opts = parse_exec_options(options_json);
    let cwd = match &opts.cwd {
        Some(c) => {
            let p = PathBuf::from(c);
            ensure!(p.exists(), "options 里的 cwd 不存在：{c}");
            p
        }
        None => dir,
    };
    info!(
        "module webui exec: module={id} cwd={} env={} cmd={cmd}",
        cwd.display(),
        opts.env.len()
    );
    run_busybox_capture(
        &["sh", "-c", cmd],
        &cwd,
        Some(id),
        std::time::Duration::from_secs(60),
        &opts.env,
    )
}

/// 模块列表的 JSON 文本（网页管理器直接拿去当 /api/modules 的响应）
pub fn list_modules_json() -> Result<String> {
    let modules = list_module(defs::MODULE_DIR);
    Ok(serde_json::to_string(&modules)?)
}
