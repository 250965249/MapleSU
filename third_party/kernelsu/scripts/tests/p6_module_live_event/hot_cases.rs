#![allow(dead_code)]
use std::{fs, io, path::Path, process::Command, time::Instant};

mod defs {
    pub const WORKING_DIR: &str = "/work/live-event";
    pub const MODULE_DIR: &str = "/work/live-event/modules";
    pub const MODULE_UPDATE_DIR: &str = "/work/live-event/pending";
    pub const HOT_INSTALL_TRASH_DIR: &str = "/work/live-event/trash";
    pub const HOT_INSTALL_MARKER: &str = ".ksu_hot_install";
    pub const MODULE_PREINIT_DIR: &str = "preinit";
    pub const HOT_INSTALL_SCRIPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
}
mod assets { pub const BUSYBOX_PATH: &str = "/bin/sh"; }
mod utils {
    pub fn ensure_dir_exists(path: impl AsRef<std::path::Path>) -> std::io::Result<()> {
        std::fs::create_dir_all(path)
    }
    pub fn is_safe_mode() -> bool { std::env::var_os("FIXTURE_SAFE_MODE").is_some() }
    pub fn switch_mnt_ns(_: i32) -> anyhow::Result<()> { Ok(()) }
}
mod sepolicy {
    pub fn apply_file(_: impl AsRef<std::path::Path>) -> anyhow::Result<()> {
        anyhow::bail!("fixture policy failure after actual rename")
    }
}
mod module {
    use super::*;
    pub enum ScriptWait { Until(Instant) }
    pub fn exec_script_with(
        script: std::path::PathBuf, _: ScriptWait, configure: impl FnOnce(&mut Command),
    ) -> anyhow::Result<()> {
        let mut command = Command::new("/bin/sh");
        command.arg(script);
        configure(&mut command);
        anyhow::ensure!(command.status()?.success(), "fixture script failed");
        Ok(())
    }
}
#[path = "actual_hot_install.rs"]
mod hot_install;

// The only fault seam: fail the staged->live syscall, optionally occupying its target
// so that the original rollback rename also fails. Stash/restore remain real Linux I/O.
fn publish_rename(source: &Path, target: &Path) -> io::Result<()> {
    match std::env::var("FIXTURE_RENAME").as_deref() {
        Ok("restore-failed") => {
            fs::create_dir_all(target)?;
            fs::write(target.join("occupied"), "external mutation")?;
            Err(io::Error::from_raw_os_error(18))
        }
        Ok("failed") => Err(io::Error::from_raw_os_error(18)),
        _ => fs::rename(source, target),
    }
}

fn main() -> anyhow::Result<()> {
    let case = std::env::args().nth(1).expect("case");
    let root = Path::new(defs::WORKING_DIR);
    if root.exists() { fs::remove_dir_all(root)?; }
    let live = Path::new(defs::MODULE_DIR).join("alpha");
    let pending = Path::new(defs::MODULE_UPDATE_DIR).join("alpha");
    fs::create_dir_all(&live)?;
    fs::create_dir_all(&pending)?;
    fs::write(live.join("value"), "old")?;
    fs::write(pending.join("value"), "new")?;
    let script = if case == "invalid-script" { "../outside" }
                 else if case == "script" { "service.sh" } else { "" };
    fs::write(pending.join(defs::HOT_INSTALL_MARKER), script)?;
    if case == "script" {
        fs::write(pending.join("sepolicy.rule"), "fixture")?;
        fs::write(pending.join("service.sh"),
            "[ -z \"${KSUD_MODULE_LIVE_EVENT+x}\" ] || exit 23\n"
                .to_owned() + "printf 'SCRIPT_ENV_CLEARED\\n'\nexit 17\n")?;
    }
    let request = hot_install::take_request(&pending).expect("request");
    let applied = hot_install::apply("alpha", case == "metamodule", &request, None);
    match case.as_str() {
        "rollback" => {
            assert!(!applied);
            assert_eq!(fs::read_to_string(live.join("value"))?, "old");
            assert_eq!(fs::read_to_string(pending.join("value"))?, "new");
        }
        "restore-failed" => {
            assert!(!applied);
            assert!(live.join("occupied").is_file());
            assert!(!live.join("value").exists());
        }
        "metamodule" | "safe-mode" | "invalid-script" => {
            assert!(!applied);
            assert_eq!(fs::read_to_string(live.join("value"))?, "old");
        }
        _ => {
            assert!(applied);
            assert_eq!(fs::read_to_string(live.join("value"))?, "new");
            assert!(!pending.exists());
        }
    }
    println!("PASS:{case}");
    Ok(())
}
