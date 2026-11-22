# SPDX-License-Identifier: GPL-3.0-or-later
"""Normal module publication rollback and boot recovery on the pinned ksud installer."""
from __future__ import annotations

MODULE_INSTALL_TRANSACTION_RS = r"""use crate::{defs, metamodule, utils::{ensure_dir_exists, ensure_file_exists}};
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use std::{
    fs::{self, DirBuilder, File, OpenOptions},
    io::{self, Read, Write},
    os::{fd::AsRawFd, unix::fs::{DirBuilderExt, OpenOptionsExt}},
    path::{Path, PathBuf},
};

pub(super) struct InstallTransaction {
    directory: PathBuf,
    _lock: File,
    record: Value,
    committed: bool,
    commit_visible: bool,
    record_durable: bool,
}

fn root() -> PathBuf {
    Path::new(defs::WORKING_DIR).join(".module-install")
}

fn sync_dir(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

fn sync_existing_parent(path: &Path) -> Result<()> {
    let mut parent = path.parent().context("Missing parent directory")?;
    loop {
        match fs::symlink_metadata(parent) {
            Ok(_) => return sync_dir(parent),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                parent = parent.parent().context("Missing existing parent directory")?;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn sync_tree(path: &Path) -> Result<()> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_dir() {
            sync_tree(&entry.path())?;
        } else if kind.is_file() {
            OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW)
                .open(entry.path())?.sync_all()?;
        }
    }
    sync_dir(path)
}

fn remove_entry(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => fs::remove_dir_all(path),
        Ok(_) => fs::remove_file(path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn private_root() -> Result<PathBuf> {
    let path = root();
    match DirBuilder::new().mode(0o700).create(&path) {
        Ok(()) => sync_dir(Path::new(defs::WORKING_DIR))?,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            ensure!(fs::symlink_metadata(&path)?.is_dir(), "Invalid installation state directory");
        }
        Err(error) => return Err(error.into()),
    }
    Ok(path)
}

fn lock(module_id: &str, wait: bool) -> Result<Option<File>> {
    let file = OpenOptions::new().read(true).write(true).create(true).truncate(false)
        .mode(0o600).custom_flags(libc::O_NOFOLLOW)
        .open(private_root()?.join(format!(".lock-{module_id}")))?;
    loop {
        let flags = libc::LOCK_EX | if wait { 0 } else { libc::LOCK_NB };
        if unsafe { libc::flock(file.as_raw_fd(), flags) } == 0 {
            return Ok(Some(file));
        }
        let error = io::Error::last_os_error();
        if !wait && error.kind() == io::ErrorKind::WouldBlock {
            return Ok(None);
        }
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error.into());
        }
    }
}

fn metadata_path(module_id: &str, name: &str) -> Result<PathBuf> {
    match name {
        "module.prop" | "update" | "remove" | "disable" | ".ksu_hot_install" => {
            Ok(Path::new(defs::MODULE_DIR).join(module_id).join(name))
        }
        "metamodule" => Ok(PathBuf::from(defs::METAMODULE_DIR.trim_end_matches('/'))),
        _ => bail!("Invalid installation metadata entry"),
    }
}

fn read_record(directory: &Path, module_id: &str) -> Result<Option<Value>> {
    let text = match fs::read(directory.join("record")) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let record: Value = serde_json::from_slice(&text)?;
    ensure!(record["version"] == 1 && record["id"] == module_id,
        "Invalid installation transaction identity");
    ensure!(record["generation"].as_str().is_some_and(|value|
        value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit())),
        "Invalid installation transaction generation");
    ensure!(matches!(record["phase"].as_str(), Some("preparing" | "committed")),
        "Invalid installation transaction phase");
    ensure!(record["oldPending"].is_boolean() && record["createdLive"].is_boolean()
        && record["entries"].is_array(), "Invalid installation transaction state");
    for entry in record["entries"].as_array().context("Missing metadata intents")? {
        metadata_path(module_id, entry["name"].as_str().context("Missing entry name")?)?;
        ensure!(entry["existed"].is_boolean(), "Invalid metadata intent");
    }
    Ok(Some(record))
}

fn restore(directory: &Path, record: &Value) -> Result<()> {
    let module_id = record["id"].as_str().context("Missing module identity")?;
    let pending = Path::new(defs::MODULE_UPDATE_DIR).join(module_id);
    let old_pending = directory.join("pending");
    if fs::symlink_metadata(&old_pending).is_ok() {
        remove_entry(&pending)?;
        fs::rename(&old_pending, &pending)?;
        sync_dir(Path::new(defs::MODULE_UPDATE_DIR))?;
        sync_dir(directory)?;
    } else if record["oldPending"] == false {
        remove_entry(&pending)?;
        sync_dir(Path::new(defs::MODULE_UPDATE_DIR))?;
    }
    let entries = record["entries"].as_array().context("Missing metadata intents")?;
    for (index, entry) in entries.iter().enumerate().rev() {
        let path = metadata_path(module_id, entry["name"].as_str().context("Missing entry name")?)?;
        let saved = directory.join(format!("entry-{index}"));
        if fs::symlink_metadata(&saved).is_ok() {
            remove_entry(&path)?;
            fs::rename(&saved, &path)?;
        } else if entry["existed"] == false {
            remove_entry(&path)?;
        }
        sync_existing_parent(&path)?;
        sync_dir(directory)?;
    }
    if record["createdLive"] == true {
        match fs::remove_dir(Path::new(defs::MODULE_DIR).join(module_id)) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        sync_dir(Path::new(defs::MODULE_DIR))?;
    }
    Ok(())
}

fn recover(directory: &Path, module_id: &str) -> Result<()> {
    if !directory.try_exists()? { return Ok(()); }
    let record = read_record(directory, module_id)?;
    let rollback = record.as_ref().is_some_and(|record| record["phase"] != "committed");
    if rollback {
        restore(directory, record.as_ref().context("Missing recovery record")?)?;
    }
    fs::remove_dir_all(directory)?;
    sync_dir(&root())?;
    if rollback {
        let _ = writeln!(io::stderr(), "- Failed installation of {module_id} rolled back");
    }
    Ok(())
}

pub(super) fn recover_before_boot() -> Result<()> {
    let entries = match fs::read_dir(root()) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_dir() { continue; }
        let module_id = entry.file_name().to_string_lossy().into_owned();
        super::validate_module_id(&module_id)?;
        let Some(_lock) = lock(&module_id, false)? else {
            continue;
        };
        if let Err(error) = recover(&entry.path(), &module_id) {
            log::warn!("Module {module_id} installation recovery: {error:#}");
        }
    }
    Ok(())
}

pub(super) fn skip_uncommitted(path: &Path, pending: bool) -> bool {
    let Some(module_id) = path.file_name().and_then(|name| name.to_str()) else {
        return true;
    };
    match read_record(&root().join(module_id), module_id) {
        Ok(Some(record)) => record["phase"] != "committed"
            && (pending || record["createdLive"] == true),
        Ok(None) => false,
        Err(error) => {
            log::warn!("Module {module_id} installation state unreadable: {error:#}");
            true
        }
    }
}

impl InstallTransaction {
    pub(super) fn begin(module_id: &str) -> Result<Self> {
        let lock = lock(module_id, true)?.context("Missing installation lock")?;
        let directory = root().join(module_id);
        recover(&directory, module_id)?;
        let mut random = [0u8; 16];
        File::open("/dev/urandom")?.read_exact(&mut random)?;
        let generation: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let old_pending = Path::new(defs::MODULE_UPDATE_DIR).join(module_id);
        let pending_existed = match fs::symlink_metadata(&old_pending) {
            Ok(_) => true,
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => return Err(error.into()),
        };
        DirBuilder::new().mode(0o700).create(&directory)?;
        let mut transaction = Self {
            directory, _lock: lock, committed: false, commit_visible: false, record_durable: false,
            record: json!({"version":1,"id":module_id,"generation":generation,
                "phase":"preparing","oldPending":pending_existed,"createdLive":false,"entries":[]}),
        };
        transaction.persist()?;
        sync_dir(&root())?;
        transaction.record_durable = true;
        if pending_existed {
            fs::rename(&old_pending, transaction.directory.join("pending"))?;
            sync_dir(Path::new(defs::MODULE_UPDATE_DIR))?;
            sync_dir(&transaction.directory)?;
        }
        Ok(transaction)
    }

    fn persist(&mut self) -> Result<()> {
        let temporary = self.directory.join("record.tmp");
        let mut file = OpenOptions::new().write(true).create(true).truncate(true)
            .mode(0o600).custom_flags(libc::O_NOFOLLOW).open(&temporary)?;
        serde_json::to_writer(&mut file, &self.record)?;
        file.sync_all()?;
        fs::rename(temporary, self.directory.join("record"))?;
        if self.record["phase"] == "committed" {
            self.commit_visible = true;
        }
        sync_dir(&self.directory)
    }

    pub(super) fn temporary_dir(&self) -> PathBuf {
        self.directory.join("tmp")
    }

    fn save_entry(&mut self, name: &str) -> Result<()> {
        let module_id = self.record["id"].as_str().context("Missing module identity")?;
        let path = metadata_path(module_id, name)?;
        let existed = match fs::symlink_metadata(&path) {
            Ok(_) => true,
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => return Err(error.into()),
        };
        let entries = self.record["entries"].as_array_mut().context("Missing metadata intents")?;
        let index = entries.len();
        entries.push(json!({"name":name,"existed":existed}));
        self.persist()?;
        if existed {
            fs::rename(&path, self.directory.join(format!("entry-{index}")))?;
            sync_dir(path.parent().context("Missing metadata parent")?)?;
            sync_dir(&self.directory)?;
        }
        Ok(())
    }

    pub(super) fn publish_metadata(&mut self, is_metamodule: bool) -> Result<()> {
        let module_id = self.record["id"].as_str().context("Missing module identity")?.to_owned();
        let live = Path::new(defs::MODULE_DIR).join(&module_id);
        self.record["createdLive"] = match fs::symlink_metadata(&live) {
            Ok(_) => false.into(),
            Err(error) if error.kind() == io::ErrorKind::NotFound => true.into(),
            Err(error) => return Err(error.into()),
        };
        self.persist()?;
        ensure_dir_exists(&live)?;
        for name in ["module.prop", defs::UPDATE_FILE_NAME, defs::REMOVE_FILE_NAME,
            defs::DISABLE_FILE_NAME, defs::HOT_INSTALL_MARKER]
        {
            self.save_entry(name)?;
        }
        fs::copy(Path::new(defs::MODULE_UPDATE_DIR).join(&module_id).join("module.prop"),
            live.join("module.prop"))?;
        File::open(live.join("module.prop"))?.sync_all()?;
        ensure_file_exists(live.join(defs::UPDATE_FILE_NAME))?;
        if is_metamodule {
            self.save_entry("metamodule")?;
            metamodule::ensure_symlink(&live)?;
            sync_dir(Path::new(defs::ADB_DIR))?;
        }
        sync_dir(&live)?;
        sync_dir(Path::new(defs::MODULE_DIR))?;
        Ok(())
    }

    pub(super) fn commit(&mut self) -> Result<()> {
        sync_tree(&Path::new(defs::MODULE_UPDATE_DIR).join(
            self.record["id"].as_str().context("Missing module identity")?))?;
        sync_dir(Path::new(defs::MODULE_UPDATE_DIR))?;
        self.record["phase"] = "committed".into();
        self.persist()?;
        self.committed = true;
        Ok(())
    }
}

impl Drop for InstallTransaction {
    fn drop(&mut self) {
        if !self.record_durable {
            let _ = fs::remove_dir_all(&self.directory);
            return;
        }
        if self.commit_visible && !self.committed {
            let _ = writeln!(io::stderr(), "! Module commit receipt unconfirmed; retained {}", self.directory.display());
            return;
        }
        if !self.committed {
            self.record["phase"] = "preparing".into();
            let result = self.persist().and_then(|()| restore(&self.directory, &self.record));
            if let Err(error) = result {
                let _ = writeln!(io::stderr(), "! Module rollback incomplete: {error:#}; retained {}", self.directory.display());
                return;
            }
        }
        let cleanup = fs::remove_dir_all(&self.directory).map_err(anyhow::Error::from)
            .and_then(|()| sync_dir(&root()));
        match cleanup {
            Ok(()) if !self.committed => {
                let _ = writeln!(io::stderr(), "- Failed installation of {} rolled back", self.record["id"]);
            }
            Ok(()) => {}
            Err(error) => {
                let _ = writeln!(io::stderr(), "! Module transaction cleanup: {error:#}");
            }
        }
    }
}
"""


def patch_module_install_transaction(tree, _source):
    tree.replace_once('userspace/ksud/src/module.rs', '    time::Instant,\n};\nuse std::{\n    fs::{copy, rename},\n    io::Write,\n};\nuse zip_extensions::inflate::zip_extract::zip_extract_file_to_memory;\n\nuse crate::defs::{MODULE_DIR, MODULE_UPDATE_DIR, UPDATE_FILE_NAME};\nuse crate::module::ModuleType::{Active, All};\nuse std::os::unix::{prelude::PermissionsExt, process::CommandExt};\n\nconst INSTALLER_CONTENT: &str = include_str!("./installer.sh");\nconst INSTALL_MODULE_SCRIPT: &str = concatcp!(\n', '    time::Instant,\n};\nuse std::{\n    fs::rename,\n    io::Write,\n};\nuse zip_extensions::inflate::zip_extract::zip_extract_file_to_memory;\n\nuse crate::defs::{MODULE_DIR, MODULE_UPDATE_DIR};\nuse crate::module::ModuleType::{Active, All};\nuse std::os::unix::{prelude::PermissionsExt, process::CommandExt};\n\n#[path = "module_install_transaction.rs"]\nmod install_transaction;\n\nconst INSTALLER_CONTENT: &str = include_str!("./installer.sh");\nconst INSTALL_MODULE_SCRIPT: &str = concatcp!(\n')
    tree.replace_once('userspace/ksud/src/module.rs', '    envs\n}\n\nfn exec_install_script(module_file: &str, is_metamodule: bool, module_id: &str) -> Result<()> {\n    let realpath = std::fs::canonicalize(module_file)\n        .with_context(|| format!("realpath: {module_file} failed"))?;\n\n', '    envs\n}\n\nfn exec_install_script(\n    module_file: &str, is_metamodule: bool, module_id: &str, temporary_dir: &Path,\n) -> Result<()> {\n    let realpath = std::fs::canonicalize(module_file)\n        .with_context(|| format!("realpath: {module_file} failed"))?;\n\n')
    tree.replace_once('userspace/ksud/src/module.rs', '    let install_script =\n        metamodule::get_install_script(is_metamodule, INSTALLER_CONTENT, INSTALL_MODULE_SCRIPT)?;\n\n    let result = Command::new(assets::BUSYBOX_PATH)\n        .args(["sh", "-c", &install_script])\n        .envs(get_common_script_envs(Some(module_id)))\n        .env("OUTFD", "1")\n        .env("ZIPFILE", realpath)\n        .status()?;\n    ensure!(result.success(), "Failed to install module script");\n', '    let install_script =\n        metamodule::get_install_script(is_metamodule, INSTALLER_CONTENT, INSTALL_MODULE_SCRIPT)?;\n\n    let parent = std::process::id() as libc::pid_t;\n    let mut command = Command::new(assets::BUSYBOX_PATH);\n    unsafe {\n        command.pre_exec(move || {\n            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {\n                return Err(std::io::Error::last_os_error());\n            }\n            if libc::getppid() != parent {\n                return Err(std::io::Error::from_raw_os_error(libc::ECANCELED));\n            }\n            Ok(())\n        });\n    }\n    let result = command\n        .args(["sh", "-c", &install_script])\n        .envs(get_common_script_envs(Some(module_id)))\n        .env("OUTFD", "1")\n        .env("KSUD_MANAGED_INSTALL", "1")\n        .env("KSUD_INSTALL_TMPDIR", temporary_dir)\n        .env("ZIPFILE", realpath)\n        .status()?;\n    ensure!(result.success(), "Failed to install module script");\n')
    tree.replace_once('userspace/ksud/src/module.rs', '            continue;\n        }\n\n        if module_type == Active && path.join(defs::DISABLE_FILE_NAME).exists() {\n            info!("{} is disabled, skip", path.display());\n            continue;\n', '            continue;\n        }\n\n        if install_transaction::skip_uncommitted(&path, module_type == ModuleType::Updated) {\n            continue;\n        }\n        if module_type == Active && path.join(defs::DISABLE_FILE_NAME).exists() {\n            info!("{} is disabled, skip", path.display());\n            continue;\n')
    tree.replace_once('userspace/ksud/src/module.rs', '            let Some(id) = module_path.file_name().and_then(|s| s.to_str()) else {\n                continue;\n            };\n            let id = id.to_string();\n            if module_path.join(defs::DISABLE_FILE_NAME).exists()\n                || module_path.join(defs::REMOVE_FILE_NAME).exists()\n', '            let Some(id) = module_path.file_name().and_then(|s| s.to_str()) else {\n                continue;\n            };\n            if install_transaction::skip_uncommitted(\n                &module_path, src_dir == defs::MODULE_UPDATE_DIR,\n            ) {\n                continue;\n            }\n            let id = id.to_string();\n            if module_path.join(defs::DISABLE_FILE_NAME).exists()\n                || module_path.join(defs::REMOVE_FILE_NAME).exists()\n')
    tree.replace_once('userspace/ksud/src/module.rs', '    rc.and(preinit)\n}\n\npub fn handle_updated_modules() -> Result<()> {\n    let modules_root = Path::new(MODULE_DIR);\n    foreach_module(ModuleType::Updated, |updated_module| {\n        if !updated_module.is_dir() {\n', '    rc.and(preinit)\n}\n\npub(super) fn recover_module_installations() -> Result<()> {\n    install_transaction::recover_before_boot()\n}\n\npub fn handle_updated_modules() -> Result<()> {\n    recover_module_installations()?;\n    let modules_root = Path::new(MODULE_DIR);\n    foreach_module(ModuleType::Updated, |updated_module| {\n        if !updated_module.is_dir() {\n')
    tree.replace_once('userspace/ksud/src/module.rs', '    ensure_dir_exists(defs::MODULE_UPDATE_DIR)?;\n    setsyscon(defs::MODULE_UPDATE_DIR)?;\n\n    // Prepare target directory\n    println!("- Installing to {}", updated_dir.display());\n    ensure_clean_dir(&updated_dir)?;\n', '    ensure_dir_exists(defs::MODULE_UPDATE_DIR)?;\n    setsyscon(defs::MODULE_UPDATE_DIR)?;\n\n    let mut transaction = install_transaction::InstallTransaction::begin(module_id)?;\n\n    // Prepare target directory\n    println!("- Installing to {}", updated_dir.display());\n    ensure_clean_dir(&updated_dir)?;\n')
    tree.replace_once('userspace/ksud/src/module.rs', '\n    // Execute install script\n    println!("- Running module installer");\n    exec_install_script(zip, is_metamodule, module_id)?;\n\n    if let Some(request) = hot_install::take_request(&updated_dir)\n        && hot_install::apply(module_id, is_metamodule, &request)\n', '\n    // Execute install script\n    println!("- Running module installer");\n    exec_install_script(zip, is_metamodule, module_id, &transaction.temporary_dir())?;\n    transaction.publish_metadata(is_metamodule)?;\n    transaction.commit()?;\n\n    if let Some(request) = hot_install::take_request(&updated_dir)\n        && hot_install::apply(module_id, is_metamodule, &request)\n')
    tree.replace_once('userspace/ksud/src/module.rs', '        println!("- Module installed successfully, no reboot required!");\n        info!("Module {module_id} installed successfully!");\n        return Ok(module_id.to_owned());\n    }\n\n    let module_dir = Path::new(MODULE_DIR).join(module_id);\n    // A metamodule doing its own hot install may have moved the marker into the live dir\n    std::fs::remove_file(module_dir.join(defs::HOT_INSTALL_MARKER)).ok();\n    ensure_dir_exists(&module_dir)?;\n    copy(\n        updated_dir.join("module.prop"),\n        module_dir.join("module.prop"),\n    )?;\n    ensure_file_exists(module_dir.join(UPDATE_FILE_NAME))?;\n\n    // Create symlink for metamodule\n    if is_metamodule {\n        println!("- Creating metamodule symlink");\n        metamodule::ensure_symlink(&module_dir)?;\n    }\n\n    println!("- Module installed successfully!");\n', '        println!("- Module installed successfully, no reboot required!");\n        info!("Module {module_id} installed successfully!");\n        return Ok(module_id.to_owned());\n    }\n\n    println!("- Module installed successfully!");\n')
    tree.replace_once('userspace/ksud/src/module.rs', '        let path = entry.path();\n        info!("path: {}", path.display());\n\n        if !path.join("module.prop").exists() {\n            continue;\n        }\n\n', '        let path = entry.path();\n        info!("path: {}", path.display());\n\n        if install_transaction::skip_uncommitted(&path, false)\n            || !path.join("module.prop").exists()\n        {\n            continue;\n        }\n\n')
    tree.replace_once('userspace/ksud/src/installer.sh', '  handle_partition odm\n\n  if $BOOTMODE; then\n    mktouch $NVBASE/modules/$MODID/update\n    rm -rf $NVBASE/modules/$MODID/remove 2>/dev/null\n    rm -rf $NVBASE/modules/$MODID/disable 2>/dev/null\n    cp -af $MODPATH/module.prop $NVBASE/modules/$MODID/module.prop\n\n    # Tell ksud to apply the module right away\n    if [ "$MODULE_HOT_INSTALL_REQUEST" = "true" ]; then\n', '  handle_partition odm\n\n  if $BOOTMODE; then\n    if [ "$KSUD_MANAGED_INSTALL" != "1" ]; then\n      mktouch $NVBASE/modules/$MODID/update\n      rm -rf $NVBASE/modules/$MODID/remove 2>/dev/null\n      rm -rf $NVBASE/modules/$MODID/disable 2>/dev/null\n      cp -af $MODPATH/module.prop $NVBASE/modules/$MODID/module.prop\n    fi\n\n    # Tell ksud to apply the module right away\n    if [ "$MODULE_HOT_INSTALL_REQUEST" = "true" ]; then\n')
    tree.replace_once('userspace/ksud/src/installer.sh', '[ -z $BOOTMODE ] && BOOTMODE=false\n\nNVBASE=/data/adb\nTMPDIR=/dev/tmp\nPOSTFSDATAD=$NVBASE/post-fs-data.d\nSERVICED=$NVBASE/service.d\n\n', '[ -z $BOOTMODE ] && BOOTMODE=false\n\nNVBASE=/data/adb\nTMPDIR=${KSUD_INSTALL_TMPDIR:-/dev/tmp}\nPOSTFSDATAD=$NVBASE/post-fs-data.d\nSERVICED=$NVBASE/service.d\n\n')
    tree.replace_once('userspace/ksud/src/init_event.rs', '    assets::ensure_binaries(true).with_context(|| "Failed to extract bin assets")?;\n\n    crate::hot_install::clean_trash();\n\n    // if we are in safe mode, we should disable all modules\n    if safe_mode {\n', '    assets::ensure_binaries(true).with_context(|| "Failed to extract bin assets")?;\n\n    crate::hot_install::clean_trash();\n    if let Err(e) = crate::module::recover_module_installations() {\n        warn!("module installation recovery failed: {e:#}");\n    }\n\n    // if we are in safe mode, we should disable all modules\n    if safe_mode {\n')
    tree.write("userspace/ksud/src/module_install_transaction.rs", MODULE_INSTALL_TRANSACTION_RS)
    return ["userspace/ksud/src/module.rs", "userspace/ksud/src/installer.sh", "userspace/ksud/src/init_event.rs", "userspace/ksud/src/module_install_transaction.rs"]

PATCHES_MODULE_INSTALL_TRANSACTION = [{
    "name": "0026-module-install-transaction.patch",
    "apply": patch_module_install_transaction,
    "status": "implemented",
    "summary": "Restore failed module pending generations and metadata, including boot recovery before execution",
}]
