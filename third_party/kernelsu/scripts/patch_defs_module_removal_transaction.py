# SPDX-License-Identifier: GPL-3.0-or-later
"""Normal module removal intent, exact target cleanup, and callback completion."""
from __future__ import annotations

MODULE_REMOVAL_TRANSACTION_RS = r"""use crate::{defs, metamodule, utils::ensure_file_exists};
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use std::{
    collections::{BTreeSet, HashMap},
    fs::{self, File, OpenOptions},
    io::{self, Read},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

fn root() -> PathBuf {
    Path::new(defs::WORKING_DIR).join(".module-install")
}

fn intent_path(module_id: &str) -> PathBuf {
    root().join(format!(".remove-{module_id}.json"))
}

fn sync_dir(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

fn identity(path: &Path) -> Result<Option<[u64; 2]>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some([metadata.dev(), metadata.ino()])),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn valid_boot_id(value: &str) -> bool {
    value.len() == 36 && value.bytes().enumerate().all(|(index, byte)| {
        if matches!(index, 8 | 13 | 18 | 23) { byte == b'-' } else { byte.is_ascii_hexdigit() }
    })
}

fn callback_boot_id() -> Result<String> {
    let value = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let value = value.trim();
    ensure!(valid_boot_id(value), "Invalid removal callback boot identity");
    Ok(value.to_owned())
}

fn read_intent(module_id: &str) -> Result<Option<Value>> {
    let bytes = match fs::read(intent_path(module_id)) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let record: Value = serde_json::from_slice(&bytes)?;
    ensure!(record["version"] == 1 && record["id"] == module_id,
        "Invalid removal transaction identity");
    ensure!(record["generation"].as_str().is_some_and(|value|
        value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit())),
        "Invalid removal generation");
    for key in ["live", "pending"] {
        if !record[key].is_null() {
            let parts = record[key].as_array().context("Invalid removal target identity")?;
            ensure!(parts.len() == 2 && parts.iter().all(Value::is_u64),
                "Invalid removal target identity");
        }
    }
    ensure!(record["metamodule"].is_boolean(), "Invalid metamodule removal state");
    ensure!(record["properties"].as_object().is_some_and(|properties|
        properties.values().all(Value::is_string)), "Invalid removal module metadata");
    for key in ["metaCallback", "ownCallback"] {
        ensure!(matches!(record[key].as_str(), Some("pending" | "running" | "done")),
            "Invalid removal callback phase");
        for suffix in ["Boot", "InterruptedBoot"] {
            let value = &record[format!("{key}{suffix}")];
            ensure!(value.is_null() || value.as_str().is_some_and(valid_boot_id),
                "Invalid removal callback boot identity");
        }
    }
    if !record["metamoduleRemoval"].is_null() {
        let plan = &record["metamoduleRemoval"];
        ensure!(plan.as_object().is_some_and(|plan|
            plan.contains_key("before") && plan.contains_key("owner")),
            "Invalid metamodule removal intent");
        super::install_transaction::validate_metamodule_state(&plan["before"])?;
        super::install_transaction::validate_metamodule_owner(&plan["owner"])?;
    }
    Ok(Some(record))
}

fn matches_identity(record: &Value, current: Option<[u64; 2]>) -> bool {
    current.is_none() || *record == json!(current)
}

pub(super) fn is_removed(module: &Path) -> bool {
    if module.join(defs::REMOVE_FILE_NAME).exists() { return true; }
    let Some(id) = module.file_name().and_then(|name| name.to_str()) else { return false; };
    match read_intent(id) {
        Ok(Some(_)) => true,
        Ok(None) => false,
        Err(error) => {
            log::warn!("Module {id} removal state unreadable: {error:#}");
            true
        }
    }
}

pub(super) fn pending_ids() -> Result<BTreeSet<String>> {
    let mut ids = BTreeSet::new();
    let entries = match fs::read_dir(root()) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(ids),
        Err(error) => return Err(error.into()),
    };
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue; };
        let Some(id) = name.strip_prefix(".remove-").and_then(|name| name.strip_suffix(".json")) else {
            continue;
        };
        if let Err(error) = super::validate_module_id(id) {
            log::warn!("Invalid removal intent name {name}: {error:#}");
            continue;
        }
        ids.insert(id.to_owned());
    }
    Ok(ids)
}

pub(super) fn append_pending_rows(rows: &mut Vec<HashMap<String, String>>) -> Result<()> {
    for id in pending_ids()? {
        if rows.iter().any(|row| row.get("id") == Some(&id)) { continue; }
        let record = match read_intent(&id) {
            Ok(Some(record)) => record,
            Ok(None) => continue,
            Err(error) => {
                log::warn!("Module {id} pending removal metadata unavailable: {error:#}");
                continue;
            }
        };
        let current = match identity(&Path::new(defs::MODULE_DIR).join(&id)) {
            Ok(current) => current,
            Err(error) => {
                log::warn!("Module {id} pending removal target unavailable: {error:#}");
                continue;
            }
        };
        if !matches_identity(&record["live"], current) {
            continue;
        }
        let mut row: HashMap<String, String> = serde_json::from_value(record["properties"].clone())?;
        row.insert("id".into(), id);
        for (key, value) in [("remove", "true"), ("enabled", "false"), ("update", "false"),
            ("web", "false"), ("action", "false"), ("mount", "false")]
        {
            row.insert(key.into(), value.into());
        }
        rows.push(row);
    }
    Ok(())
}

pub(super) fn mark(module_id: &str) -> Result<()> {
    let mut removal = Removal::open(module_id, true)?.context("Missing removal transaction")?;
    removal.check_targets()?;
    removal.persist()?;
    let live = Path::new(defs::MODULE_DIR).join(module_id);
    let marker = live.join(defs::REMOVE_FILE_NAME);
    ensure_file_exists(&marker)?;
    File::open(marker)?.sync_all()?;
    sync_dir(&live)
}

pub(super) fn cancel(module_id: &str) -> Result<()> {
    let live = Path::new(defs::MODULE_DIR).join(module_id);
    if let Some(record) = read_intent(module_id)? {
        ensure!(matches_identity(&record["live"], identity(&live)?),
            "Removal target changed for module {module_id}");
        ensure!(record["metaCallback"] == "pending" && record["ownCallback"] == "pending",
            "Removal already started for module {module_id}: metaCallback={} ownCallback={}",
            record["metaCallback"], record["ownCallback"]);
    }
    match fs::remove_file(live.join(defs::REMOVE_FILE_NAME)) {
        Ok(()) => sync_dir(&live)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    match fs::remove_file(intent_path(module_id)) {
        Ok(()) => sync_dir(&root())?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

pub(super) struct Removal {
    record: Value,
}

impl Removal {
    pub(super) fn open(module_id: &str, create: bool) -> Result<Option<Self>> {
        if let Some(record) = read_intent(module_id)? { return Ok(Some(Self { record })); }
        let live = Path::new(defs::MODULE_DIR).join(module_id);
        if !create && !live.join(defs::REMOVE_FILE_NAME).exists() { return Ok(None); }
        let mut random = [0u8; 16];
        File::open("/dev/urandom")?.read_exact(&mut random)?;
        let generation: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let properties = super::read_module_prop(&live).unwrap_or_default();
        let mut removal = Self { record: json!({
            "version":1,"id":module_id,"generation":generation,
            "live":identity(&live)?,
            "pending":identity(&Path::new(defs::MODULE_UPDATE_DIR).join(module_id))?,
            "metamodule":metamodule::is_metamodule(&properties),
            "properties":properties,
            "metaCallback":"pending","ownCallback":"pending"
        }) };
        removal.persist()?;
        Ok(Some(removal))
    }

    fn id(&self) -> Result<&str> {
        self.record["id"].as_str().context("Missing removal module identity")
    }

    fn persist(&mut self) -> Result<()> {
        let id = self.id()?;
        if let Some(current) = read_intent(id)? {
            ensure!(current["generation"] == self.record["generation"],
                "Removal generation changed for module {id}");
        }
        let temporary = root().join(format!(".remove-{id}.tmp"));
        let mut file = OpenOptions::new().write(true).create(true).truncate(true)
            .mode(0o600).custom_flags(libc::O_NOFOLLOW).open(&temporary)?;
        serde_json::to_writer(&mut file, &self.record)?;
        file.sync_all()?;
        fs::rename(temporary, intent_path(id))?;
        sync_dir(&root())
    }

    fn check_targets(&self) -> Result<()> {
        let id = self.id()?;
        for (key, directory) in [("live", defs::MODULE_DIR), ("pending", defs::MODULE_UPDATE_DIR)] {
            ensure!(matches_identity(&self.record[key], identity(&Path::new(directory).join(id))?),
                "Removal {key} target changed for module {id}");
        }
        Ok(())
    }

    fn callback(&mut self, phase: &str, run: impl FnOnce() -> Result<()>) -> Result<()> {
        match self.record[phase].as_str() {
            Some("done") => return Ok(()),
            Some("pending" | "running") => {}
            _ => bail!("Invalid removal callback phase"),
        }
        let boot = callback_boot_id()?;
        let boot_key = format!("{phase}Boot");
        if self.record[phase] == "running" {
            if let Some(previous) = self.record[&boot_key].as_str() {
                ensure!(previous != boot,
                    "Removal callback outcome unconfirmed for module {}: {phase}", self.id()?);
                let previous = previous.to_owned();
                log::warn!("Module {} removal callback interrupted in boot {previous}: {phase}; retrying", self.id()?);
                self.record[format!("{phase}InterruptedBoot")] = previous.into();
            } else {
                // A legacy running record needs an observed boot boundary before replay.
                self.record[&boot_key] = boot.into();
                self.persist()?;
                bail!("Removal callback outcome unconfirmed for module {}: {phase}", self.id()?);
            }
        }
        self.record[phase] = "running".into();
        self.record[&boot_key] = boot.into();
        self.persist()?;
        if let Err(error) = run() {
            log::warn!("Module {} removal callback: {error:#}", self.id()?);
        }
        self.record[phase] = "done".into();
        self.persist()
    }

    pub(super) fn run_callbacks(&mut self) -> Result<()> {
        self.check_targets()?;
        let id = self.id()?.to_owned();
        let is_meta = self.record["metamodule"] == true;
        self.callback("metaCallback", || {
            if is_meta { Ok(()) } else { metamodule::exec_metauninstall_script(&id) }
        })?;
        let uninstaller = Path::new(defs::MODULE_DIR).join(&id).join("uninstall.sh");
        self.callback("ownCallback", || {
            if uninstaller.exists() {
                super::exec_script_with(uninstaller, super::ScriptWait::Forever, |command| {
                    command.env("KSUD_REMOVAL_CALLBACK_IDS", super::removal_callback_ancestry(&id));
                })
            } else { Ok(()) }
        })
    }

    fn remove_metamodule(&mut self, live: &Path) -> Result<()> {
        if self.record["metamodule"] != true { return Ok(()); }
        let guard = super::install_transaction::MetamodulePublication::lock()?;
        let current = guard.current()?;
        let owner = guard.owner()?;
        let generation = self.record["generation"].clone();
        let existing = &self.record["metamoduleRemoval"];
        if !existing.is_null() {
            if owner["generation"] == generation {
                ensure!(owner["state"].is_null(), "Metamodule removal owner changed");
                ensure!(current.is_null() || current == existing["before"],
                    "Metamodule resource changed during removal");
                return guard.unlink(&current);
            }
            if owner != existing["owner"] { return Ok(()); }
            ensure!(current == existing["before"], "Metamodule removal target changed");
        } else {
            if !current.is_null() {
                if current["kind"] != "symlink" { return Ok(()); }
                let target = Path::new(current["target"].as_str().context("Missing metamodule target")?);
                let resolved = if target.is_absolute() { target.to_path_buf() } else {
                    Path::new(defs::METAMODULE_DIR.trim_end_matches('/')).parent()
                        .context("Missing metamodule parent")?.join(target)
                };
                if resolved != live { return Ok(()); }
                ensure!(owner.is_null() || owner["state"] == current,
                    "Metamodule resource changed outside publication");
            } else if !owner["state"].is_null() {
                if owner["state"]["kind"] != "symlink" { return Ok(()); }
                let target = Path::new(owner["state"]["target"].as_str()
                    .context("Missing metamodule owner target")?);
                let resolved = if target.is_absolute() { target.to_path_buf() } else {
                    Path::new(defs::METAMODULE_DIR.trim_end_matches('/')).parent()
                        .context("Missing metamodule parent")?.join(target)
                };
                if resolved != live { return Ok(()); }
            }
            self.record["metamoduleRemoval"] = json!({"before":current,"owner":owner});
            self.persist()?;
        }
        guard.set_owner(&generation, &Value::Null)?;
        guard.unlink(&current)
    }

    pub(super) fn remove(mut self) -> Result<()> {
        self.check_targets()?;
        let id = self.id()?.to_owned();
        let live = Path::new(defs::MODULE_DIR).join(&id);
        let pending = Path::new(defs::MODULE_UPDATE_DIR).join(&id);
        match fs::remove_dir_all(&pending) {
            Ok(()) => sync_dir(Path::new(defs::MODULE_UPDATE_DIR))?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("Failed to remove pending module"),
        }
        let config_result = crate::module_config::clear_module_configs(&id).and_then(|()| {
            let directory = Path::new(defs::MODULE_CONFIG_DIR);
            match fs::metadata(directory) {
                Ok(_) => sync_dir(directory),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(error.into()),
            }
        });
        let mut first_error = config_result.err();
        if let Some(error) = &first_error {
            log::warn!("Module {id} config cleanup: {error:#}");
        }
        let meta_result = self.remove_metamodule(&live);
        if let Err(error) = meta_result {
            log::warn!("Module {id} metamodule cleanup: {error:#}");
            if first_error.is_none() { first_error = Some(error); }
        }
        let live_result = (|| -> Result<()> {
            match fs::remove_dir_all(&live) {
                Ok(()) => sync_dir(Path::new(defs::MODULE_DIR))?,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            Ok(())
        })();
        if let Err(error) = live_result {
            log::warn!("Failed to remove live module {id}: {error:#}");
            if first_error.is_none() { first_error = Some(error); }
        }
        if let Some(error) = first_error { return Err(error); }
        let current = read_intent(&id)?.context("Removal intent disappeared before completion")?;
        ensure!(current["generation"] == self.record["generation"],
            "Removal generation changed before completion for module {id}");
        fs::remove_file(intent_path(&id))?;
        sync_dir(&root())?;
        log::info!("Module {id} removed");
        Ok(())
    }
}
"""


def patch_module_removal_transaction(tree, _source):
    tree.replace_once('userspace/ksud/src/module.rs', '\n#[path = "module_install_transaction.rs"]\nmod install_transaction;\n\nconst INSTALLER_CONTENT: &str = include_str!("./installer.sh");\nconst INSTALL_MODULE_SCRIPT: &str = concatcp!(\n', '\n#[path = "module_install_transaction.rs"]\nmod install_transaction;\n#[path = "module_removal_transaction.rs"]\nmod removal_transaction;\n\nconst INSTALLER_CONTENT: &str = include_str!("./installer.sh");\nconst INSTALL_MODULE_SCRIPT: &str = concatcp!(\n')
    tree.replace_once('userspace/ksud/src/module.rs', '            info!("{} is disabled, skip", path.display());\n            continue;\n        }\n        if module_type == Active && path.join(defs::REMOVE_FILE_NAME).exists() {\n            warn!("{} is removed, skip", path.display());\n            continue;\n        }\n', '            info!("{} is disabled, skip", path.display());\n            continue;\n        }\n        if module_type == Active && removal_transaction::is_removed(&path) {\n            warn!("{} is removed, skip", path.display());\n            continue;\n        }\n')
    tree.replace_once('userspace/ksud/src/module.rs', '}\n\npub fn prune_modules() -> Result<()> {\n    foreach_module(All, |module| {\n        if !module.join(defs::REMOVE_FILE_NAME).exists() {\n            return Ok(());\n        }\n\n        info!("remove module: {}", module.display());\n\n        // Execute metamodule\'s metauninstall.sh first\n        let module_id = module.file_name().and_then(|n| n.to_str()).unwrap_or("");\n\n        // Check if this is a metamodule\n        let is_metamodule =\n            read_module_prop(module).is_ok_and(|props| metamodule::is_metamodule(&props));\n\n        if is_metamodule {\n            info!("Removing metamodule symlink");\n            if let Err(e) = metamodule::remove_symlink() {\n                warn!("Failed to remove metamodule symlink: {e}");\n            }\n        } else if let Err(e) = metamodule::exec_metauninstall_script(module_id) {\n            warn!("Failed to exec metamodule uninstall for {module_id}: {e}");\n        }\n\n        // Then execute module\'s own uninstall.sh\n        let uninstaller = module.join("uninstall.sh");\n        if uninstaller.exists()\n            && let Err(e) = exec_script(uninstaller, ScriptWait::Forever)\n        {\n            warn!("Failed to exec uninstaller: {e}");\n        }\n\n        // Clear module configs before removing module directory\n        if let Err(e) = crate::module_config::clear_module_configs(module_id) {\n            warn!("Failed to clear configs for {module_id}: {e}");\n        }\n\n        // Finally remove the module directory\n        if let Err(e) = remove_dir_all(module) {\n            warn!("Failed to remove {}: {e}", module.display());\n        }\n\n        Ok(())\n    })?;\n\n    // collect remaining modules, if none, clean up metamodule record\n    let remaining_modules: Vec<_> = std::fs::read_dir(defs::MODULE_DIR)?\n        .filter_map(std::result::Result::ok)\n        .filter(|entry| entry.path().join("module.prop").exists())\n        .collect();\n\n    if remaining_modules.is_empty() {\n        info!("no remaining modules.");\n    }\n\n    Ok(())\n}\n\n// Kernels before this UAPI only look for modules.rc under /metadata/watchdog and /metadata.\n', '}\n\npub fn prune_modules() -> Result<()> {\n    let mut ids = removal_transaction::pending_ids()?;\n    foreach_module(All, |module| {\n        if removal_transaction::is_removed(module)\n            && let Some(id) = module.file_name().and_then(|name| name.to_str())\n        {\n            ids.insert(id.to_owned());\n        }\n        Ok(())\n    })?;\n\n    let mut first_error = None;\n    for id in ids {\n        let result = (|| -> Result<()> {\n            let Some(_lock) = install_transaction::mutation_lock(&id, false)? else {\n                info!("Module {id} operation in progress, skip removal this time");\n                return Ok(());\n            };\n            let Some(mut removal) = removal_transaction::Removal::open(&id, false)? else {\n                return Ok(());\n            };\n            info!("remove module: {id}");\n            removal.run_callbacks()?;\n            removal.remove()\n        })();\n        if let Err(error) = result {\n            warn!("Failed to remove module {id}: {error:#}");\n            if first_error.is_none() { first_error = Some(error); }\n        }\n    }\n    if let Some(error) = first_error { return Err(error); }\n\n    let remaining_modules: Vec<_> = std::fs::read_dir(defs::MODULE_DIR)?\n        .filter_map(std::result::Result::ok)\n        .filter(|entry| entry.path().join("module.prop").exists())\n        .collect();\n    if remaining_modules.is_empty() { info!("no remaining modules."); }\n    Ok(())\n}\n\npub(super) fn removal_callback_ancestry(module_id: &str) -> String {\n    let mut held = std::env::var("KSUD_REMOVAL_CALLBACK_IDS").unwrap_or_default();\n    if !held.split(\':\').any(|id| id == module_id) {\n        if !held.is_empty() { held.push(\':\'); }\n        held.push_str(module_id);\n    }\n    held\n}\n\n// Kernels before this UAPI only look for modules.rc under /metadata/watchdog and /metadata.\n')
    tree.replace_once('userspace/ksud/src/module.rs', '            let id = id.to_string();\n            if module_path.join(defs::DISABLE_FILE_NAME).exists()\n                || module_path.join(defs::REMOVE_FILE_NAME).exists()\n            {\n                modules.insert(id, None);\n                continue;\n', '            let id = id.to_string();\n            if module_path.join(defs::DISABLE_FILE_NAME).exists()\n                || module_path.join(defs::REMOVE_FILE_NAME).exists()\n                || removal_transaction::is_removed(&Path::new(MODULE_DIR).join(&id))\n            {\n                modules.insert(id, None);\n                continue;\n')
    tree.replace_once('userspace/ksud/src/module.rs', 'pub fn handle_updated_modules() -> Result<()> {\n    recover_module_installations()?;\n    let modules_root = Path::new(MODULE_DIR);\n    foreach_module(ModuleType::Updated, |updated_module| {\n        if !updated_module.is_dir() {\n            return Ok(());\n        }\n\n        if let Some(name) = updated_module.file_name() {\n            let module_dir = modules_root.join(name);\n            let mut disabled = false;\n            let mut removed = false;\n            if module_dir.exists() {\n                // If the old module is disabled, we need to also disable the new one\n                disabled = module_dir.join(defs::DISABLE_FILE_NAME).exists();\n                removed = module_dir.join(defs::REMOVE_FILE_NAME).exists();\n                remove_dir_all(&module_dir)?;\n            }\n            rename(updated_module, &module_dir)?;\n            if removed {\n                let path = module_dir.join(defs::REMOVE_FILE_NAME);\n                if let Err(e) = ensure_file_exists(&path) {\n                    warn!("Failed to create {}: {e}", path.display());\n                }\n            } else if disabled {\n                let path = module_dir.join(defs::DISABLE_FILE_NAME);\n                if let Err(e) = ensure_file_exists(&path) {\n                    warn!("Failed to create {}: {e}", path.display());\n                }\n            }\n        }\n        Ok(())\n    })?;\n    Ok(())\n}\n\n', 'pub fn handle_updated_modules() -> Result<()> {\n    recover_module_installations()?;\n    let modules_root = Path::new(MODULE_DIR);\n    let mut first_error = None;\n    foreach_module(ModuleType::Updated, |updated_module| {\n        let Some(id) = updated_module.file_name().and_then(|name| name.to_str()) else {\n            return Ok(());\n        };\n        let result = (|| -> Result<()> {\n            validate_module_id(id)?;\n            let Some(_lock) = install_transaction::mutation_lock(id, false)? else {\n                info!("Module {id} operation in progress, skip update this time");\n                return Ok(());\n            };\n            let module_dir = modules_root.join(id);\n            if removal_transaction::is_removed(&module_dir) {\n                return Ok(());\n            }\n            if module_dir.join(defs::DISABLE_FILE_NAME).exists() {\n                ensure_file_exists(updated_module.join(defs::DISABLE_FILE_NAME))?;\n            }\n            if module_dir.exists() { remove_dir_all(&module_dir)?; }\n            rename(updated_module, &module_dir)?;\n            Ok(())\n        })();\n        if let Err(error) = result {\n            warn!("Failed to update module {id}: {error:#}");\n            if first_error.is_none() { first_error = Some(error); }\n        }\n        Ok(())\n    })?;\n    if let Some(error) = first_error { return Err(error); }\n    Ok(())\n}\n\n')
    tree.replace_once('userspace/ksud/src/module.rs', '\npub fn undo_uninstall_module(id: &str) -> Result<()> {\n    validate_module_id(id)?;\n\n    let module_path = Path::new(defs::MODULE_DIR).join(id);\n    ensure!(module_path.exists(), "Module {id} not found");\n\n    // Remove the remove mark\n    let remove_file = module_path.join(defs::REMOVE_FILE_NAME);\n    if remove_file.exists() {\n        std::fs::remove_file(&remove_file)\n            .with_context(|| format!("Failed to delete remove file for module \'{id}\'"))?;\n        info!("Removed the remove mark for module {id}");\n    }\n\n    if let Err(e) = regenerate_preinit() {\n        warn!("regenerate preinit failed: {e:#}");\n    }\n\n    Ok(())\n}\n\npub fn uninstall_module(id: &str) -> Result<()> {\n    validate_module_id(id)?;\n\n    let module_path = Path::new(defs::MODULE_DIR).join(id);\n    ensure!(module_path.exists(), "Module {id} not found");\n\n    // Mark for removal\n    let remove_file = module_path.join(defs::REMOVE_FILE_NAME);\n    File::create(remove_file).with_context(|| "Failed to create remove file")?;\n\n    info!("Module {id} marked for removal");\n\n    if let Err(e) = regenerate_preinit() {\n        warn!("regenerate preinit failed: {e:#}");\n    }\n\n    Ok(())\n}\n\n', '\npub fn undo_uninstall_module(id: &str) -> Result<()> {\n    validate_module_id(id)?;\n    let _lock = install_transaction::mutation_lock(id, true)?\n        .context("Missing module mutation lock")?;\n    let module_path = Path::new(defs::MODULE_DIR).join(id);\n    ensure!(module_path.exists(), "Module {id} not found");\n    removal_transaction::cancel(id)?;\n    info!("Removed the remove mark for module {id}");\n    if let Err(e) = regenerate_preinit() {\n        warn!("regenerate preinit failed: {e:#}");\n    }\n    Ok(())\n}\n\npub fn uninstall_module(id: &str) -> Result<()> {\n    validate_module_id(id)?;\n    let _lock = install_transaction::mutation_lock(id, true)?\n        .context("Missing module mutation lock")?;\n    let module_path = Path::new(defs::MODULE_DIR).join(id);\n    ensure!(module_path.exists(), "Module {id} not found");\n    removal_transaction::mark(id).context("Failed to create remove file")?;\n    info!("Module {id} marked for removal");\n    if let Err(e) = regenerate_preinit() {\n        warn!("regenerate preinit failed: {e:#}");\n    }\n    Ok(())\n}\n\n')
    tree.replace_once('userspace/ksud/src/module.rs', '        // Add enabled, update, remove, web, action flags\n        let enabled = !path.join(defs::DISABLE_FILE_NAME).exists();\n        let update = path.join(defs::UPDATE_FILE_NAME).exists();\n        let remove = path.join(defs::REMOVE_FILE_NAME).exists();\n        let web = path.join(defs::MODULE_WEB_DIR).exists();\n        let action = path.join(defs::MODULE_ACTION_SH).exists();\n        let need_mount = path.join("system").exists() && !path.join("skip_mount").exists();\n', '        // Add enabled, update, remove, web, action flags\n        let enabled = !path.join(defs::DISABLE_FILE_NAME).exists();\n        let update = path.join(defs::UPDATE_FILE_NAME).exists();\n        let remove = removal_transaction::is_removed(&path);\n        let web = path.join(defs::MODULE_WEB_DIR).exists();\n        let action = path.join(defs::MODULE_ACTION_SH).exists();\n        let need_mount = path.join("system").exists() && !path.join("skip_mount").exists();\n')
    tree.replace_once('userspace/ksud/src/module.rs', '}\n\npub fn list_modules() -> Result<()> {\n    let modules = list_module(defs::MODULE_DIR);\n    println!("{}", serde_json::to_string_pretty(&modules)?);\n    Ok(())\n}\n', '}\n\npub fn list_modules() -> Result<()> {\n    let mut modules = list_module(defs::MODULE_DIR);\n    removal_transaction::append_pending_rows(&mut modules)?;\n    println!("{}", serde_json::to_string_pretty(&modules)?);\n    Ok(())\n}\n')
    tree.replace_once('userspace/ksud/src/module_install_transaction.rs', '}\n\nfn lock(module_id: &str, wait: bool) -> Result<Option<File>> {\n    let file = OpenOptions::new().read(true).write(true).create(true).truncate(false)\n        .mode(0o600).custom_flags(libc::O_NOFOLLOW)\n        .open(private_root()?.join(format!(".lock-{module_id}")))?;\n', '}\n\nfn lock(module_id: &str, wait: bool) -> Result<Option<File>> {\n    let held = std::env::var("KSUD_REMOVAL_CALLBACK_IDS").unwrap_or_default();\n    let wait = wait && !held.split(\':\').any(|id| id == module_id);\n    let file = OpenOptions::new().read(true).write(true).create(true).truncate(false)\n        .mode(0o600).custom_flags(libc::O_NOFOLLOW)\n        .open(private_root()?.join(format!(".lock-{module_id}")))?;\n')
    tree.replace_once('userspace/ksud/src/module_install_transaction.rs', '            Ok(Path::new(defs::MODULE_DIR).join(module_id).join(name))\n        }\n        "metamodule" => Ok(PathBuf::from(defs::METAMODULE_DIR.trim_end_matches(\'/\'))),\n        _ => bail!("Invalid installation metadata entry"),\n    }\n}\n', '            Ok(Path::new(defs::MODULE_DIR).join(module_id).join(name))\n        }\n        "metamodule" => Ok(PathBuf::from(defs::METAMODULE_DIR.trim_end_matches(\'/\'))),\n        "remove-intent" => Ok(root().join(format!(".remove-{module_id}.json"))),\n        _ => bail!("Invalid installation metadata entry"),\n    }\n}\n')
    tree.replace_once('userspace/ksud/src/module_install_transaction.rs', '    Ok(())\n}\n\npub(super) fn skip_uncommitted(path: &Path, pending: bool) -> bool {\n    let Some(module_id) = path.file_name().and_then(|name| name.to_str()) else {\n        return true;\n', '    Ok(())\n}\n\npub(super) fn mutation_lock(module_id: &str, wait: bool) -> Result<Option<File>> {\n    let Some(lock) = lock(module_id, wait)? else { return Ok(None); };\n    recover(&root().join(module_id), module_id)?;\n    Ok(Some(lock))\n}\n\npub(super) fn skip_uncommitted(path: &Path, pending: bool) -> bool {\n    let Some(module_id) = path.file_name().and_then(|name| name.to_str()) else {\n        return true;\n')
    tree.replace_once('userspace/ksud/src/module_install_transaction.rs', '        self.persist()?;\n        ensure_dir_exists(&live)?;\n        for name in ["module.prop", defs::UPDATE_FILE_NAME, defs::REMOVE_FILE_NAME,\n            defs::DISABLE_FILE_NAME, defs::HOT_INSTALL_MARKER]\n        {\n            self.save_entry(name)?;\n        }\n', '        self.persist()?;\n        ensure_dir_exists(&live)?;\n        for name in ["module.prop", defs::UPDATE_FILE_NAME, defs::REMOVE_FILE_NAME,\n            defs::DISABLE_FILE_NAME, defs::HOT_INSTALL_MARKER, "remove-intent"]\n        {\n            self.save_entry(name)?;\n        }\n')
    tree.replace_once('userspace/ksud/src/metamodule.rs', '            get_metamodule_id().as_deref(),\n        ))\n        .env("MODULE_ID", module_id)\n        .status()?;\n\n    ensure!(\n', '            get_metamodule_id().as_deref(),\n        ))\n        .env("MODULE_ID", module_id)\n        .env("KSUD_REMOVAL_CALLBACK_IDS", crate::module::removal_callback_ancestry(module_id))\n        .status()?;\n\n    ensure!(\n')
    tree.replace_once("userspace/ksud/src/module_install_transaction.rs", '    };\n    match read_record(&root().join(module_id), module_id) {\n        Ok(Some(record)) => record["phase"] != "committed"\n            && (pending || record["createdLive"] == true),\n        Ok(None) => false,\n        Err(error) => {\n            log::warn!("Module {module_id} installation state unreadable: {error:#}");\n', '    };\n    match read_record(&root().join(module_id), module_id) {\n        Ok(Some(record)) => record["phase"] != "committed"\n            && (pending || record["createdLive"] == true\n                || record["entries"].as_array().is_some_and(|entries| entries.iter().any(|entry|\n                    entry["existed"] == true\n                        && matches!(entry["name"].as_str(), Some("remove" | "remove-intent"))))),\n        Ok(None) => false,\n        Err(error) => {\n            log::warn!("Module {module_id} installation state unreadable: {error:#}");\n')
    tree.replace_once('userspace/ksud/src/module.rs', 'use std::os::unix::{prelude::PermissionsExt, process::CommandExt};\n\n#[path = "module_install_transaction.rs"]\nmod install_transaction;\n#[path = "module_removal_transaction.rs"]\nmod removal_transaction;\n\nconst INSTALLER_CONTENT: &str = include_str!("./installer.sh");\n', 'use std::os::unix::{prelude::PermissionsExt, process::CommandExt};\n\n#[path = "module_install_transaction.rs"]\nmod install_transaction;\nuse install_transaction::metadata_lock;\n#[path = "module_removal_transaction.rs"]\nmod removal_transaction;\n\nconst INSTALLER_CONTENT: &str = include_str!("./installer.sh");\n')
    tree.replace_once('userspace/ksud/src/module.rs', '                return Ok(());\n            };\n            info!("remove module: {id}");\n            removal.run_callbacks()?;\n            removal.remove()\n        })();\n        if let Err(error) = result {\n            warn!("Failed to remove module {id}: {error:#}");\n', '                return Ok(());\n            };\n            info!("remove module: {id}");\n            removal.run_callbacks()?;\n            let _metadata = metadata_lock(&id)?;\n            removal.remove()\n        })();\n        if let Err(error) = result {\n            warn!("Failed to remove module {id}: {error:#}");\n')
    tree.replace_once('userspace/ksud/src/module.rs', '            let Some(_lock) = install_transaction::mutation_lock(id, false)? else {\n                info!("Module {id} operation in progress, skip update this time");\n                return Ok(());\n            };\n            let module_dir = modules_root.join(id);\n            if removal_transaction::is_removed(&module_dir) {\n                return Ok(());\n            }\n', '            let Some(_lock) = install_transaction::mutation_lock(id, false)? else {\n                info!("Module {id} operation in progress, skip update this time");\n                return Ok(());\n            };\n            let _metadata = metadata_lock(id)?;\n            let module_dir = modules_root.join(id);\n            if removal_transaction::is_removed(&module_dir) {\n                return Ok(());\n            }\n')
    tree.replace_once('userspace/ksud/src/module.rs', '}\n\npub fn undo_uninstall_module(id: &str) -> Result<()> {\n    validate_module_id(id)?;\n    let _lock = install_transaction::mutation_lock(id, true)?\n        .context("Missing module mutation lock")?;\n    let module_path = Path::new(defs::MODULE_DIR).join(id);\n    ensure!(module_path.exists(), "Module {id} not found");\n    removal_transaction::cancel(id)?;\n    info!("Removed the remove mark for module {id}");\n    if let Err(e) = regenerate_preinit() {\n        warn!("regenerate preinit failed: {e:#}");\n    }\n    Ok(())\n}\n\npub fn uninstall_module(id: &str) -> Result<()> {\n    validate_module_id(id)?;\n    let _lock = install_transaction::mutation_lock(id, true)?\n        .context("Missing module mutation lock")?;\n    let module_path = Path::new(defs::MODULE_DIR).join(id);\n    ensure!(module_path.exists(), "Module {id} not found");\n    removal_transaction::mark(id).context("Failed to create remove file")?;\n    info!("Module {id} marked for removal");\n    if let Err(e) = regenerate_preinit() {\n        warn!("regenerate preinit failed: {e:#}");\n    }\n    Ok(())\n}\n\npub fn run_action(id: &str) -> Result<()> {\n    validate_module_id(id)?;\n', '}\n\npub fn undo_uninstall_module(id: &str) -> Result<()> {\n    validate_module_id(id)?;\n    {\n        let _lock = install_transaction::mutation_lock(id, true)?\n            .context("Missing module mutation lock")?;\n        let _metadata = metadata_lock(id)?;\n        let module_path = Path::new(defs::MODULE_DIR).join(id);\n        ensure!(module_path.exists(), "Module {id} not found");\n        removal_transaction::cancel(id)?;\n    }\n    info!("Removed the remove mark for module {id}");\n    if let Err(e) = regenerate_preinit() {\n        warn!("regenerate preinit failed: {e:#}");\n    }\n    Ok(())\n}\n\npub fn uninstall_module(id: &str) -> Result<()> {\n    mark_module_for_removal(id)?;\n    info!("Module {id} marked for removal");\n    if let Err(e) = regenerate_preinit() {\n        warn!("regenerate preinit failed: {e:#}");\n    }\n    Ok(())\n}\n\nfn mark_module_for_removal(id: &str) -> Result<()> {\n    validate_module_id(id)?;\n    let _lock = install_transaction::mutation_lock(id, true)?\n        .context("Missing module mutation lock")?;\n    let _metadata = metadata_lock(id)?;\n    let module_path = Path::new(defs::MODULE_DIR).join(id);\n    ensure!(module_path.exists(), "Module {id} not found");\n    removal_transaction::mark(id).context("Failed to create remove file")\n}\n\npub fn run_action(id: &str) -> Result<()> {\n    validate_module_id(id)?;\n')
    tree.replace_once('userspace/ksud/src/module.rs', '\npub fn enable_module(id: &str) -> Result<()> {\n    validate_module_id(id)?;\n\n    let module_path = Path::new(defs::MODULE_DIR).join(id);\n    ensure!(module_path.exists(), "Module {id} not found");\n\n    let disable_path = module_path.join(defs::DISABLE_FILE_NAME);\n    if disable_path.exists() {\n        std::fs::remove_file(&disable_path).with_context(|| {\n            format!("Failed to remove disable file: {}", disable_path.display())\n        })?;\n        info!("Module {id} enabled");\n    }\n\n    if let Err(e) = regenerate_preinit() {\n        warn!("regenerate preinit failed: {e:#}");\n', '\npub fn enable_module(id: &str) -> Result<()> {\n    validate_module_id(id)?;\n\n    {\n        let _metadata = metadata_lock(id)?;\n        let module_path = Path::new(defs::MODULE_DIR).join(id);\n        ensure!(module_path.exists(), "Module {id} not found");\n\n        let disable_path = module_path.join(defs::DISABLE_FILE_NAME);\n        if disable_path.exists() {\n            std::fs::remove_file(&disable_path).with_context(|| {\n                format!("Failed to remove disable file: {}", disable_path.display())\n            })?;\n            info!("Module {id} enabled");\n        }\n    }\n\n    if let Err(e) = regenerate_preinit() {\n        warn!("regenerate preinit failed: {e:#}");\n')
    tree.replace_once('userspace/ksud/src/module.rs', '    Ok(())\n}\n\npub fn disable_module(id: &str) -> Result<()> {\n    let module_path = Path::new(defs::MODULE_DIR).join(id);\n    ensure!(module_path.exists(), "Module {id} not found");\n\n    let disable_path = module_path.join(defs::DISABLE_FILE_NAME);\n    ensure_file_exists(disable_path)?;\n\n    info!("Module {id} disabled");\n\n    if let Err(e) = regenerate_preinit() {\n', '    Ok(())\n}\n\npub fn disable_module(id: &str) -> Result<()> {\n    validate_module_id(id)?;\n    {\n        let _metadata = metadata_lock(id)?;\n        let module_path = Path::new(defs::MODULE_DIR).join(id);\n        ensure!(module_path.exists(), "Module {id} not found");\n\n        let disable_path = module_path.join(defs::DISABLE_FILE_NAME);\n        ensure_file_exists(disable_path)?;\n    }\n\n    info!("Module {id} disabled");\n\n    if let Err(e) = regenerate_preinit() {\n')
    tree.replace_once('userspace/ksud/src/module.rs', '    Ok(())\n}\n\npub fn disable_all_modules() -> Result<()> {\n    mark_all_modules(defs::DISABLE_FILE_NAME)?;\n    if let Err(e) = regenerate_preinit() {\n        warn!("regenerate preinit failed: {e:#}");\n    }\n    Ok(())\n}\n\npub fn uninstall_all_modules() -> Result<()> {\n    info!("Uninstalling all modules");\n    mark_all_modules(defs::REMOVE_FILE_NAME)?;\n    if let Err(e) = regenerate_preinit() {\n        warn!("regenerate preinit failed: {e:#}");\n    }\n    Ok(())\n}\n\nfn mark_all_modules(flag_file: &str) -> Result<()> {\n    // we assume the module dir is already mounted\n    let dir = std::fs::read_dir(defs::MODULE_DIR)?;\n    for entry in dir.flatten() {\n        let path = entry.path();\n        let flag = path.join(flag_file);\n        if let Err(e) = ensure_file_exists(flag) {\n            warn!("Failed to mark module: {}: {e}", path.display());\n        }\n    }\n\n    Ok(())\n}\n\n/// Read module.prop from the given module path and return as a HashMap\n', '    Ok(())\n}\n\npub fn disable_all_modules() -> Result<()> {\n    let result = mark_all_modules(defs::DISABLE_FILE_NAME);\n    if let Err(e) = regenerate_preinit() {\n        warn!("regenerate preinit failed: {e:#}");\n    }\n    result\n}\n\npub fn uninstall_all_modules() -> Result<()> {\n    info!("Uninstalling all modules");\n    let result = mark_all_modules(defs::REMOVE_FILE_NAME);\n    if let Err(e) = regenerate_preinit() {\n        warn!("regenerate preinit failed: {e:#}");\n    }\n    result\n}\n\nfn mark_all_modules(flag_file: &str) -> Result<()> {\n    // we assume the module dir is already mounted\n    let dir = std::fs::read_dir(defs::MODULE_DIR)?;\n    let mut first_error = None;\n    for entry in dir {\n        let result = (|| -> Result<()> {\n            let entry = entry?;\n            if !entry.file_type()?.is_dir() { return Ok(()); }\n            let name = entry.file_name();\n            let id = name.to_str().context("Invalid module directory name")?;\n            validate_module_id(id)?;\n            if flag_file == defs::REMOVE_FILE_NAME {\n                mark_module_for_removal(id)?;\n            } else {\n                let _metadata = metadata_lock(id)?;\n                let path = Path::new(defs::MODULE_DIR).join(id);\n                ensure!(path.is_dir(), "Module {id} not found");\n                ensure_file_exists(path.join(flag_file))\n                    .with_context(|| format!("Failed to mark module {id}"))?;\n            }\n            Ok(())\n        })();\n        if let Err(error) = result {\n            warn!("Failed to mark modules {flag_file}: {error:#}");\n            if first_error.is_none() { first_error = Some(error); }\n        }\n    }\n    if let Some(error) = first_error { return Err(error); }\n    Ok(())\n}\n\n/// Read module.prop from the given module path and return as a HashMap\n')
    tree.replace_once('userspace/ksud/src/module_install_transaction.rs', '};\n\npub(super) struct InstallTransaction {\n    directory: PathBuf,\n    _lock: File,\n    record: Value,\n    committed: bool,\n    commit_visible: bool,\n', '};\n\npub(super) struct InstallTransaction {\n    directory: PathBuf,\n    metadata_guard: Option<File>,\n    _lock: File,\n    record: Value,\n    committed: bool,\n    commit_visible: bool,\n')
    tree.replace_once('userspace/ksud/src/module_install_transaction.rs', '        }\n    }\n}\n\nfn metadata_path(module_id: &str, name: &str) -> Result<PathBuf> {\n    match name {\n        "module.prop" | "update" | "remove" | "disable" | ".ksu_hot_install" => {\n            Ok(Path::new(defs::MODULE_DIR).join(module_id).join(name))\n', '        }\n    }\n}\n\npub(super) fn metadata_lock(module_id: &str) -> Result<File> {\n    super::validate_module_id(module_id)?;\n    let file = OpenOptions::new().read(true).write(true).create(true).truncate(false)\n        .mode(0o600).custom_flags(libc::O_NOFOLLOW)\n        .open(private_root()?.join(format!(".metadata-lock-{module_id}")))?;\n    loop {\n        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {\n            return Ok(file);\n        }\n        let error = io::Error::last_os_error();\n        if error.kind() != io::ErrorKind::Interrupted {\n            return Err(error.into());\n        }\n    }\n}\n\nfn metadata_path(module_id: &str, name: &str) -> Result<PathBuf> {\n    match name {\n        "module.prop" | "update" | "remove" | "disable" | ".ksu_hot_install" => {\n            Ok(Path::new(defs::MODULE_DIR).join(module_id).join(name))\n')
    tree.replace_once('userspace/ksud/src/module_install_transaction.rs', '}\n\nfn recover(directory: &Path, module_id: &str) -> Result<()> {\n    if !directory.try_exists()? { return Ok(()); }\n    let record = read_record(directory, module_id)?;\n    let rollback = record.as_ref().is_some_and(|record| record["phase"] != "committed");\n    if rollback {\n        restore(directory, record.as_ref().context("Missing recovery record")?)?;\n', '}\n\nfn recover(directory: &Path, module_id: &str) -> Result<()> {\n    if !directory.try_exists()? { return Ok(()); }\n    let _metadata = metadata_lock(module_id)?;\n    let record = read_record(directory, module_id)?;\n    let rollback = record.as_ref().is_some_and(|record| record["phase"] != "committed");\n    if rollback {\n        restore(directory, record.as_ref().context("Missing recovery record")?)?;\n')
    tree.replace_once('userspace/ksud/src/module_install_transaction.rs', '            Err(error) => return Err(error.into()),\n        };\n        DirBuilder::new().mode(0o700).create(&directory)?;\n        let mut transaction = Self {\n            directory, _lock: lock, committed: false, commit_visible: false, record_durable: false,\n            record: json!({"version":1,"id":module_id,"generation":generation,\n                "phase":"preparing","oldPending":pending_existed,"createdLive":false,"entries":[]}),\n        };\n        transaction.persist()?;\n', '            Err(error) => return Err(error.into()),\n        };\n        DirBuilder::new().mode(0o700).create(&directory)?;\n        let mut transaction = Self {\n            directory, _lock: lock, metadata_guard: None,\n            committed: false, commit_visible: false, record_durable: false,\n            record: json!({"version":1,"id":module_id,"generation":generation,\n                "phase":"preparing","oldPending":pending_existed,"createdLive":false,"entries":[]}),\n        };\n        transaction.persist()?;\n')
    tree.replace_once('userspace/ksud/src/module_install_transaction.rs', '    }\n\n    pub(super) fn publish_metadata(&mut self, is_metamodule: bool) -> Result<()> {\n        let module_id = self.record["id"].as_str().context("Missing module identity")?.to_owned();\n        let live = Path::new(defs::MODULE_DIR).join(&module_id);\n        self.record["createdLive"] = match fs::symlink_metadata(&live) {\n            Ok(_) => false.into(),\n            Err(error) if error.kind() == io::ErrorKind::NotFound => true.into(),\n', '    }\n\n    pub(super) fn publish_metadata(&mut self, is_metamodule: bool) -> Result<()> {\n        let module_id = self.record["id"].as_str().context("Missing module identity")?.to_owned();\n        if self.metadata_guard.is_none() {\n            self.metadata_guard = Some(metadata_lock(&module_id)?);\n        }\n        let live = Path::new(defs::MODULE_DIR).join(&module_id);\n        self.record["createdLive"] = match fs::symlink_metadata(&live) {\n            Ok(_) => false.into(),\n            Err(error) if error.kind() == io::ErrorKind::NotFound => true.into(),\n')
    tree.replace_once('userspace/ksud/src/module_install_transaction.rs', '        sync_dir(Path::new(defs::MODULE_UPDATE_DIR))?;\n        self.record["phase"] = "committed".into();\n        self.persist()?;\n        self.committed = true;\n        Ok(())\n    }\n}\n\n', '        sync_dir(Path::new(defs::MODULE_UPDATE_DIR))?;\n        self.record["phase"] = "committed".into();\n        self.persist()?;\n        self.committed = true;\n        Ok(())\n    }\n\n    pub(super) fn take_metadata_guard(&mut self) -> Option<File> {\n        self.metadata_guard.take()\n    }\n}\n\n')
    tree.replace_once('userspace/ksud/src/module_install_transaction.rs', '            let _ = writeln!(io::stderr(), "! Module commit receipt unconfirmed; retained {}", self.directory.display());\n            return;\n        }\n        if !self.committed {\n            self.record["phase"] = "preparing".into();\n            let result = self.persist().and_then(|()| restore(&self.directory, &self.record));\n            if let Err(error) = result {\n                let _ = writeln!(io::stderr(), "! Module rollback incomplete: {error:#}; retained {}", self.directory.display());\n                return;\n            }\n', '            let _ = writeln!(io::stderr(), "! Module commit receipt unconfirmed; retained {}", self.directory.display());\n            return;\n        }\n        if !self.committed {\n            let result = (|| -> Result<()> {\n                if self.metadata_guard.is_none() {\n                    let id = self.record["id"].as_str().context("Missing module identity")?;\n                    self.metadata_guard = Some(metadata_lock(id)?);\n                }\n                self.record["phase"] = "preparing".into();\n                self.persist()?;\n                restore(&self.directory, &self.record)\n            })();\n            if let Err(error) = result {\n                let _ = writeln!(io::stderr(), "! Module rollback incomplete: {error:#}; retained {}", self.directory.display());\n                return;\n            }\n')
    tree.replace_once('userspace/ksud/src/module.rs', '    transaction.publish_metadata(is_metamodule)?;\n    transaction.commit()?;\n\n    if let Some(request) = hot_install::take_request(&updated_dir)\n        && hot_install::apply(module_id, is_metamodule, &request)\n', '    transaction.publish_metadata(is_metamodule)?;\n    transaction.commit()?;\n    let metadata_guard = transaction.take_metadata_guard();\n\n    if let Some(request) = hot_install::take_request(&updated_dir)\n        && hot_install::apply(module_id, is_metamodule, &request, metadata_guard)\n')
    tree.replace_once('userspace/ksud/src/hot_install.rs', 'pub fn apply(module_id: &str, is_metamodule: bool, request: &Request) -> bool {\n    println!("- Hot install requested");\n\n    let run_script = match check(module_id, is_metamodule, request)\n        .and_then(|script| swap(module_id).map(|()| script))\n    {', 'pub fn apply(\n    module_id: &str,\n    is_metamodule: bool,\n    request: &Request,\n    metadata_guard: Option<std::fs::File>,\n) -> bool {\n    println!("- Hot install requested");\n\n    let result = {\n        let _metadata = metadata_guard;\n        check(module_id, is_metamodule, request)\n            .and_then(|script| swap(module_id).map(|()| script))\n    };\n    let run_script = match result {')
    tree.replace_once('userspace/ksud/src/module.rs', '\n    if is_metamodule {\n        info!("Installing metamodule: {module_id}");\n\n        // Check if there\'s already a metamodule installed\n        if metamodule::has_metamodule()\n            && let Some(existing_path) = metamodule::get_metamodule_path()\n        {\n            let existing_id = read_module_prop(&existing_path)\n                .ok()\n                .and_then(|m| m.get("id").cloned())\n                .unwrap_or_else(|| "unknown".to_string());\n\n            if existing_id != module_id {\n                println!("\\n❌ Installation Failed");\n                println!("┌────────────────────────────────");\n                println!("│ A metamodule is already installed");\n                println!("│   Current metamodule: {existing_id}");\n                println!("│");\n                println!("│ Only one metamodule can be active at a time.");\n                println!("│");\n                println!("│ To install this metamodule:");\n                println!("│   1. Uninstall the current metamodule");\n                println!("│   2. Reboot your device");\n                println!("│   3. Install the new metamodule");\n                println!("└─────────────────────────────────\\n");\n                bail!("Cannot install multiple metamodules");\n            }\n        }\n    }\n\n    let zip_uncompressed_size = get_zip_uncompressed_size(zip)?;\n    info!(\n', '\n    if is_metamodule {\n        info!("Installing metamodule: {module_id}");\n\n        ensure_unique_metamodule(module_id)?;\n    }\n\n    let zip_uncompressed_size = get_zip_uncompressed_size(zip)?;\n    info!(\n')
    tree.replace_once('userspace/ksud/src/module.rs', '    println!("- Module installed successfully!");\n    info!("Module {module_id} installed successfully!");\n\n    Ok(module_id.to_owned())\n}\n\npub fn install_module(zip: &str) -> Result<()> {\n    ksucalls::ensure_uapi_version_matched()?;\n', '    println!("- Module installed successfully!");\n    info!("Module {module_id} installed successfully!");\n\n    Ok(module_id.to_owned())\n}\n\npub(super) fn duplicate_metamodule_error(existing_id: &str) -> Result<()> {\n    println!("\\n❌ Installation Failed");\n    println!("┌────────────────────────────────");\n    println!("│ A metamodule is already installed");\n    println!("│   Current metamodule: {existing_id}");\n    println!("│");\n    println!("│ Only one metamodule can be active at a time.");\n    println!("│");\n    println!("│ To install this metamodule:");\n    println!("│   1. Uninstall the current metamodule");\n    println!("│   2. Reboot your device");\n    println!("│   3. Install the new metamodule");\n    println!("└─────────────────────────────────\\n");\n    bail!("Cannot install multiple metamodules");\n}\n\npub(super) fn ensure_unique_metamodule(module_id: &str) -> Result<()> {\n    // Check if there\'s already a metamodule installed\n    if metamodule::has_metamodule()\n        && let Some(existing_path) = metamodule::get_metamodule_path()\n    {\n        let existing_id = read_module_prop(&existing_path)\n            .ok()\n            .and_then(|m| m.get("id").cloned())\n            .unwrap_or_else(|| "unknown".to_string());\n\n        if existing_id != module_id {\n            return duplicate_metamodule_error(&existing_id);\n        }\n    }\n    Ok(())\n}\n\npub fn install_module(zip: &str) -> Result<()> {\n    ksucalls::ensure_uapi_version_matched()?;\n')
    tree.replace_once('userspace/ksud/src/module_install_transaction.rs', 'use crate::{defs, metamodule, utils::{ensure_dir_exists, ensure_file_exists}};\nuse anyhow::{Context, Result, bail, ensure};\nuse serde_json::{Value, json};\nuse std::{\n    fs::{self, DirBuilder, File, OpenOptions},\n    io::{self, Read, Write},\n    os::{fd::AsRawFd, unix::fs::{DirBuilderExt, OpenOptionsExt}},\n    path::{Path, PathBuf},\n};\n\npub(super) struct InstallTransaction {\n    directory: PathBuf,\n    metadata_guard: Option<File>,\n    _lock: File,\n    record: Value,\n    committed: bool,\n', 'use crate::{defs, utils::{ensure_dir_exists, ensure_file_exists}};\nuse anyhow::{Context, Result, bail, ensure};\nuse serde_json::{Value, json};\nuse std::{\n    fs::{self, DirBuilder, File, OpenOptions},\n    io::{self, Read, Write},\n    os::{fd::AsRawFd, unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt}},\n    path::{Path, PathBuf},\n};\n\npub(super) struct InstallTransaction {\n    directory: PathBuf,\n    publication_guard: Option<MetamodulePublication>,\n    metadata_guard: Option<File>,\n    _lock: File,\n    record: Value,\n    committed: bool,\n')
    tree.replace_once('userspace/ksud/src/module_install_transaction.rs', '        }\n    }\n}\n\nfn metadata_path(module_id: &str, name: &str) -> Result<PathBuf> {\n    match name {\n        "module.prop" | "update" | "remove" | "disable" | ".ksu_hot_install" => {\n            Ok(Path::new(defs::MODULE_DIR).join(module_id).join(name))\n', '        }\n    }\n}\n\npub(super) struct MetamodulePublication {\n    _lock: File,\n}\n\nfn metamodule_path() -> &\'static Path {\n    Path::new(defs::METAMODULE_DIR.trim_end_matches(\'/\'))\n}\n\npub(super) fn validate_metamodule_state(state: &Value) -> Result<()> {\n    if state.is_null() { return Ok(()); }\n    ensure!(state["dev"].is_u64() && state["ino"].is_u64()\n        && matches!(state["kind"].as_str(), Some("symlink" | "directory")),\n        "Invalid metamodule resource identity");\n    ensure!(if state["kind"] == "symlink" { state["target"].is_string() }\n        else { state["target"].is_null() }, "Invalid metamodule resource target");\n    Ok(())\n}\n\npub(super) fn validate_metamodule_owner(owner: &Value) -> Result<()> {\n    if owner.is_null() { return Ok(()); }\n    ensure!(owner["version"] == 1 && owner["generation"].as_str().is_some_and(|value|\n        value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit())),\n        "Invalid metamodule publication owner");\n    ensure!(owner.as_object().is_some_and(|owner| owner.contains_key("state")),\n        "Missing metamodule owner state");\n    validate_metamodule_state(&owner["state"])\n}\n\nfn metamodule_state(path: &Path) -> Result<Value> {\n    let metadata = match fs::symlink_metadata(path) {\n        Ok(metadata) => metadata,\n        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Value::Null),\n        Err(error) => return Err(error.into()),\n    };\n    let (kind, target) = if metadata.file_type().is_symlink() {\n        ("symlink", Value::String(fs::read_link(path)?.into_os_string().into_string()\n            .map_err(|_| anyhow::anyhow!("Invalid metamodule link encoding"))?))\n    } else {\n        ensure!(metadata.is_dir(), "Invalid metamodule resource type");\n        ("directory", Value::Null)\n    };\n    Ok(json!({"kind":kind,"target":target,"dev":metadata.dev(),"ino":metadata.ino()}))\n}\n\nimpl MetamodulePublication {\n    pub(super) fn lock() -> Result<Self> {\n        let file = OpenOptions::new().read(true).write(true).create(true).truncate(false)\n            .mode(0o600).custom_flags(libc::O_NOFOLLOW)\n            .open(private_root()?.join(".metamodule-lock"))?;\n        loop {\n            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {\n                return Ok(Self { _lock: file });\n            }\n            let error = io::Error::last_os_error();\n            if error.kind() != io::ErrorKind::Interrupted { return Err(error.into()); }\n        }\n    }\n\n    fn ensure_available(&self, module_id: &str) -> Result<()> {\n        let current = self.current()?;\n        let owner = self.owner()?;\n        ensure!(owner.is_null() || owner["state"] == current,\n            "Metamodule resource changed outside publication");\n        if owner["state"]["kind"] == "symlink" {\n            let target = Path::new(owner["state"]["target"].as_str().context("Missing metamodule owner target")?);\n            let resolved = if target.is_absolute() { target.to_path_buf() } else {\n                metamodule_path().parent().context("Missing metamodule parent")?.join(target)\n            };\n            if resolved != Path::new(defs::MODULE_DIR).join(module_id) {\n                let existing_id = resolved.file_name().and_then(|id| id.to_str()).unwrap_or("unknown");\n                return super::duplicate_metamodule_error(existing_id);\n            }\n        }\n        super::ensure_unique_metamodule(module_id)\n    }\n\n    pub(super) fn current(&self) -> Result<Value> {\n        metamodule_state(metamodule_path())\n    }\n\n    pub(super) fn owner(&self) -> Result<Value> {\n        let file = match OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW)\n            .open(root().join(".metamodule-owner.json"))\n        {\n            Ok(file) => file,\n            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Value::Null),\n            Err(error) => return Err(error.into()),\n        };\n        let owner: Value = serde_json::from_reader(file)?;\n        validate_metamodule_owner(&owner)?;\n        Ok(owner)\n    }\n\n    pub(super) fn set_owner(&self, generation: &Value, state: &Value) -> Result<()> {\n        let owner = json!({"version":1,"generation":generation,"state":state});\n        validate_metamodule_owner(&owner)?;\n        let temporary = root().join(".metamodule-owner.tmp");\n        let mut file = OpenOptions::new().write(true).create(true).truncate(true)\n            .mode(0o600).custom_flags(libc::O_NOFOLLOW).open(&temporary)?;\n        serde_json::to_writer(&mut file, &owner)?;\n        file.sync_all()?;\n        fs::rename(temporary, root().join(".metamodule-owner.json"))?;\n        sync_dir(&root())\n    }\n\n    pub(super) fn unlink(&self, expected: &Value) -> Result<()> {\n        ensure!(self.current()? == *expected, "Metamodule resource changed before removal");\n        if !expected.is_null() { remove_entry(metamodule_path())?; }\n        sync_dir(Path::new(defs::ADB_DIR))\n    }\n}\n\nfn has_metamodule_publication(record: &Value) -> bool {\n    !record["metamodulePublication"].is_null()\n        || record["entries"].as_array().is_some_and(|entries| entries.iter().any(|entry|\n            entry["name"] == "metamodule"))\n}\n\nfn restore_metamodule(directory: &Path, record: &Value, guard: &MetamodulePublication) -> Result<()> {\n    let plan = &record["metamodulePublication"];\n    let owner = guard.owner()?;\n    if owner["generation"] != record["generation"] { return Ok(()); }\n    let current = guard.current()?;\n    let before = &plan["before"];\n    let after = &plan["after"];\n    let saved = directory.join("metamodule-backup");\n    let backup = metamodule_state(&saved)?;\n    if owner["state"] == *before {\n        ensure!(current == *before, "Restored metamodule resource changed");\n        return Ok(());\n    }\n    ensure!(owner["state"] == *after, "Metamodule publication owner changed");\n    ensure!(current.is_null() || current == *before || current == *after,\n        "Metamodule resource changed during installation rollback");\n    if current == *before {\n        ensure!(backup.is_null(), "Ambiguous metamodule rollback backup");\n    } else {\n        ensure!(backup == *before, "Metamodule rollback backup changed");\n        if !current.is_null() { guard.unlink(after)?; }\n        if !before.is_null() {\n            fs::rename(&saved, metamodule_path())?;\n            sync_dir(Path::new(defs::ADB_DIR))?;\n            sync_dir(directory)?;\n        }\n    }\n    sync_dir(Path::new(defs::ADB_DIR))?;\n    sync_dir(directory)?;\n    // Keep this generation even after restoration, so older recovery never revives it.\n    guard.set_owner(&record["generation"], before)\n}\n\nfn restore_legacy_metamodule(directory: &Path, record: &Value, index: usize,\n    entry: &Value, guard: &MetamodulePublication) -> Result<()>\n{\n    let saved = directory.join(format!("entry-{index}"));\n    let backup = metamodule_state(&saved)?;\n    let current = guard.current()?;\n    let owner = guard.owner()?;\n    if !owner.is_null() {\n        if owner["generation"] != record["generation"] { return Ok(()); }\n        if current == owner["state"] && backup.is_null() {\n            sync_dir(Path::new(defs::ADB_DIR))?;\n            return sync_dir(directory);\n        }\n        ensure!(current.is_null() && backup == owner["state"],\n            "Legacy metamodule restoration changed");\n    } else {\n        ensure!(!backup.is_null() || entry["existed"] == false,\n            "Legacy metamodule rollback target unconfirmed");\n        ensure!(current.is_null(), "Legacy metamodule publication outcome unconfirmed");\n        if backup.is_null() { guard.unlink(&Value::Null)?; }\n        guard.set_owner(&record["generation"], &backup)?;\n    }\n    if !backup.is_null() {\n        fs::rename(&saved, metamodule_path())?;\n        sync_dir(Path::new(defs::ADB_DIR))?;\n        sync_dir(directory)?;\n    }\n    Ok(())\n}\n\nfn metadata_path(module_id: &str, name: &str) -> Result<PathBuf> {\n    match name {\n        "module.prop" | "update" | "remove" | "disable" | ".ksu_hot_install" => {\n            Ok(Path::new(defs::MODULE_DIR).join(module_id).join(name))\n')
    tree.replace_once('userspace/ksud/src/module_install_transaction.rs', '    for entry in record["entries"].as_array().context("Missing metadata intents")? {\n        metadata_path(module_id, entry["name"].as_str().context("Missing entry name")?)?;\n        ensure!(entry["existed"].is_boolean(), "Invalid metadata intent");\n    }\n    Ok(Some(record))\n}\n\nfn restore(directory: &Path, record: &Value) -> Result<()> {\n    let module_id = record["id"].as_str().context("Missing module identity")?;\n    let pending = Path::new(defs::MODULE_UPDATE_DIR).join(module_id);\n    let old_pending = directory.join("pending");\n    if fs::symlink_metadata(&old_pending).is_ok() {\n', '    for entry in record["entries"].as_array().context("Missing metadata intents")? {\n        metadata_path(module_id, entry["name"].as_str().context("Missing entry name")?)?;\n        ensure!(entry["existed"].is_boolean(), "Invalid metadata intent");\n    }\n    if !record["metamodulePublication"].is_null() {\n        let plan = &record["metamodulePublication"];\n        ensure!(plan.as_object().is_some_and(|plan|\n            ["oldOwner", "before", "after"].iter().all(|key| plan.contains_key(*key))),\n            "Invalid metamodule publication intent");\n        validate_metamodule_owner(&plan["oldOwner"])?;\n        validate_metamodule_state(&plan["before"])?;\n        validate_metamodule_state(&plan["after"])?;\n        ensure!(plan["after"]["kind"] == "symlink"\n            && plan["after"]["target"].as_str().map(Path::new)\n                == Some(Path::new(defs::MODULE_DIR).join(module_id).as_path()),\n            "Invalid metamodule publication target");\n    }\n    Ok(Some(record))\n}\n\nfn restore(directory: &Path, record: &Value, publication: Option<&MetamodulePublication>) -> Result<()> {\n    let module_id = record["id"].as_str().context("Missing module identity")?;\n    let pending = Path::new(defs::MODULE_UPDATE_DIR).join(module_id);\n    let old_pending = directory.join("pending");\n    if fs::symlink_metadata(&old_pending).is_ok() {\n')
    tree.replace_once('userspace/ksud/src/module_install_transaction.rs', '    } else if record["oldPending"] == false {\n        remove_entry(&pending)?;\n        sync_dir(Path::new(defs::MODULE_UPDATE_DIR))?;\n    }\n    let entries = record["entries"].as_array().context("Missing metadata intents")?;\n    for (index, entry) in entries.iter().enumerate().rev() {\n        let path = metadata_path(module_id, entry["name"].as_str().context("Missing entry name")?)?;\n        let saved = directory.join(format!("entry-{index}"));\n        if fs::symlink_metadata(&saved).is_ok() {\n            remove_entry(&path)?;\n', '    } else if record["oldPending"] == false {\n        remove_entry(&pending)?;\n        sync_dir(Path::new(defs::MODULE_UPDATE_DIR))?;\n    }\n    if !record["metamodulePublication"].is_null() {\n        restore_metamodule(directory, record, publication.context("Missing metamodule publication guard")?)?;\n    }\n    let entries = record["entries"].as_array().context("Missing metadata intents")?;\n    for (index, entry) in entries.iter().enumerate().rev() {\n        if entry["name"] == "metamodule" {\n            restore_legacy_metamodule(directory, record, index, entry,\n                publication.context("Missing legacy metamodule publication guard")?)?;\n            continue;\n        }\n        let path = metadata_path(module_id, entry["name"].as_str().context("Missing entry name")?)?;\n        let saved = directory.join(format!("entry-{index}"));\n        if fs::symlink_metadata(&saved).is_ok() {\n            remove_entry(&path)?;\n')
    tree.replace_once('userspace/ksud/src/module_install_transaction.rs', '    let _metadata = metadata_lock(module_id)?;\n    let record = read_record(directory, module_id)?;\n    let rollback = record.as_ref().is_some_and(|record| record["phase"] != "committed");\n    if rollback {\n        restore(directory, record.as_ref().context("Missing recovery record")?)?;\n    }\n    fs::remove_dir_all(directory)?;\n    sync_dir(&root())?;\n    if rollback {\n', '    let _metadata = metadata_lock(module_id)?;\n    let record = read_record(directory, module_id)?;\n    let rollback = record.as_ref().is_some_and(|record| record["phase"] != "committed");\n    if rollback {\n        let record = record.as_ref().context("Missing recovery record")?;\n        let publication = if has_metamodule_publication(record) {\n            Some(MetamodulePublication::lock()?)\n        } else { None };\n        restore(directory, record, publication.as_ref())?;\n    }\n    fs::remove_dir_all(directory)?;\n    sync_dir(&root())?;\n    if rollback {\n')
    tree.replace_once('userspace/ksud/src/module_install_transaction.rs', '            Err(error) => return Err(error.into()),\n        };\n        DirBuilder::new().mode(0o700).create(&directory)?;\n        let mut transaction = Self {\n            directory, _lock: lock, metadata_guard: None,\n            committed: false, commit_visible: false, record_durable: false,\n            record: json!({"version":1,"id":module_id,"generation":generation,\n                "phase":"preparing","oldPending":pending_existed,"createdLive":false,"entries":[]}),\n        };\n', '            Err(error) => return Err(error.into()),\n        };\n        DirBuilder::new().mode(0o700).create(&directory)?;\n        let mut transaction = Self {\n            directory, _lock: lock, publication_guard: None, metadata_guard: None,\n            committed: false, commit_visible: false, record_durable: false,\n            record: json!({"version":1,"id":module_id,"generation":generation,\n                "phase":"preparing","oldPending":pending_existed,"createdLive":false,"entries":[]}),\n        };\n')
    tree.replace_once('userspace/ksud/src/module_install_transaction.rs', '        let module_id = self.record["id"].as_str().context("Missing module identity")?.to_owned();\n        if self.metadata_guard.is_none() {\n            self.metadata_guard = Some(metadata_lock(&module_id)?);\n        }\n        let live = Path::new(defs::MODULE_DIR).join(&module_id);\n        self.record["createdLive"] = match fs::symlink_metadata(&live) {\n            Ok(_) => false.into(),\n            Err(error) if error.kind() == io::ErrorKind::NotFound => true.into(),\n', '        let module_id = self.record["id"].as_str().context("Missing module identity")?.to_owned();\n        if self.metadata_guard.is_none() {\n            self.metadata_guard = Some(metadata_lock(&module_id)?);\n        }\n        if is_metamodule {\n            sync_tree(&Path::new(defs::MODULE_UPDATE_DIR).join(&module_id))?;\n            sync_dir(Path::new(defs::MODULE_UPDATE_DIR))?;\n            self.publication_guard = Some(MetamodulePublication::lock()?);\n            self.publication_guard.as_ref().context("Missing metamodule publication guard")?\n                .ensure_available(&module_id)?;\n        }\n        let live = Path::new(defs::MODULE_DIR).join(&module_id);\n        self.record["createdLive"] = match fs::symlink_metadata(&live) {\n            Ok(_) => false.into(),\n            Err(error) if error.kind() == io::ErrorKind::NotFound => true.into(),\n')
    tree.replace_once('userspace/ksud/src/module_install_transaction.rs', '            live.join("module.prop"))?;\n        File::open(live.join("module.prop"))?.sync_all()?;\n        ensure_file_exists(live.join(defs::UPDATE_FILE_NAME))?;\n        if is_metamodule {\n            self.save_entry("metamodule")?;\n            metamodule::ensure_symlink(&live)?;\n            sync_dir(Path::new(defs::ADB_DIR))?;\n        }\n        sync_dir(&live)?;\n        sync_dir(Path::new(defs::MODULE_DIR))?;\n        Ok(())\n    }\n\n    pub(super) fn commit(&mut self) -> Result<()> {\n        sync_tree(&Path::new(defs::MODULE_UPDATE_DIR).join(\n            self.record["id"].as_str().context("Missing module identity")?))?;\n        sync_dir(Path::new(defs::MODULE_UPDATE_DIR))?;\n        self.record["phase"] = "committed".into();\n        self.persist()?;\n        self.committed = true;\n        Ok(())\n    }\n\n    pub(super) fn take_metadata_guard(&mut self) -> Option<File> {\n', '            live.join("module.prop"))?;\n        File::open(live.join("module.prop"))?.sync_all()?;\n        ensure_file_exists(live.join(defs::UPDATE_FILE_NAME))?;\n        if is_metamodule {\n            let guard = self.publication_guard.as_ref().context("Missing metamodule publication guard")?;\n            let before = guard.current()?;\n            let old_owner = guard.owner()?;\n            ensure!(old_owner.is_null() || old_owner["state"] == before,\n                "Metamodule resource changed outside publication");\n            let prepared = self.directory.join("metamodule-published");\n            std::os::unix::fs::symlink(&live, &prepared)?;\n            sync_dir(&self.directory)?;\n            let after = metamodule_state(&prepared)?;\n            self.record["metamodulePublication"] = json!({\n                "oldOwner":old_owner,"before":before,"after":after});\n            self.persist()?;\n            let guard = self.publication_guard.as_ref().context("Missing metamodule publication guard")?;\n            guard.set_owner(&self.record["generation"], &after)?;\n            ensure!(guard.current()? == before, "Metamodule resource changed before publication");\n            if !before.is_null() {\n                fs::rename(metamodule_path(), self.directory.join("metamodule-backup"))?;\n                sync_dir(Path::new(defs::ADB_DIR))?;\n                sync_dir(&self.directory)?;\n            }\n            fs::rename(&prepared, metamodule_path())?;\n            sync_dir(Path::new(defs::ADB_DIR))?;\n            sync_dir(&self.directory)?;\n        }\n        sync_dir(&live)?;\n        sync_dir(Path::new(defs::MODULE_DIR))?;\n        Ok(())\n    }\n\n    pub(super) fn commit(&mut self) -> Result<()> {\n        if self.publication_guard.is_none() {\n            sync_tree(&Path::new(defs::MODULE_UPDATE_DIR).join(\n                self.record["id"].as_str().context("Missing module identity")?))?;\n            sync_dir(Path::new(defs::MODULE_UPDATE_DIR))?;\n        }\n        self.record["phase"] = "committed".into();\n        self.persist()?;\n        self.committed = true;\n        drop(self.publication_guard.take());\n        Ok(())\n    }\n\n    pub(super) fn take_metadata_guard(&mut self) -> Option<File> {\n')
    tree.replace_once('userspace/ksud/src/module_install_transaction.rs', '                if self.metadata_guard.is_none() {\n                    let id = self.record["id"].as_str().context("Missing module identity")?;\n                    self.metadata_guard = Some(metadata_lock(id)?);\n                }\n                self.record["phase"] = "preparing".into();\n                self.persist()?;\n                restore(&self.directory, &self.record)\n            })();\n            if let Err(error) = result {\n                let _ = writeln!(io::stderr(), "! Module rollback incomplete: {error:#}; retained {}", self.directory.display());\n                return;\n', '                if self.metadata_guard.is_none() {\n                    let id = self.record["id"].as_str().context("Missing module identity")?;\n                    self.metadata_guard = Some(metadata_lock(id)?);\n                }\n                if has_metamodule_publication(&self.record) && self.publication_guard.is_none() {\n                    self.publication_guard = Some(MetamodulePublication::lock()?);\n                }\n                self.record["phase"] = "preparing".into();\n                self.persist()?;\n                restore(&self.directory, &self.record, self.publication_guard.as_ref())\n            })();\n            if let Err(error) = result {\n                let _ = writeln!(io::stderr(), "! Module rollback incomplete: {error:#}; retained {}", self.directory.display());\n                return;\n')
    tree.write("userspace/ksud/src/module_removal_transaction.rs", MODULE_REMOVAL_TRANSACTION_RS)
    # Only ksud's actual live-directory mutation produces this per-invocation event.
    # Keep the marker out of module script environments and preserve rename errors.
    tree.replace_once('userspace/ksud/src/hot_install.rs',
        'fn swap(module_id: &str) -> Result<()> {\n',
        '''fn notify_live_change(module_id: &str) {
    use std::io::Write;
    let Ok(nonce) = std::env::var("KSUD_MODULE_LIVE_EVENT") else { return; };
    if nonce.len() != 32 || !nonce.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return;
    }
    let _ = writeln!(std::io::stderr(), "__MAPLESU_MODULE_LIVE_V1__{nonce}:{module_id}");
}

fn swap(module_id: &str) -> Result<()> {
''')
    tree.replace_once('userspace/ksud/src/hot_install.rs',
        '            warn!("Failed to restore {}: {e}", live_dir.display());\n',
        '            warn!("Failed to restore {}: {e}", live_dir.display());\n'
        '            notify_live_change(module_id);\n')
    tree.replace_once('userspace/ksud/src/hot_install.rs',
        '        return Err(e).with_context(|| format!("Failed to move {}", staged_dir.display()));\n'
        '    }\n    Ok(())\n}\n',
        '        return Err(e).with_context(|| format!("Failed to move {}", staged_dir.display()));\n'
        '    }\n    notify_live_change(module_id);\n    Ok(())\n}\n')
    tree.replace_once('userspace/ksud/src/hot_install.rs',
        '                command.stdin(Stdio::null());\n',
        '                command.env_remove("KSUD_MODULE_LIVE_EVENT").stdin(Stdio::null());\n')
    tree.replace_once('userspace/ksud/src/module.rs',
        '        .env("KSUD_MANAGED_INSTALL", "1")\n',
        '        .env("KSUD_MANAGED_INSTALL", "1")\n'
        '        .env_remove("KSUD_MODULE_LIVE_EVENT")\n')
    return ["userspace/ksud/src/module.rs", "userspace/ksud/src/module_install_transaction.rs", "userspace/ksud/src/metamodule.rs", "userspace/ksud/src/module_removal_transaction.rs", "userspace/ksud/src/hot_install.rs"]

PATCHES_MODULE_REMOVAL_TRANSACTION = [{
    "name": "0027-module-removal-transaction.patch",
    "apply": patch_module_removal_transaction,
    "status": "implemented",
    "summary": "Persist exact module removal intent, clean pending and live generations, and retain unfinished cleanup",
}]
