//! Root-only KSU authorization operations for the independent recovery WebUI.
use anyhow::{Result, anyhow, ensure};
use serde_json::json;
use crate::webadmin::Backend;

#[derive(Debug, clap::Subcommand)]
pub enum Operation {
    Snapshot,
    Set {
        package: String,
        uid: u32,
        #[arg(action = clap::ArgAction::Set)]
        allow: bool,
    },
    Log,
    ClearLog,
    SetLogging {
        #[arg(action = clap::ArgAction::Set)]
        enabled: bool,
    },
}

pub fn run(operation: Operation) -> Result<()> {
    ensure!(unsafe { libc::getuid() == 0 && libc::geteuid() == 0 }, "NOT_ROOT");
    let backend = crate::webadmin_ksud::KsudBackend;
    let feature = crate::feature_id::FeatureId::Sulog as u32;
    let value = match operation {
        Operation::Snapshot => {
            let uids = crate::ksucalls::allow_list_uids_checked()?;
            let logging = crate::ksucalls::get_feature(feature)?;
            json!({"ok": true, "uids": uids, "loggingEnabled": logging.supported && logging.value != 0})
        }
        Operation::Set { package, uid, allow } => {
            ensure!(!package.is_empty() && package.len() <= 255, "PACKAGE_INVALID");
            let before = backend.app_profile(&package, uid).map_err(|error| anyhow!(error))?;
            let old = before["allowSu"].as_bool().ok_or_else(|| anyhow!("READ_FAILED"))?;
            backend.set_app_root(&package, uid, allow).map_err(|error| anyhow!(error))?;
            let after = backend.app_profile(&package, uid).map_err(|error| anyhow!(error))?;
            ensure!(after["allowSu"].as_bool() == Some(allow), "READBACK_FAILED");
            json!({"ok": true, "allowed": allow, "changed": old != allow})
        }
        Operation::Log => backend.sulog(4096, ""),
        Operation::ClearLog => {
            backend.clear_sulog().map_err(|error| anyhow!(error))?;
            json!({"ok": true, "cleared": true})
        }
        Operation::SetLogging { enabled } => {
            backend.set_sulog_enabled(enabled).map_err(|error| anyhow!(error))?;
            let after = crate::ksucalls::get_feature(feature)?;
            ensure!(after.supported && (after.value != 0) == enabled, "READBACK_FAILED");
            crate::feature::save_config()?;
            json!({"ok": true, "enabled": enabled})
        }
    };
    println!("MAPLESU_NORMAL_SU_V1 {value}");
    Ok(())
}
