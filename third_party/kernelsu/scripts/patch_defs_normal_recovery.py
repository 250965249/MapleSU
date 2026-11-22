#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Fixed Normal-mode recovery helper and its pure host tests (0015)."""
from __future__ import annotations

NORMAL_RECOVERY_RS = r"""//! Fixed root-only recovery boundary for Normal mode; no paths or arbitrary commands.

#[derive(Clone, Copy, Debug)]
#[cfg_attr(target_os = "android", derive(clap::ValueEnum))]
pub enum Operation {
    Readiness,
    State,
    On,
    Off,
}

impl Operation {
    const fn name(self) -> &'static str {
        match self {
            Self::Readiness => "readiness",
            Self::State => "state",
            Self::On => "on",
            Self::Off => "off",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    NotRoot,
    ReadFailed,
    WriteFailed,
    ReadbackFailed,
    StateMismatch,
}

impl Failure {
    const fn code(self) -> &'static str {
        match self {
            Self::NotRoot => "NOT_ROOT",
            Self::ReadFailed => "READ_FAILED",
            Self::WriteFailed => "WRITE_FAILED",
            Self::ReadbackFailed => "READBACK_FAILED",
            Self::StateMismatch => "STATE_MISMATCH",
        }
    }
}

pub trait StealthPort {
    type Error;
    fn read(&mut self) -> Result<bool, Self::Error>;
    fn write(&mut self, enabled: bool) -> Result<(), Self::Error>;
}

pub fn execute(
    operation: Operation,
    is_root: bool,
    port: &mut impl StealthPort,
) -> Result<bool, Failure> {
    if !is_root {
        return Err(Failure::NotRoot);
    }
    match operation {
        Operation::State => port.read().map_err(|_| Failure::ReadFailed),
        Operation::On => set_and_verify(true, port),
        Operation::Off => set_and_verify(false, port),
        Operation::Readiness => {
            let current = port.read().map_err(|_| Failure::ReadFailed)?;
            set_and_verify(current, port)
        }
    }
}

fn set_and_verify(enabled: bool, port: &mut impl StealthPort) -> Result<bool, Failure> {
    port.write(enabled).map_err(|_| Failure::WriteFailed)?;
    let actual = port.read().map_err(|_| Failure::ReadbackFailed)?;
    if actual != enabled {
        return Err(Failure::StateMismatch);
    }
    Ok(actual)
}

pub fn receipt(operation: Operation, result: Result<bool, Failure>) -> String {
    let outcome = match result {
        Ok(enabled) => format!("stealth={}", u8::from(enabled)),
        Err(error) => format!("error={}", error.code()),
    };
    format!(
        "MAPLESU_NORMAL_RECOVERY_V1 operation={} {outcome}",
        operation.name()
    )
}

#[cfg(target_os = "android")]
pub fn run(operation: Operation) -> anyhow::Result<()> {
    struct KernelStealth;
    impl StealthPort for KernelStealth {
        type Error = anyhow::Error;
        fn read(&mut self) -> Result<bool, Self::Error> {
            crate::ksucalls::stealth_probe_get()
        }
        fn write(&mut self, enabled: bool) -> Result<(), Self::Error> {
            crate::ksucalls::stealth_probe_set(enabled)
        }
    }

    let is_root = unsafe { libc::getuid() == 0 && libc::geteuid() == 0 };
    let result = execute(operation, is_root, &mut KernelStealth);
    println!("{}", receipt(operation, result));
    result
        .map(|_| ())
        .map_err(|error| anyhow::anyhow!(error.code()))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Port {
        state: bool,
        writes: usize,
    }
    impl StealthPort for Port {
        type Error = ();
        fn read(&mut self) -> Result<bool, Self::Error> {
            Ok(self.state)
        }
        fn write(&mut self, value: bool) -> Result<(), Self::Error> {
            self.state = value;
            self.writes += 1;
            Ok(())
        }
    }

    #[test]
    fn state_is_read_only_and_has_a_fixed_receipt() {
        let mut port = Port {
            state: true,
            writes: 0,
        };
        let result = execute(Operation::State, true, &mut port);
        assert_eq!(result, Ok(true));
        assert_eq!(port.writes, 0);
        assert_eq!(
            receipt(Operation::State, result),
            "MAPLESU_NORMAL_RECOVERY_V1 operation=state stealth=1"
        );
    }
    #[test]
    fn readiness_proves_same_value_write_and_readback_without_toggling() {
        for enabled in [false, true] {
            let mut port = Port {
                state: enabled,
                writes: 0,
            };
            assert_eq!(execute(Operation::Readiness, true, &mut port), Ok(enabled));
            assert_eq!(port.state, enabled);
            assert_eq!(port.writes, 1);
        }
    }

    #[test]
    fn on_and_off_confirm_the_requested_kernel_state() {
        let mut port = Port {
            state: false,
            writes: 0,
        };
        assert_eq!(execute(Operation::On, true, &mut port), Ok(true));
        assert_eq!(execute(Operation::Off, true, &mut port), Ok(false));
        assert_eq!(port.writes, 2);
        assert_eq!(
            receipt(Operation::Off, Ok(false)),
            "MAPLESU_NORMAL_RECOVERY_V1 operation=off stealth=0"
        );
    }

    struct FaultPort {
        reads: usize,
        writes: usize,
        fail_read_at: Option<usize>,
        fail_write: bool,
        state: bool,
        ignore_write: bool,
    }
    impl FaultPort {
        fn new() -> Self {
            Self {
                reads: 0,
                writes: 0,
                fail_read_at: None,
                fail_write: false,
                state: false,
                ignore_write: false,
            }
        }
    }
    impl StealthPort for FaultPort {
        type Error = ();
        fn read(&mut self) -> Result<bool, Self::Error> {
            self.reads += 1;
            if self.fail_read_at == Some(self.reads) {
                return Err(());
            }
            Ok(self.state)
        }
        fn write(&mut self, enabled: bool) -> Result<(), Self::Error> {
            self.writes += 1;
            if self.fail_write {
                return Err(());
            }
            if !self.ignore_write {
                self.state = enabled;
            }
            Ok(())
        }
    }

    #[test]
    fn non_root_has_no_kernel_side_effects() {
        for operation in [
            Operation::Readiness,
            Operation::State,
            Operation::On,
            Operation::Off,
        ] {
            let mut port = FaultPort::new();
            assert_eq!(execute(operation, false, &mut port), Err(Failure::NotRoot));
            assert_eq!((port.reads, port.writes), (0, 0));
        }
    }

    #[test]
    fn readiness_read_failure_does_not_write() {
        let mut port = FaultPort::new();
        port.fail_read_at = Some(1);
        assert_eq!(
            execute(Operation::Readiness, true, &mut port),
            Err(Failure::ReadFailed)
        );
        assert_eq!(port.writes, 0);
    }

    #[test]
    fn write_failure_is_not_success_and_has_a_fixed_error_receipt() {
        let mut port = FaultPort::new();
        port.fail_write = true;
        let result = execute(Operation::On, true, &mut port);
        assert_eq!(result, Err(Failure::WriteFailed));
        assert_eq!(port.reads, 0);
        assert_eq!(
            receipt(Operation::On, result),
            "MAPLESU_NORMAL_RECOVERY_V1 operation=on error=WRITE_FAILED"
        );
    }

    #[test]
    fn readiness_readback_failure_is_not_success() {
        let mut port = FaultPort::new();
        port.fail_read_at = Some(2);
        assert_eq!(
            execute(Operation::Readiness, true, &mut port),
            Err(Failure::ReadbackFailed)
        );
        assert_eq!(port.writes, 1);
    }

    #[test]
    fn on_rejects_write_that_did_not_change_kernel_state() {
        let mut port = FaultPort::new();
        port.ignore_write = true;
        assert_eq!(
            execute(Operation::On, true, &mut port),
            Err(Failure::StateMismatch)
        );
    }

    #[test]
    fn off_rejects_write_that_did_not_change_kernel_state() {
        let mut port = FaultPort::new();
        port.state = true;
        port.ignore_write = true;
        assert_eq!(
            execute(Operation::Off, true, &mut port),
            Err(Failure::StateMismatch)
        );
    }
}
"""


NORMAL_SUPERUSER_RS = r"""//! Root-only KSU authorization operations for the independent recovery WebUI.
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
"""


def patch_0015(tree, _s7k) -> list[str]:
    root = "userspace/ksud/src/"
    tree.insert_after(root + "su.rs", "    crate::ksucalls::grant_root()?;\n",
                      "    // Manager children must survive its force-stop and package removal.\n"
                      "    utils::switch_cgroups();\n")
    tree.write(root + "normal_recovery.rs", NORMAL_RECOVERY_RS)
    tree.write(root + "normal_superuser.rs", NORMAL_SUPERUSER_RS)
    tree.insert_after(root + "main.rs", "mod feature_id;\n",
                      '#[cfg(any(target_os = "android", test))]\nmod normal_recovery;\n')
    tree.insert_after(root + "main.rs", "mod normal_recovery;\n",
                      '#[cfg(target_os = "android")]\nmod normal_superuser;\n')
    tree.insert_before(root + "cli.rs", "    /// Trigger `post-fs-data` event\n    PostFsData,",
                       "    /// Fixed root-only Normal mode recovery operations\n"
                       "    #[command(hide = true)]\n"
                       "    NormalRecovery {\n"
                       "        #[arg(value_enum)]\n"
                       "        operation: crate::normal_recovery::Operation,\n"
                       "    },\n\n")
    tree.insert_before(root + "cli.rs", "    /// Trigger `post-fs-data` event\n    PostFsData,",
                       "    /// Fixed root-only Normal authorization operations\n"
                       "    #[command(hide = true)]\n"
                       "    NormalSuperuser {\n"
                       "        #[command(subcommand)]\n"
                       "        operation: crate::normal_superuser::Operation,\n"
                       "    },\n\n")
    tree.insert_before(root + "cli.rs", "        Commands::PostFsData => init_event::on_post_fs_data(),",
                       "        Commands::NormalRecovery { operation } => crate::normal_recovery::run(operation),\n")
    tree.insert_before(root + "cli.rs", "        Commands::PostFsData => init_event::on_post_fs_data(),",
                       "        Commands::NormalSuperuser { operation } => crate::normal_superuser::run(operation),\n")
    # Recovery has no installed Manager after true removal; its existing root daemon owns policy.
    for handler, old, new in (("do_get_app_profile", "only_manager", "manager_or_root"),
                              ("do_set_app_profile", "only_manager_authed", "manager_or_root_authed")):
        tree.replace_once("kernel/supercall/dispatch.c", f"        .handler = {handler},\n        .perm_check = {old}\n",
                          f"        .handler = {handler},\n        .perm_check = {new}\n")
    tree.insert_after(root + "ksucalls.rs", '    anyhow::ensure!(input.len() <= MANAGER_IOCTL_MAX, "入参结构体太大");\n', r'''    if unsafe { libc::getuid() == 0 && libc::geteuid() == 0 } {
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
''')
    # Preserve errno for missing profiles and the older-kernel manager fallback.
    tree.replace_once(root + "ksucalls.rs",
                      'bail!("ksuctl failed: {}", io::Error::last_os_error())',
                      'return Err(anyhow::Error::new(io::Error::last_os_error()).context("ksuctl failed"));')
    calls = tree.read(root + "ksucalls.rs")
    start = calls.index("fn list_uids(allow: bool) -> Vec<u32> {")
    end = calls.index('/// 读"管理器 App 的 appid"', start)
    old_list = calls[start:end]
    checked = old_list.replace("fn list_uids(allow: bool) -> Vec<u32>", "fn list_uids_checked(allow: bool) -> anyhow::Result<Vec<u32>>")
    checked = checked.replace("    if ksuctl(req, &raw mut probe).is_err() {\n        return Vec::new();\n    }", "    ksuctl(req, &raw mut probe)?;")
    checked = checked.replace("    if ksuctl(req, cmd).is_err() {\n        return Vec::new();\n    }", "    ksuctl(req, cmd)?;")
    checked = checked.replace("return Vec::new();", "return Ok(Vec::new());")
    checked = checked.replace("    unsafe { std::slice::from_raw_parts(ptr, n) }.to_vec()", "    Ok(unsafe { std::slice::from_raw_parts(ptr, n) }.to_vec())")
    wrapper = "fn list_uids(allow: bool) -> Vec<u32> {\n    list_uids_checked(allow).unwrap_or_default()\n}\n\n" \
              "pub fn allow_list_uids_checked() -> anyhow::Result<Vec<u32>> {\n    list_uids_checked(true)\n}\n\n"
    tree.replace_once(root + "ksucalls.rs", old_list, wrapper + checked)
    return [root + file for file in ("normal_recovery.rs", "normal_superuser.rs", "cli.rs", "main.rs", "su.rs", "ksucalls.rs")] + ["kernel/supercall/dispatch.c"]


PATCHES_NORMAL_RECOVERY = [{
    "name": "0015-normal-recovery.patch",
    "summary": "Normal recovery root-only fixed CLI with kernel state and UID authorization readback",
    "apply": patch_0015,
    "status": "implemented",
    "checks": [
        ("userspace/ksud/src/normal_recovery.rs", ["MAPLESU_NORMAL_RECOVERY_V1", "stealth_probe_get", "stealth_probe_set", "STATE_MISMATCH"]),
        ("userspace/ksud/src/cli.rs", ["NormalRecovery", "crate::normal_recovery::run(operation)"]),
        ("userspace/ksud/src/normal_superuser.rs", ["MAPLESU_NORMAL_SU_V1", "allow_list_uids_checked", "READBACK_FAILED"]),
        ("kernel/supercall/dispatch.c", [".handler = do_set_app_profile,\n        .perm_check = manager_or_root_authed"]),
        ("userspace/ksud/src/su.rs", ["crate::ksucalls::grant_root()?;\n    // Manager children must survive its force-stop and package removal.\n    utils::switch_cgroups();"]),
    ],
    "compile_verified": True,
    "compile_note": "9 pure host Rust tests; Android ARM64 release build via build_userland.sh --kmi all, NDK 26.1.10909125, Rust 1.94.0; evidence .analysis/normal-recovery-cli-20261101/android-build.log.",
}]
