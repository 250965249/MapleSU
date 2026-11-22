use std::ffi::CString;
use std::io::{ErrorKind, Write};

use anyhow::{Context, Result};
use rustix::fs::{Mode, symlink, unlink};
use rustix::{
    fd::AsFd,
    fs::{Access, CWD, FileType, access, makedev, mkdir, mknodat},
    mount::{
        FsMountFlags, FsOpenFlags, MountAttrFlags, MoveMountFlags, UnmountFlags, fsconfig_create,
        fsmount, fsopen, move_mount, unmount,
    },
};

struct AutoUmount {
    mountpoints: Vec<String>,
}

impl Drop for AutoUmount {
    fn drop(&mut self) {
        for mountpoint in self.mountpoints.iter().rev() {
            if let Err(e) = unmount(mountpoint.as_str(), UnmountFlags::DETACH) {
                log::error!("Cannot umount {}: {}", mountpoint, e)
            }
        }
    }
}

fn mount_filesystem(name: &str, mountpoint: &str) -> Result<()> {
    mkdir(mountpoint, Mode::from_raw_mode(0o755)).or_else(|err| match err.kind() {
        ErrorKind::AlreadyExists => Ok(()),
        _ => Err(err),
    })?;
    let fs_fd = fsopen(name, FsOpenFlags::FSOPEN_CLOEXEC)?;
    fsconfig_create(fs_fd.as_fd())?;
    let mount_fd = fsmount(
        fs_fd.as_fd(),
        FsMountFlags::FSMOUNT_CLOEXEC,
        MountAttrFlags::empty(),
    )?;
    move_mount(
        mount_fd.as_fd(),
        "",
        CWD,
        mountpoint,
        MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
    )?;
    Ok(())
}

fn prepare_mount() -> AutoUmount {
    let mut mountpoints = vec![];

    // mount procfs
    match mount_filesystem("proc", "/proc") {
        Ok(_) => mountpoints.push("/proc".to_string()),
        Err(e) => log::error!("Cannot mount procfs: {:?}", e),
    }

    AutoUmount { mountpoints }
}

fn setup_kmsg() {
    const KMSG: &str = "/dev/kmsg";
    let device = match access(KMSG, Access::EXISTS) {
        Ok(_) => KMSG,
        Err(_) => {
            // try to create it
            mknodat(
                CWD,
                "/kmsg",
                FileType::CharacterDevice,
                0o666.into(),
                makedev(1, 11),
            )
            .ok();
            "/kmsg"
        }
    };

    let _ = kernlog::init_with_device(device);
}

fn unlimit_kmsg() {
    // Disable kmsg rate limiting
    if let Ok(mut rate) = std::fs::File::options()
        .write(true)
        .open("/proc/sys/kernel/printk_devkmsg")
    {
        writeln!(rate, "on").ok();
    }
}

pub fn init() -> Result<()> {
    // Setup kernel log first
    setup_kmsg();

    log::info!("Hello, KernelSU!");

    // mount /proc to access kernel interface
    let _dontdrop = prepare_mount();

    // This relies on the fact that we have /proc mounted
    unlimit_kmsg();

    if ksuinit::has_kernelsu() {
        log::info!("KernelSU may be already loaded in kernel, skip!");
    } else {
        log::info!("Loading kernelsu.ko..");
        if let Err(e) = load_module_from_path("/kernelsu.ko") {
            log::error!("Cannot load kernelsu.ko: {:?}", e);
        }
    }

    // And now we should prepare the real init to transfer control to it
    unlink("/init")?;

    let real_init = match access("/init.real", Access::EXISTS) {
        Ok(_) => "init.real",
        Err(_) => "/system/bin/init",
    };

    log::info!("init is {}", real_init);
    symlink(real_init, "/init")?;

    Ok(())
}


// MapleSU ramdisk provenance is image metadata, never a kernel module argument.
fn module_params_without_image_metadata(params: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(params.len());
    let mut position = 0;
    while position < params.len() {
        if params[position].is_ascii_whitespace() {
            output.push(params[position]);
            position += 1;
            continue;
        }
        let start = position;
        let mut quoted = false;
        while position < params.len() {
            if params[position] == b'"' {
                quoted = !quoted;
            } else if !quoted && params[position].is_ascii_whitespace() {
                break;
            }
            position += 1;
        }
        let token = &params[start..position];
        if !token.starts_with(b"maplesu_original_ramdisk=") {
            output.extend_from_slice(token);
        }
    }
    output
}

#[cfg(test)]
mod image_metadata_tests {
    use super::module_params_without_image_metadata as filter;

    #[test]
    fn removes_only_explicit_provenance_tokens_and_keeps_all_other_bytes() {
        assert_eq!(filter(b""), b"");
        assert_eq!(filter(b" \t\r\n"), b" \t\r\n");
        assert_eq!(filter(b"norc=1  foo=bar\tforce_feature=1:0"), b"norc=1  foo=bar\tforce_feature=1:0");
        assert_eq!(filter(b"maplesu_original_ramdisk=empty-v1"), b"");
        assert_eq!(filter(b"a=1 maplesu_original_ramdisk=empty-v1 b=2"), b"a=1  b=2");
        assert_eq!(filter(b" maplesu_original_ramdisk=empty-v1\tmaplesu_original_ramdisk=future-v9\n"), b" \t\n");
        assert_eq!(filter(b"maplesu_original_ramdisk= maplesu_original_ramdisk b=\xff"), b" maplesu_original_ramdisk b=\xff");
        assert_eq!(filter(b"other_maplesu_original_ramdisk=empty-v1"), b"other_maplesu_original_ramdisk=empty-v1");
        assert_eq!(filter(b"foo=\"maplesu_original_ramdisk=x\" other=\"one maplesu_original_ramdisk=y\""),
            b"foo=\"maplesu_original_ramdisk=x\" other=\"one maplesu_original_ramdisk=y\"");
        assert_eq!(filter(b"maplesu_original_ramdisk=\"future value\" keep=\"all values\""), b" keep=\"all values\"");
    }
}

fn load_module_from_path(path: &str) -> Result<()> {
    anyhow::ensure!(rustix::process::getpid().is_init(), "Invalid process");
    let buffer = std::fs::read(path).with_context(|| format!("Cannot read file {}", path))?;
    let params = std::fs::read("/ksu_config").unwrap_or_default();
    let params = module_params_without_image_metadata(&params);
    let params = unsafe { CString::from_vec_unchecked(params) };
    log::info!("load kernelsu with params {params:?}");
    ksuinit::load_module(&buffer, &params)
}

/// Ultra uses only the compatibility companion, before real first-stage init.
pub fn vr_init() -> Result<()> {
    anyhow::ensure!(rustix::process::getpid().is_init(), "Invalid process");
    setup_kmsg();
    let _mounts = prepare_mount();
    let loaded = std::fs::read("/.maplesu_vr/maplesu_vr.ko")
        .context("read Ultra vr companion")
        .and_then(|bytes| ksuinit::load_module(&bytes, c""));
    if let Err(error) = loaded {
        log::error!("MapleSU vr: early filter load failed: {error:#}");
    }
    // Rename preserves the original init's symlink target and mode.
    std::fs::rename("/.maplesu_vr/init.orig", "/init").context("restore original init")?;
    Ok(())
}
