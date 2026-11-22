// SPDX-License-Identifier: GPL-3.0-or-later
use std::{io::Cursor, path::PathBuf};
use android_bootimg::{cpio::{Cpio, CpioEntry}, parser::{BootImage, BootImageVersion}, patcher::BootImagePatchOption};
use anyhow::{Context, Result, ensure};

const ROOT: &str = ".maplesu_vr";
const MARKER: &str = ".maplesu_vr/id";
const BACKUP: &str = ".maplesu_vr/init.orig";
const ID: &[u8] = b"MAPLESU_VR_BOOTSTRAP_V1\n";

pub fn present(cpio: &Cpio) -> bool {
    cpio.entry_by_name(MARKER).and_then(CpioEntry::data) == Some(ID)
}

pub fn remove(cpio: &mut Cpio) -> Result<()> {
    if !cpio.exists(ROOT) && !cpio.exists(MARKER) { return Ok(()); }
    ensure!(present(cpio) && cpio.exists(BACKUP), "VR_BOOTSTRAP_LAYOUT_INVALID");
    cpio.rm("init", false);
    cpio.mv(BACKUP, "init")?;
    cpio.rm(ROOT, true);
    Ok(())
}

pub fn patch_image(source: &[u8], shim: &[u8], module: &[u8]) -> Result<Vec<u8>> {
    let image = BootImage::parse(source)?;
    ensure!(matches!(image.get_header().get_version(), BootImageVersion::Android(_)), "VR_BOOTSTRAP_BOOT_REQUIRED");
    let ramdisk = image.get_blocks().get_ramdisk().context("VR_BOOTSTRAP_RAMDISK_REQUIRED")?;
    let mut raw = Vec::new();
    ramdisk.dump(&mut raw, false)?;
    let mut cpio = Cpio::load_from_data(&raw)?;
    remove(&mut cpio)?;
    ensure!(!cpio.exists("init.real") && !cpio.exists("kernelsu.ko") && !cpio.exists("maplesu_id") && !cpio.exists(".backup") && !cpio.exists("overlay.d") && !cpio.exists(".magisk"), "VR_BOOTSTRAP_STOCK_REQUIRED");
    ensure!(cpio.exists("init"), "VR_BOOTSTRAP_INIT_REQUIRED");
    ensure!(shim.starts_with(b"\x7fELF") && module.starts_with(b"\x7fELF"), "VR_BOOTSTRAP_PAYLOAD_INVALID");
    cpio.add(ROOT, CpioEntry::dir(0o700))?;
    cpio.mv("init", BACKUP)?;
    cpio.add("init", CpioEntry::regular(0o750, Box::new(shim.to_vec())))?;
    cpio.add(".maplesu_vr/maplesu_vr.ko", CpioEntry::regular(0o600, Box::new(module.to_vec())))?;
    cpio.add(MARKER, CpioEntry::regular(0o600, Box::new(ID.to_vec())))?;
    let mut rebuilt = Vec::new();
    cpio.dump(&mut rebuilt)?;
    let mut patch = BootImagePatchOption::new(&image);
    patch.replace_ramdisk(Box::new(Cursor::new(rebuilt)), false);
    let mut output = Cursor::new(Vec::new());
    patch.patch(&mut output)?;
    Ok(output.into_inner())
}

#[derive(clap::Args, Debug)]
pub struct VrBootstrapArgs {
    #[arg(short, long)]
    pub boot: PathBuf,
    #[arg(short, long)]
    pub out: PathBuf,
    #[arg(long, default_value = "vr-bootstrap.img")]
    pub out_name: String,
    #[arg(long)]
    pub kmi: String,
}

pub fn patch(args: VrBootstrapArgs) -> Result<()> {
    ensure!(PathBuf::from(&args.out_name).file_name().and_then(|p| p.to_str()) == Some(&args.out_name), "VR_BOOTSTRAP_OUTPUT_INVALID");
    // The packaged companion is the KMI catalog; avoid a second, stale allowlist.
    let prefix = if cfg!(target_os = "android") { "" } else { "aarch64/" };
    let module = crate::assets::get_asset_data(&format!("{prefix}{}_maplesu_vr.ko", args.kmi))
        .with_context(|| format!("VR_BOOTSTRAP_KMI_UNSUPPORTED: {}", args.kmi))?;
    let shim = crate::assets::get_asset_data(&format!("{prefix}maplesu_vrinit"))?;
    let original = std::fs::read(args.boot)?;
    let bytes = patch_image(&original, &shim, &module)?;
    std::fs::create_dir_all(&args.out)?;
    let target = args.out.join(args.out_name);
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(target)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    println!("VR_BOOTSTRAP_READY {}", sha256::digest(&bytes));
    Ok(())
}

#[cfg(test)]
#[path = "vr_bootstrap_tests.rs"]
mod tests;
