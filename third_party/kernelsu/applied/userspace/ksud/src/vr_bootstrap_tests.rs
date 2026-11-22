use super::*;

fn archive(relative_symlink: bool) -> Cpio {
    let mut cpio = Cpio::new();
    let init = if relative_symlink { CpioEntry::symlink(0o777, "system/bin/init") } else {
        CpioEntry::regular(0o750, Box::new(b"ORIGINAL_INIT".to_vec()))
    };
    cpio.add("init", init).unwrap();
    cpio.add("fstab.fixture", CpioEntry::regular(0o640, Box::new(b"KEEP".to_vec()))).unwrap();
    cpio
}
fn boot(cpio: &Cpio, kernel: bool) -> Vec<u8> {
    let mut rd = Vec::new(); cpio.dump(&mut rd).unwrap();
    let mut b = vec![0u8; 4096]; b[..8].copy_from_slice(b"ANDROID!");
    b[8..12].copy_from_slice(&(if kernel {32u32} else {0u32}).to_le_bytes());
    b[12..16].copy_from_slice(&(rd.len() as u32).to_le_bytes());
    b[20..24].copy_from_slice(&1580u32.to_le_bytes());
    b[40..44].copy_from_slice(&3u32.to_le_bytes());
    if kernel { b.resize(8192, 0); b[4096..4128].fill(0x42); }
    b.extend_from_slice(&rd); b.resize(131072, 0); b
}
fn unpack(bytes: &[u8]) -> Cpio {
    let b = BootImage::parse(bytes).unwrap(); let mut rd = Vec::new();
    b.get_blocks().get_ramdisk().unwrap().dump(&mut rd, false).unwrap();
    Cpio::load_from_data(&rd).unwrap()
}
#[test]
fn boot_and_init_boot_install_only_companion_and_restore_relative_init() {
    for kernel in [true,false] { for link in [true,false] {
        let source = boot(&archive(link), kernel);
        let patched = patch_image(&source, b"\x7fELFshim", b"\x7fELFcompanion").unwrap();
        assert_eq!(source.len(), patched.len());
        let mut cp = unpack(&patched); assert!(present(&cp));
        assert!(!cp.exists("kernelsu.ko"));
        assert_eq!(cp.entry_by_name("fstab.fixture").unwrap().data(), Some(b"KEEP".as_slice()));
        assert_eq!(cp.entry_by_name(BACKUP).unwrap().data(), archive(link).entry_by_name("init").unwrap().data());
        remove(&mut cp).unwrap(); assert!(!cp.exists(ROOT));
        assert_eq!(cp.entry_by_name("init").unwrap().data(), archive(link).entry_by_name("init").unwrap().data());
    }}
}
#[test]
fn repatch_is_idempotent_and_normal_removal_is_repeatable() {
    let first = patch_image(&boot(&archive(true),true), b"\x7fELFshim", b"\x7fELFcompanion").unwrap();
    assert_eq!(first, patch_image(&first,b"\x7fELFshim",b"\x7fELFcompanion").unwrap());
    let mut cp = unpack(&first); remove(&mut cp).unwrap(); remove(&mut cp).unwrap();
    assert!(!present(&cp)); assert!(!cp.exists(BACKUP));
}
#[test]
fn damaged_identity_and_foreign_root_layouts_fail_before_output() {
    for marker in [".backup", "overlay.d", "init.real", "kernelsu.ko", "maplesu_id", ".maplesu_vr/id"] {
        let mut cp = archive(false);
        cp.add(marker,CpioEntry::regular(0o600,Box::new(b"FOREIGN".to_vec()))).unwrap();
        assert!(patch_image(&boot(&cp,true),b"\x7fELFshim",b"\x7fELFcompanion").is_err(),"{marker}");
    }
}
