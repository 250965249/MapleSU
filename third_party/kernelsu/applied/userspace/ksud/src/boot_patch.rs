#![allow(clippy::ref_option, clippy::needless_pass_by_value)]

use std::fs::File;
use std::io::{Cursor, Seek, SeekFrom};
use std::path::Path;
use std::path::PathBuf;

use android_bootimg::cpio::{Cpio, CpioEntry};
use android_bootimg::parser::{BootImage, BootImageVersion, RamdiskImage};
use android_bootimg::patcher::BootImagePatchOption;
use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use anyhow::bail;
use anyhow::ensure;
use memmap2::{Mmap, MmapOptions};
use regex_lite::Regex;

use crate::assets;
use crate::feature_id::{FeatureId, parse_feature_id};

#[cfg(target_os = "android")]
mod android {
    use super::Result;
    use super::{FlashFailureAction, flash_failure_action, image_fits_partition};
    pub(super) use crate::defs::{BACKUP_FILENAME, KSU_BACKUP_DIR, KSU_BACKUP_FILE_PREFIX};
    use crate::defs::{DEFAULT_PACKAGE_NAME, KSU_TEMP_BACKUP_DIR_NAME};
    use android_bootimg::cpio::{Cpio, CpioEntry};
    use anyhow::{Context, anyhow, bail, ensure};
    use regex_lite::Regex;
    use rustix::process::getuid;
    use std::fs::{File, OpenOptions};
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use crate::utils;

    pub(super) fn ensure_gki_kernel() -> Result<()> {
        let version = get_kernel_version()?;
        let is_gki = version.0 == 5 && version.1 >= 10 || version.2 > 5;
        ensure!(is_gki, "only support GKI kernel");
        Ok(())
    }

    pub fn get_kernel_version() -> Result<(i32, i32, i32)> {
        let uname = rustix::system::uname();
        let version = uname.release().to_string_lossy();
        let re = Regex::new(r"(\d+)\.(\d+)\.(\d+)")?;
        if let Some(captures) = re.captures(&version) {
            let major = captures
                .get(1)
                .and_then(|m| m.as_str().parse::<i32>().ok())
                .ok_or_else(|| anyhow!("Major version parse error"))?;
            let minor = captures
                .get(2)
                .and_then(|m| m.as_str().parse::<i32>().ok())
                .ok_or_else(|| anyhow!("Minor version parse error"))?;
            let patch = captures
                .get(3)
                .and_then(|m| m.as_str().parse::<i32>().ok())
                .ok_or_else(|| anyhow!("Patch version parse error"))?;
            Ok((major, minor, patch))
        } else {
            Err(anyhow!("Invalid kernel version string"))
        }
    }

    fn parse_kmi(version: &str) -> Result<String> {
        let re = Regex::new(r"(.* )?(\d+\.\d+)(\S+)?(android\d+)(.*)")?;
        let cap = re
            .captures(version)
            .ok_or_else(|| anyhow::anyhow!("Failed to get KMI from boot/modules"))?;
        let android_version = cap.get(4).map_or("", |m| m.as_str());
        let kernel_version = cap.get(2).map_or("", |m| m.as_str());
        Ok(format!("{android_version}-{kernel_version}"))
    }

    fn parse_kmi_from_uname() -> Result<String> {
        let uname = rustix::system::uname();
        let version = uname.release().to_string_lossy();
        parse_kmi(&version)
    }

    fn parse_kmi_from_modules() -> Result<String> {
        use std::io::BufRead;
        // find a *.ko in /vendor/lib/modules
        let modfile = std::fs::read_dir("/vendor/lib/modules")?
            .filter_map(Result::ok)
            .find(|entry| entry.path().extension().is_some_and(|ext| ext == "ko"))
            .map(|entry| entry.path())
            .ok_or_else(|| anyhow!("No kernel module found"))?;
        let output = Command::new("modinfo").arg(modfile).output()?;
        for line in output.stdout.lines().map_while(Result::ok) {
            if line.starts_with("vermagic") {
                return parse_kmi(&line);
            }
        }
        bail!("Parse KMI from modules failed")
    }

    pub fn get_current_kmi() -> Result<String> {
        parse_kmi_from_uname().or_else(|_| parse_kmi_from_modules())
    }

    fn calculate_sha1(file_path: impl AsRef<Path>) -> Result<String> {
        use sha1::Digest;
        use std::io::Read;
        let mut file = std::fs::File::open(file_path.as_ref())?;
        let mut hasher = sha1::Sha1::new();
        let mut buffer = [0; 1024];

        loop {
            let n = file.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
        }

        let result = hasher.finalize();
        Ok(base16ct::lower::encode_string(&result))
    }

    fn find_backup_location(sha1: &String) -> Result<(File, String)> {
        let filename = format!("{KSU_BACKUP_FILE_PREFIX}{sha1}");
        let target = format!("{KSU_BACKUP_DIR}{filename}");
        if let Ok(target_file) = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&target)
        {
            return Ok((target_file, target));
        }

        // We have no permission to access /data/adb
        // Save it to /data/user_de/$USER/$PKG/boot_backup
        let user_id = getuid().as_raw() / 100_000;

        let backup_dir =
            format!("/data/user_de/{user_id}/{DEFAULT_PACKAGE_NAME}/{KSU_TEMP_BACKUP_DIR_NAME}");
        std::fs::remove_dir_all(&backup_dir).ok();
        std::fs::create_dir(&backup_dir)?;
        let backup_file = format!("{backup_dir}/{filename}");
        if let Ok(file) = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&backup_file)
        {
            return Ok((file, backup_file));
        }

        bail!("Both /data/adb/ksu and {backup_dir} are not accessible!")
    }

    /// 备份当前 boot 镜像，并**校验备份确实写好了**（7K :165-238）。
    ///
    /// 返回备份文件路径：刷写校验失败时要用它回滚（B3）。
    /// `record_stock` 决定是否把它登记成 ramdisk 里的 `stock_image.sha1`
    /// （只有原厂态才登记，见 `should_record_stock`）。
    pub(super) fn do_backup(cpio: &mut Cpio, image: &Path, record_stock: bool) -> Result<PathBuf> {
        let sha1 = calculate_sha1(image)?;
        let (mut target_file, target) = find_backup_location(&sha1)?;
        println!("- Backup stock boot image");
        let mut source = OpenOptions::new()
            .create(false)
            .truncate(false)
            .read(true)
            .write(false)
            .open(image)?;

        // Use io::copy instead of fs::copy to allow copy block device
        std::io::copy(&mut source, &mut target_file)
            .with_context(|| format!("failed to backup to {target}"))?;
        // 落盘后再回读校验，避免只在页缓存里"看起来对"
        target_file
            .sync_all()
            .with_context(|| format!("failed to sync backup {target}"))?;

        let backup_sha1 = calculate_sha1(&target)?;
        if backup_sha1 != sha1 {
            bail!(
                "backup verification failed: {target} has sha1 {backup_sha1} but the source image has sha1 {sha1}.\n\
                 Refusing to continue: the backup is not trustworthy."
            );
        }
        println!("- Backup verified (sha1 {sha1})");

        if record_stock {
            let backup_file = CpioEntry::regular(0o755, Box::new(sha1));
            cpio.add(BACKUP_FILENAME, backup_file)?;
        } else {
            println!("- Keeping the existing stock image marker (this image is already patched)");
        }

        println!("- Stock image has been backup to");
        println!("- {target}");
        Ok(PathBuf::from(target))
    }

    /// 把校验失败的分区用备份原样写回去，并再验 sha1（7K :240-260）。
    fn rollback_partition(blk: &mut File, partition: &str, backup: &Path) -> Result<()> {
        let mut source = OpenOptions::new()
            .create(false)
            .truncate(false)
            .read(true)
            .write(false)
            .open(backup)
            .with_context(|| format!("open backup {}", backup.display()))?;
        blk.seek(SeekFrom::Start(0))?;
        std::io::copy(&mut source, blk)
            .with_context(|| format!("write backup {} back", backup.display()))?;
        blk.sync_all().context("sync rolled back boot failed")?;

        let backup_sha1 = calculate_sha1(backup)?;
        let partition_sha1 = calculate_sha1(partition)?;
        ensure!(
            backup_sha1 == partition_sha1,
            "rollback verification failed: {partition} has sha1 {partition_sha1} but the backup has sha1 {backup_sha1}"
        );
        Ok(())
    }

    /// 写分区 + sync + 读回整段 SHA-256 校验（7K :271-291）。
    ///
    /// 任何一步失败都只返回 Err，收场逻辑统一交给 `flash_failure_error`。
    fn write_and_verify(blk: &mut File, partition: &str, data: &[u8]) -> Result<()> {
        blk.write_all(data).context("flash boot failed")?;
        blk.sync_all().context("sync boot failed")?;

        let expected = sha256::digest(data);
        blk.seek(SeekFrom::Start(0))
            .with_context(|| format!("seek {partition} for verification"))?;
        let mut readback = vec![0u8; data.len()];
        blk.read_exact(&mut readback)
            .with_context(|| format!("read back {partition} for verification"))?;
        let actual = sha256::digest(&readback);
        drop(readback);

        ensure!(
            expected == actual,
            "write verification failed (expected sha256 {expected}, got {actual})"
        );
        println!("- Write verified (sha256 {actual})");
        Ok(())
    }

    /// 刷写失败的唯一出口（7K :293-340）：回滚成功 → 提示可重试；否则明确「勿重启」。
    fn flash_failure_error(
        blk: &mut File,
        partition: &str,
        backup: Option<&Path>,
        error: &anyhow::Error,
    ) -> anyhow::Error {
        println!("- Flashing {partition} failed: {error:#}");

        let mut rollback_error: Option<anyhow::Error> = None;
        let rollback_result: Option<Result<()>> = backup.map(|backup_path| {
            println!("- Rolling back from {}", backup_path.display());
            rollback_partition(blk, partition, backup_path)
        });
        let rolled_back = match rollback_result {
            Some(Ok(())) => true,
            Some(Err(e)) => {
                rollback_error = Some(e);
                false
            }
            None => false,
        };

        match flash_failure_action(backup.is_some(), rolled_back) {
            FlashFailureAction::RolledBack => anyhow!(
                "flashing {partition} failed: {error:#}\n\
                 the original partition content has been written back from the backup and verified with sha1,\n\
                 so the device should still boot. Please retry, or use the offline patch-to-file flow."
            ),
            FlashFailureAction::PartitionMayBeCorrupted => {
                let detail = rollback_error.map_or_else(
                    || "there is no verified backup to roll back to".to_string(),
                    |e| format!("the rollback itself failed: {e:#}"),
                );
                anyhow!(
                    "flashing {partition} failed: {error:#}\n\
                     and it could not be rolled back ({detail}).\n\
                     The partition may be corrupted: DO NOT REBOOT the device.\n\
                     Flash the backup back from a computer with fastboot, then reboot."
                )
            }
        }
    }

    /// 刷写 boot/init_boot 分区，带三道护栏（7K :353-400）：
    /// ① 写前用 BLKGETSIZE64 确认镜像装得下（防选错分区）；
    /// ② 写完 sync 后读回整段 SHA-256 比对；
    /// ③ 任何失败用备份回滚并再验 sha1；回滚不了就明确「勿重启」。
    pub(super) fn flash_partition(
        partition: &str,
        data: &[u8],
        backup: Option<&Path>,
    ) -> Result<()> {
        let mut blk = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .truncate(false)
            .create(false)
            .open(partition)
            .with_context(|| format!("open {partition}"))?;
        unsafe {
            const BLKROSET: i32 = libc::_IO(0x12, 93);
            let mut val: libc::c_int = 0;
            if libc::ioctl(blk.as_raw_fd(), BLKROSET, &raw mut val) != 0 {
                bail!("Failed to set rw for {partition}: {}", *libc::__errno());
            }
        }

        let part_size = unsafe {
            // BLKGETSIZE64 = _IOR(0x12, 114, size_t)
            const BLKGETSIZE64: i32 = libc::_IOR::<libc::size_t>(0x12, 114);
            let mut size: u64 = 0;
            if libc::ioctl(blk.as_raw_fd(), BLKGETSIZE64, &raw mut size) != 0 {
                bail!(
                    "Failed to query the size of {partition}: {}. \
                     Cannot confirm the target partition, refusing to write.",
                    *libc::__errno()
                );
            }
            size
        };
        ensure!(
            image_fits_partition(data.len() as u64, part_size),
            "the boot image is {} bytes but partition {partition} is only {} bytes. \
             The wrong partition was probably selected; refusing to write.",
            data.len(),
            part_size
        );

        match write_and_verify(&mut blk, partition, data) {
            Ok(()) => Ok(()),
            Err(error) => Err(flash_failure_error(&mut blk, partition, backup, &error)),
        }
    }

    pub(super) fn clean_backup(sha1: &str) -> Result<()> {
        println!("- Clean up backup");
        let backup_name = format!("{KSU_BACKUP_FILE_PREFIX}{sha1}");
        let dir = std::fs::read_dir(KSU_BACKUP_DIR)?;
        for entry in dir.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            if let Some(name) = path.file_name() {
                let name = name.to_string_lossy().to_string();
                if name != backup_name
                    && name.starts_with(KSU_BACKUP_FILE_PREFIX)
                    && std::fs::remove_file(path).is_ok()
                {
                    println!("- removed {name}");
                }
            }
        }
        Ok(())
    }

    pub fn choose_boot_partition(
        kmi: &str,
        is_replace_kernel: bool,
        partition: &Option<String>,
    ) -> String {
        let slot_suffix = get_slot_suffix(false);
        let skip_init_boot = kmi.starts_with("android12-");
        let init_boot_exist =
            Path::new(&format!("/dev/block/by-name/init_boot{slot_suffix}")).exists();

        // if specific partition is specified, use it
        if let Some(part) = partition {
            return match part.as_str() {
                "boot" | "init_boot" | "vendor_boot" => part.clone(),
                _ => "boot".to_string(),
            };
        }

        // if init_boot exists and not skipping it, use it
        if !is_replace_kernel && init_boot_exist && !skip_init_boot {
            return "init_boot".to_string();
        }

        "boot".to_string()
    }

    pub fn get_slot_suffix(ota: bool) -> String {
        let mut slot_suffix = utils::getprop("ro.boot.slot_suffix").unwrap_or_default();
        if !slot_suffix.is_empty() && ota {
            if slot_suffix == "_a" {
                slot_suffix = "_b".to_string();
            } else {
                slot_suffix = "_a".to_string();
            }
        }
        slot_suffix
    }

    pub fn list_available_partitions() -> Vec<String> {
        let slot_suffix = get_slot_suffix(false);
        let candidates = vec!["boot", "init_boot", "vendor_boot"];
        candidates
            .into_iter()
            .filter(|name| Path::new(&format!("/dev/block/by-name/{name}{slot_suffix}")).exists())
            .map(ToString::to_string)
            .collect()
    }

    pub(super) fn auto_boot_partition_path(
        kmi: &str,
        ota: bool,
        is_replace_kernel: bool,
        partition: &Option<String>,
    ) -> PathBuf {
        let slot_suffix = get_slot_suffix(ota);
        let name = choose_boot_partition(kmi, is_replace_kernel, partition);
        PathBuf::from(format!("/dev/block/by-name/{name}{slot_suffix}"))
    }

    pub(super) fn post_ota() -> Result<()> {
        use crate::assets::BOOTCTL_PATH;
        use crate::defs::ADB_DIR;
        let status = Command::new(BOOTCTL_PATH).arg("hal-info").status()?;
        if !status.success() {
            return Ok(());
        }

        let current_slot = Command::new(BOOTCTL_PATH)
            .arg("get-current-slot")
            .output()?
            .stdout;
        let current_slot = String::from_utf8(current_slot)?;
        let current_slot = current_slot.trim();
        let target_slot = i32::from(current_slot == "0");

        Command::new(BOOTCTL_PATH)
            .arg(format!("set-active-boot-slot {target_slot}"))
            .status()?;

        let post_fs_data = Path::new(ADB_DIR).join("post-fs-data.d");
        utils::ensure_dir_exists(&post_fs_data)?;
        let post_ota_sh = post_fs_data.join("post_ota.sh");

        let sh_content = format!(
            r"
{BOOTCTL_PATH} mark-boot-successful
rm -f {BOOTCTL_PATH}
rm -f /data/adb/post-fs-data.d/post_ota.sh
"
        );

        std::fs::write(&post_ota_sh, sh_content)?;
        std::fs::set_permissions(post_ota_sh, std::fs::Permissions::from_mode(0o755))?;

        Ok(())
    }
}

#[cfg(target_os = "android")]
pub use android::*;

fn map_file(file: &Path) -> Result<Mmap> {
    let mut f = File::open(file).with_context(|| format!("open {}", file.display()))?;
    let len = f
        .seek(SeekFrom::End(0))
        .with_context(|| format!("seek end of {}", file.display()))? as usize;
    let mmap = unsafe { MmapOptions::new().len(len).map(&f)? };
    Ok(mmap)
}

pub fn parse_kmi(buffer: &[u8]) -> Result<String> {
    let re = Regex::new(r"(\d+\.\d+)(?:\S+)?(android\d+)").context("Failed to compile regex")?;
    buffer
        .windows(4)
        .enumerate()
        .filter(|(_, x)| {
            x[1] == b'.'
                && x[2].is_ascii_digit()
                && match x[0] {
                    b'5' => x[3].is_ascii_digit(),
                    b'6'..=b'9' => true,
                    _ => false,
                }
        })
        .find_map(|(i, _)| {
            let a = &buffer[i..buffer.len().min(i + 100)];
            if let Some(e) = a.iter().position(|c| *c == 0)
                && let Ok(s) = std::str::from_utf8(&a[..e])
                && let Some(caps) = re.captures(s)
                && let (Some(kernel_version), Some(android_version)) = (caps.get(1), caps.get(2))
            {
                Some(format!(
                    "{}-{}",
                    android_version.as_str(),
                    kernel_version.as_str()
                ))
            } else {
                None
            }
        })
        .ok_or_else(|| {
            println!("- Failed to get KMI version");
            anyhow!("Try to choose LKM manually")
        })
}

fn parse_kmi_from_kernel(kernel: &Path) -> Result<String> {
    let data = std::fs::read(kernel).context("Failed to read kernel file")?;
    parse_kmi(&data)
}

fn parse_kmi_from_boot(image: &Path) -> Result<String> {
    let data = map_file(image)?;
    let boot = BootImage::parse(&data)?;
    if let Some(kernel) = boot.get_blocks().get_kernel() {
        let mut output = Vec::<u8>::new();
        kernel.dump(&mut output, false)?;
        parse_kmi(&output)
    } else {
        bail!("no kernel found in boot image")
    }
}

/// For vendor boot, prefer the `init_boot` ramdisk entry over the one with empty name,
/// matching the original magiskboot lookup order (init_boot.cpio before ramdisk.cpio).
fn extract_ramdisk(ramdisk_image: &RamdiskImage) -> Result<(Cpio, Option<usize>)> {
    if ramdisk_image.is_vendor_ramdisk() {
        let (pos, target) = ramdisk_image
            .iter_vendor_ramdisk()
            .enumerate()
            .find(|e| e.1.get_name_raw() == b"init_boot")
            .or_else(|| {
                ramdisk_image
                    .iter_vendor_ramdisk()
                    .enumerate()
                    .find(|e| e.1.get_name_raw() == b"")
            })
            .ok_or_else(|| anyhow!("No suitable vendor ramdisk entry found"))?;
        let mut buf = Vec::<u8>::new();
        target.dump(&mut buf, false)?;
        Ok((Cpio::load_from_data(&buf)?, Some(pos)))
    } else {
        let mut buf = Vec::<u8>::new();
        ramdisk_image.dump(&mut buf, false)?;
        Ok((Cpio::load_from_data(&buf)?, None))
    }
}

fn enforce_bootimage_version(boot: &BootImage<'_>) -> Result<()> {
    if let BootImageVersion::Android(ver) = boot.get_header().get_version()
        && ver < 3
    {
        bail!("bootimage version {ver} is not supported!")
    }
    Ok(())
}


// ══════════════════════════════════════════════════════════════════════════
// MapleSU W18b（0007b）· boot-patch 安全增强
//
// 移植自 7K v2.30 `userspace/ksud/src/boot_patch.rs` 的以下判据/算法（逐字或等价）：
//   · RamdiskState 四态 + of()            :626-700
//   · init_disposition()                  :703-724
//   · should_record_stock()               :726-745
//   · image_fits_partition()              :747-760
//   · restore_admission()/is_restorable() :835-880
//   · FlashFailureAction/flash_failure_action() :1005-1030
//   · query_ramdisk_state()/read_ramdisk_state() :934-994
// Android 侧（写分区路径）的 do_backup/write_and_verify/rollback_partition/
// flash_failure_error/flash_partition 在下面 `mod android` 里逐条移植：
//   · do_backup + 备份回读校验           :165-238
//   · rollback_partition                  :240-260
//   · write_and_verify（写后整段 SHA-256）:271-291
//   · flash_failure_error（唯一失败出口）  :293-400
//   · flash_partition（长度闸 + 读回校验 + 回滚）:353-400
//
// 与 7K 的**有意差异**（03 分册 §2.2.5 / §2.2.7 / §8-C1）：
//   · Ours 判据用 0 字节标记条目 `maplesu_id`，不用 7K 的 `sevenk.ko`；
//     模块条目沿用上游名 `kernelsu.ko`（对官方 KernelSU 双向兼容，主文档:467）。
//   · UAPI 相等语义保留上游（不移植 7K 的 `kernel >= userspace` 放宽，见 §8-C1）。
//   · 7K 的「内核归属探测闸」(KernelOwner + stealth_probe_get) 未移植：它依赖内核侧
//     安全阀命令先真机验证；本分支改用「按目标镜像状态拒绝」这道不依赖内核的闸。
//     → manifest.patchSeries.todo 里登记为 W18b 剩余 blocker。
// ══════════════════════════════════════════════════════════════════════════

/// MapleSU 的归属标记（存在即 Ours）；内容写 `uapi=7` 便于现场诊断。
const OURS_MARKER_ENTRY: &str = "maplesu_id";
const OURS_MARKER_CONTENT: &[u8] = b"uapi=7";

/// 官方 KernelSU 唯一认得的模块条目名。
///
/// 我们打的镜像**也**放这个条目：官方 ksud 判定"已打过补丁"只看它，缺了它
/// 官方会把我们的 `init`（我们放的 ksuinit）挪去覆盖 `init.real` 里的真 init
/// → 开机死循环（7K 用户 2026-09-21 实测；见 7K boot_patch.rs:601-621 长注释）。
const OFFICIAL_KSU_ENTRY: &str = "kernelsu.ko";

/// ramdisk 里 `init` 的四种状态（7K :626-690）。
///
/// 判定目的：绝不能在「布局不兼容的别的 root 方案改过」的镜像上做 `init -> init.real`，
/// 更不能直接刷写这种镜像 —— 那会把真正的 init 覆盖掉（硬砖）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RamdiskState {
    /// 我们自己打的补丁（有 `maplesu_id`）
    Ours,
    /// 官方 KernelSU / 本项目早期包：有 `kernelsu.ko` 且有 `init.real` → 布局同源兼容
    Compatible,
    /// 别人的/畸形布局：有 `kernelsu.ko` 却没有 `init.real`，或只有 `init.real`
    Foreign,
    /// 原厂镜像：三者都没有
    Stock,
}

impl RamdiskState {
    pub fn of(cpio: &Cpio) -> Self {
        // ① 有我们的标记                          → Ours
        // ② 有 kernelsu.ko 且有 init.real          → Compatible（官方 KSU 同源布局）
        // ③ 有 kernelsu.ko 但没有 init.real        → Foreign（畸形，叠了必砖）
        // ④ 只有 init.real、无任何 KSU 模块        → Foreign（别的 root 方案）
        // ⑤ 都没有                                → Stock
        if crate::vr_bootstrap::present(cpio) {
            Self::Compatible
        } else if cpio.exists(OURS_MARKER_ENTRY) {
            Self::Ours
        } else if cpio.exists(OFFICIAL_KSU_ENTRY) {
            if cpio.exists("init.real") {
                Self::Compatible
            } else {
                Self::Foreign
            }
        } else if cpio.exists("init.real") {
            Self::Foreign
        } else {
            Self::Stock
        }
    }

    /// 机器接口输出词（`ksud boot-info ramdisk-state` 的唯一输出，7K :688-698）。
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ours => "ours",
            Self::Compatible => "compatible",
            Self::Foreign => "foreign",
            Self::Stock => "stock",
        }
    }
}

/// 拿到镜像后对 `init` / `init.real` 该做哪一步（7K :703-724）。
///
/// **只有原厂镜像才允许把 `init` 挪成 `init.real`** —— 这一步不可逆；
/// `Compatible` 镜像里 `init.real` 就是真正的 Android init，挪动 = 覆盖它 = 死循环。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InitDisposition {
    MoveInitToReal,
    KeepInitReal,
}

const fn init_disposition(state: RamdiskState) -> InitDisposition {
    match state {
        RamdiskState::Stock => InitDisposition::MoveInitToReal,
        RamdiskState::Ours | RamdiskState::Compatible | RamdiskState::Foreign => {
            InitDisposition::KeepInitReal
        }
    }
}

/// 这份备份要不要登记成 ramdisk 里的 `stock_image.sha1`（7K :726-745）。
///
/// **只有当前镜像是原厂（Stock）时才登记**：在已打补丁的镜像上勾强制备份，
/// 那份镜像不是原厂；登记进去会让 restore 的退路指向已打补丁的镜像。
fn should_record_stock(state: RamdiskState, explicit_backup: bool) -> bool {
    if explicit_backup && state != RamdiskState::Stock {
        println!(
            "- Explicit backup: keeping it, but NOT recording it as the stock image \
             (the current image is not stock)"
        );
    }
    state == RamdiskState::Stock
}

/// 镜像长度必须装得进目标分区（7K :747-760，防「选错分区」）。
const fn image_fits_partition(image_len: u64, partition_size: u64) -> bool {
    image_len <= partition_size
}

/// 只有 Ours / Compatible 的镜像可以安全还原（7K :835-839）。
const fn is_restorable(state: RamdiskState) -> bool {
    matches!(state, RamdiskState::Ours | RamdiskState::Compatible)
}

/// 还原准入（7K :858-880 的 fail-closed 形态；`--force-foreign` 逃生口未移植，
/// 见 manifest.todos —— 这是**有意收紧**：v1 绝不拆别的 root 方案）。
fn restore_admission(state: RamdiskState) -> Result<()> {
    if !is_restorable(state) {
        bail!(
            "refusing to restore: this boot image was NOT patched by a KernelSU-compatible tool.\n\
             · a `kernelsu.ko` entry with NO `init.real` (malformed / unknown layout) — stacking on it bricks;\n\
             · another root solution left an `init.real` entry.\n\
             Restoring it here would DELETE that solution's modules and move `init.real` back to\n\
             `init` — i.e. it would tear down a root you did not install. Nothing was written.\n\
             Flash the STOCK boot/init_boot image for this device from a computer (fastboot) instead."
        );
    }
    Ok(())
}

/// 刷写失败该怎么收场（7K :1005-1030，纯判据、宿主机可测）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FlashFailureAction {
    /// 已回滚成功：设备应仍能开机
    RolledBack,
    /// 没退路：必须报「分区可能已损坏，请勿重启」
    PartitionMayBeCorrupted,
}

const fn flash_failure_action(has_backup: bool, rollback_succeeded: bool) -> FlashFailureAction {
    if has_backup && rollback_succeeded {
        FlashFailureAction::RolledBack
    } else {
        FlashFailureAction::PartitionMayBeCorrupted
    }
}

/// 只读查询一张 boot 镜像的 ramdisk 状态（7K :934-994）。
///
/// 契约：成功 → 恰好一个词 `ours|compatible|foreign|stock`；任何失败 → `unknown`
/// （App 对 unknown 是 fail-closed，不显示"直接安装"按钮）。**绝不写盘**。
pub fn query_ramdisk_state(image: Option<&Path>) -> &'static str {
    let Some(path) = resolve_query_image(image) else {
        #[cfg(not(target_os = "android"))]
        println!("- ramdisk-state: --boot <image> is required on the host");
        return "unknown";
    };
    match read_ramdisk_state(&path) {
        Ok(state) => state.as_str(),
        Err(e) => {
            println!("- ramdisk-state: cannot read {}: {e:#}", path.display());
            "unknown"
        }
    }
}

#[cfg(target_os = "android")]
fn resolve_query_image(image: Option<&Path>) -> Option<PathBuf> {
    image.map_or_else(
        || {
            let kmi = get_current_kmi().unwrap_or_default();
            Some(auto_boot_partition_path(&kmi, false, false, &None))
        },
        |p| Some(p.to_path_buf()),
    )
}

#[cfg(not(target_os = "android"))]
fn resolve_query_image(image: Option<&Path>) -> Option<PathBuf> {
    image.map(Path::to_path_buf)
}

fn read_ramdisk_state(path: &Path) -> Result<RamdiskState> {
    let data = map_file(path)?;
    let image = BootImage::parse(&data)?;
    let ramdisk = image
        .get_blocks()
        .get_ramdisk()
        .ok_or_else(|| anyhow!("no ramdisk in this image"))?;
    let (cpio, _vendor_idx) = extract_ramdisk(ramdisk)?;
    Ok(RamdiskState::of(&cpio))
}

#[allow(clippy::struct_excessive_bools)]
#[derive(clap::Args, Debug)]
pub struct BootPatchArgs {
    /// boot image path, if not specified, will try to find the boot image automatically
    #[arg(short, long)]
    pub boot: Option<PathBuf>,

    /// kernel image path to replace
    #[arg(short, long)]
    pub kernel: Option<PathBuf>,

    /// LKM module path to replace, if not specified, will use the builtin one
    #[arg(short, long)]
    pub module: Option<PathBuf>,

    /// init to be replaced
    #[arg(short, long)]
    pub init: Option<PathBuf>,

    /// will use another slot when boot image is not specified
    #[cfg(target_os = "android")]
    #[arg(short = 'u', long, default_value = "false")]
    pub ota: bool,

    /// Flash it to boot partition after patch
    #[cfg(target_os = "android")]
    #[arg(short, long, default_value = "false")]
    pub flash: bool,

    /// Force backup source image as stock image
    #[cfg(target_os = "android")]
    #[arg(long, default_value = "false")]
    pub backup: bool,

    /// Output path. If not specified, will use current directory.
    /// If specified, the boot image will be written to the directory
    /// even if --flash is specified.
    #[cfg(target_os = "android")]
    #[arg(short, long, default_value = None)]
    pub out: Option<PathBuf>,

    /// Output path. If not specified, will use current directory.
    #[cfg(not(target_os = "android"))]
    #[arg(short, long, default_value = None)]
    pub out: Option<PathBuf>,

    /// KMI version, if specified, will use the specified KMI
    #[arg(long, default_value = None)]
    pub kmi: Option<String>,

    /// target partition override (init_boot | boot | vendor_boot)
    #[cfg(target_os = "android")]
    #[arg(long, default_value = None)]
    pub partition: Option<String>,

    /// File name of the output. If specified, the boot image will be
    /// written to the output directory even if --flash is specified.
    #[cfg(target_os = "android")]
    #[arg(long, default_value = None)]
    pub out_name: Option<String>,

    /// File name of the output.
    #[cfg(not(target_os = "android"))]
    #[arg(long, default_value = None)]
    pub out_name: Option<String>,

    /// Extra cmdline to append to boot image header
    #[arg(long, default_value = None)]
    pub cmdline: Option<String>,

    #[command(flatten)]
    config: KsuConfigArgs,

    /// Force enable adbd and disable adbd auth
    #[arg(long, default_value = "false")]
    enable_adbd: bool,

    /// Add more adb_debug prop
    #[arg(long, required = false)]
    adb_debug_prop: Option<String>,

    /// Do not (re-)install kernelsu, only modify configs (allow_shell, etc.)
    #[arg(long, default_value = "false")]
    no_install: bool,

    #[cfg(not(target_os = "android"))]
    #[arg(long, default_value = "aarch64")]
    arch: String,

    /// Patching ramdisk instead of boot image. This is used for AVD ramdisk
    #[arg(long, default_value = "false")]
    ramdisk: bool,
}

/// KernelSU module params, stored in ramdisk `/ksu_config` (boot-patch) or the
/// injected capsule (boot-patch-v2).
#[derive(clap::Args, Debug, Default)]
pub struct KsuConfigArgs {
    /// Always allow shell to get root permission
    #[arg(long, default_value = "false")]
    allow_shell: bool,

    /// Do not load custom rc
    #[arg(long, default_value = "false")]
    no_custom_rc: bool,

    /// Do not run module preinit actions
    #[arg(long, default_value = "false")]
    no_preinit: bool,

    /// Force a kernel feature to a value at boot, e.g. `su_compat=0`.
    /// Forced features can not be changed or loaded by userspace. Can be repeated.
    #[arg(long, value_name = "FEATURE=VALUE", value_parser = parse_force_feature)]
    force_feature: Vec<(FeatureId, u64)>,

    /// [Developer only] Block a kernel module from loading at boot by name, e.g.
    /// `oplus_secure_guard`. Comma-separated and/or repeated. Omitting clears it.
    /// Blocked modules fail to load with EPERM; blocking one that first stage
    /// init loads (modules.load / modules.load.recovery) or that others depend
    /// on can bootloop the device. You are on your own.
    #[arg(long = "block-module", value_name = "NAME", value_delimiter = ',', value_parser = parse_block_module)]
    block_module: Vec<String>,
}

/// Max length of the `block_modules=` value. The kernel copies it into a
/// 256-byte buffer, leaving 255 bytes for the value; anything longer is
/// silently truncated there, so reject it on the host instead.
const MAX_BLOCK_MODULES_LEN: usize = 255;

impl KsuConfigArgs {
    /// Validate options whose full value is only known after joining. Call
    /// before `apply` so the user gets an error instead of the kernel silently
    /// truncating an over-long list (which would leave some modules unblocked).
    pub fn validate(&self) -> Result<()> {
        if !self.block_module.is_empty() {
            let len = self.block_module.join(",").len();
            ensure!(
                len <= MAX_BLOCK_MODULES_LEN,
                "block-module list is too long ({len} bytes, max {MAX_BLOCK_MODULES_LEN}); block fewer modules"
            );
        }
        Ok(())
    }

    /// Set the full state of these options in `config`, other entries are kept.
    pub fn apply(&self, config: &mut Vec<String>) {
        set_config_flag(config, "no custom rc", "norc=1", self.no_custom_rc);
        set_config_flag(config, "allow shell", "allow_shell=1", self.allow_shell);
        set_config_flag(config, "no preinit", "preinit=0", self.no_preinit);

        config.retain(|v| !v.starts_with("force_feature="));
        if !self.force_feature.is_empty() {
            let mut entries = Vec::with_capacity(self.force_feature.len());
            for (feature_id, value) in &self.force_feature {
                println!("- Forcing feature {} to {value}", feature_id.name());
                entries.push(format!("{}:{value}", feature_id.name()));
            }
            config.push(format!("force_feature={}", entries.join(",")));
        }

        config.retain(|v| !v.starts_with("block_modules="));
        if !self.block_module.is_empty() {
            let list = self.block_module.join(",");
            println!("- Blocking modules: {list}");
            config.push(format!("block_modules={list}"));
        }
    }
}

/// Validate a single module name for the `--block-module` option. The kernel
/// `block_modules` buffer holds 255 bytes, so keep names well within that.
fn parse_block_module(s: &str) -> Result<String> {
    ensure!(!s.is_empty(), "module name must not be empty");
    ensure!(
        s.len() <= 64,
        "module name '{s}' is too long (max 64 bytes)"
    );
    ensure!(
        s.bytes().all(|ch| ch.is_ascii_alphanumeric() || ch == b'_'),
        "invalid module name '{s}': only letters, digits and '_' are allowed"
    );
    Ok(s.to_owned())
}

fn set_config_flag(config: &mut Vec<String>, name: &str, value: &str, add: bool) {
    let has_value = config.iter().any(|v| v == value);

    if add {
        println!("- Adding {name} config");
        if !has_value {
            config.push(value.to_owned());
        }
    } else if has_value {
        println!("- Removing {name} config");
        config.retain(|v| v != value);
    }
}

fn parse_force_feature(s: &str) -> Result<(FeatureId, u64)> {
    let (name, value) = s
        .split_once('=')
        .context("expected FEATURE=VALUE, e.g. su_compat=0")?;
    let value = value
        .parse()
        .with_context(|| format!("invalid value for feature {name}: {value}"))?;
    Ok((parse_feature_id(name)?, value))
}

pub fn patch(args: BootPatchArgs) -> Result<()> {
    let inner = move || {
        let BootPatchArgs {
            boot: image,
            init,
            kernel,
            module: kmod,
            out,
            kmi,
            out_name,
            cmdline,
            config,
            enable_adbd,
            adb_debug_prop,
            no_install,
            #[cfg(target_os = "android")]
            ota,
            #[cfg(target_os = "android")]
            flash,
            #[cfg(target_os = "android")]
            backup,
            #[cfg(target_os = "android")]
            partition,
            #[cfg(not(target_os = "android"))]
            arch,
            ramdisk,
        } = args;

        println!(include_str!("banner"));

        #[cfg(target_os = "android")]
        let patch_file = image.is_some();

        #[cfg(target_os = "android")]
        if !patch_file {
            ensure_gki_kernel()?;
        }

        let is_replace_kernel = kernel.is_some();

        if ramdisk && is_replace_kernel {
            bail!("incompatiable option: --ramdisk and --kernel")
        }

        #[cfg(target_os = "android")]
        if ramdisk && flash {
            bail!("incompatiable option: --ramdisk and --flash")
        }

        if is_replace_kernel {
            ensure!(
                init.is_none() && kmod.is_none(),
                "init and module must not be specified."
            );
        }

        // None means --no-install: preserve the marker for the existing LKM.
        let bundled_lkm = (!no_install).then_some(kmod.is_none());

        let kmi = kmi.map_or_else(
            || -> Result<_> {
                if kmod.is_some() || (no_install && image.is_some()) {
                    return Ok(String::new());
                }
                // Explicit KMI is handled by map_or_else before this default path.
                if let Some(kernel_path) = &kernel {
                    println!("- KMI source: replacement kernel {}", kernel_path.display());
                    return parse_kmi_from_kernel(kernel_path);
                }
                if !ramdisk && let Some(image_path) = &image {
                    let data = map_file(image_path)?;
                    let target = BootImage::parse(&data)?;
                    if target.get_blocks().get_kernel().is_some() {
                        println!("- KMI source: target boot {}", image_path.display());
                        return parse_kmi_from_boot(image_path);
                    }
                }
                #[cfg(target_os = "android")]
                if ota {
                    let slot_suffix = get_slot_suffix(true);
                    println!("- Trying to auto detect KMI version from boot");
                    return parse_kmi_from_boot(Path::new(&format!(
                        "/dev/block/by-name/boot{slot_suffix}"
                    )));
                }
                #[cfg(target_os = "android")]
                match get_current_kmi() {
                    Ok(value) => {
                        return Ok(value);
                    }
                    Err(e) => {
                        println!("- {e}");
                    }
                }
                Ok(if ramdisk {
                    bail!("please specify kmi manually")
                } else if let Some(image_path) = &image {
                    println!(
                        "- Trying to auto detect KMI version for {}",
                        image_path.display()
                    );
                    parse_kmi_from_boot(image_path)?
                } else {
                    String::new()
                })
            },
            Ok,
        )?;

        let boot_image_file = if let Some(image) = image {
            ensure!(image.exists(), "boot image not found");
            std::fs::canonicalize(image)?
        } else {
            #[cfg(target_os = "android")]
            {
                auto_boot_partition_path(&kmi, ota, is_replace_kernel, &partition)
            }
            #[cfg(not(target_os = "android"))]
            {
                bail!("Please specify a boot image");
            }
        };

        #[cfg(target_os = "android")]
        println!("- Bootdevice: {}", boot_image_file.display());

        // try extract bootctl/busybox
        #[cfg(target_os = "android")]
        let _ = assets::ensure_binaries(false);

        println!("- Preparing assets");
        println!("- Unpacking boot image");
        let boot_image_data = map_file(&boot_image_file)?;
        let boot_image = if ramdisk {
            BootImage::parse_raw_ramdisk(&boot_image_data)?
        } else {
            BootImage::parse(&boot_image_data)?
        };
        enforce_bootimage_version(&boot_image)?;

        let mut patcher = BootImagePatchOption::new(&boot_image);

        if let Some(cmdline_value) = &cmdline {
            patcher.override_cmdline(cmdline_value.as_bytes());
            println!("- Set cmdline to: {cmdline_value}");
        }

        if let Some(kernel_path) = kernel {
            println!("- Adding Kernel");
            let kernel_data = map_file(&kernel_path)?;
            patcher.replace_kernel(Box::new(Cursor::new(kernel_data)), false);
        }

        let kernelsu_ko: Box<dyn AsRef<[u8]>> = if no_install {
            Box::new(Vec::<u8>::new())
        } else if let Some(kmod_path) = kmod {
            Box::new(map_file(&kmod_path)?)
        } else {
            #[cfg(target_os = "android")]
            {
                println!("- KMI: {kmi}");
                let name = format!("{kmi}_kernelsu.ko");
                assets::get_asset(&name).with_context(|| format!("Failed to load {name}"))?
            }
            #[cfg(not(target_os = "android"))]
            {
                println!("- KMI: {kmi}");
                println!("- Arch: {arch}");
                let name = format!("{arch}/{kmi}_kernelsu.ko");
                assets::get_asset(&name).with_context(|| format!("Failed to load {name}"))?
            }
        };

        let ksu_init: Box<dyn AsRef<[u8]>> = if no_install {
            Box::new(Vec::<u8>::new())
        } else if let Some(init_path) = init {
            Box::new(map_file(&init_path)?)
        } else {
            #[cfg(not(target_os = "android"))]
            {
                assets::get_asset(&format!("{arch}/ksuinit")).context("Failed to load ksuinit")?
            }
            #[cfg(target_os = "android")]
            {
                assets::get_asset("ksuinit").context("Failed to load ksuinit")?
            }
        };

        let source_without_ramdisk = boot_image.get_blocks().get_ramdisk().is_none();
        let (mut cpio, vendor_ramdisk_idx) =
            if let Some(ramdisk_image) = boot_image.get_blocks().get_ramdisk() {
                extract_ramdisk(ramdisk_image)?
            } else {
                println!("- No ramdisk, create by default");
                (Cpio::new(), None)
            };

        crate::vr_bootstrap::remove(&mut cpio)?;

        // 刷写前备份的落盘路径（B1/B3）：校验失败时要拿它回滚
        #[cfg(target_os = "android")]
        let mut flash_backup: Option<PathBuf> = None;

        if !no_install {
            ensure!(
                !cpio.is_magisk_patched(),
                "Cannot work with Magisk patched image"
            );

            println!("- Adding KernelSU LKM");
            // W18b（0007b）：先按 ramdisk 布局定性，再决定 init 处置与刷写闸。
            let ramdisk_state = RamdiskState::of(&cpio);
            println!("- Ramdisk state: {}", ramdisk_state.as_str());

            // 写分区的唯一闸：Foreign 布局（畸形 / 别的 root 方案）拒绝刷写；
            // 离线打补丁到文件仍然允许（那是安全退路）。
            #[cfg(target_os = "android")]
            if flash && ramdisk_state == RamdiskState::Foreign {
                bail!(
                    "the target boot image was patched by an INCOMPATIBLE root solution, so\n\
                     writing it has been refused (Foreign layout: `kernelsu.ko` without `init.real`,\n\
                     or another root solution's `init.real`). NOTHING was written; the partition is untouched.\n\
                     Patch the STOCK boot/init_boot image to a FILE instead (ksud boot-patch -b <stock> -o <dir>),\n\
                     then flash that file yourself; or restore the stock image first."
                );
            }

            match init_disposition(ramdisk_state) {
                InitDisposition::MoveInitToReal => {
                    if cpio.exists("init") {
                        cpio.mv("init", "init.real")?;
                    }
                }
                InitDisposition::KeepInitReal => {
                    // 真 init 已经在 init.real 里：一个字节都不碰（挪了就是死循环）
                }
            }

            cpio.add("init", CpioEntry::regular(0o755, ksu_init))?;
            // 官方名条目（给官方 KernelSU 看的"已打过补丁"标记；内容是真模块）
            cpio.add(OFFICIAL_KSU_ENTRY, CpioEntry::regular(0o755, kernelsu_ko))?;
            // 我们的归属标记（0 字节判据；内容 uapi=7 便于诊断）
            cpio.add(
                OURS_MARKER_ENTRY,
                CpioEntry::regular(0o644, Box::new(OURS_MARKER_CONTENT.to_vec())),
            )?;

            // B1/B3：刷写前备份；只有原厂态才登记 stock_image.sha1
            #[cfg(target_os = "android")]
            {
                let record_stock = should_record_stock(ramdisk_state, backup);
                if backup || flash {
                    match do_backup(&mut cpio, &boot_image_file, record_stock) {
                        Ok(path) => flash_backup = Some(path),
                        Err(e) => {
                            println!("- Backup stock image failed: {e:?}");
                        }
                    }
                }
            }
        }

        let mut ksu_config: Vec<String> = cpio
            .entry_by_name("ksu_config")
            .and_then(CpioEntry::data)
            .and_then(|v| str::from_utf8(v).ok())
            .map_or_else(Vec::new, |v| {
                v.split(' ').map(std::borrow::ToOwned::to_owned).collect()
            });

        config.validate()?;
        config.apply(&mut ksu_config);
        if !no_install && source_without_ramdisk {
            ksu_config.retain(|v| !v.starts_with("maplesu_original_ramdisk="));
            ksu_config.push("maplesu_original_ramdisk=empty-v1".to_owned());
        }
        if let Some(bundled) = bundled_lkm {
            set_config_flag(&mut ksu_config, "bundled LKM", "bundled=1", bundled);
        }

        if ksu_config.is_empty() {
            cpio.rm("ksu_config", false);
        } else {
            let data = ksu_config.join(" ").into_bytes();
            cpio.add("ksu_config", CpioEntry::regular(0o644, Box::new(data)))?;
        }

        // remove legacy config file
        cpio.rm("allow_shell", false);

        if enable_adbd || adb_debug_prop.is_some() {
            println!("- Adding adb_debug props");
            cpio.add(
                "force_debuggable",
                CpioEntry::regular(0o644, Box::new(Vec::<u8>::new())),
            )?;

            let mut prop = Vec::<u8>::new();
            if enable_adbd {
                println!("- Adding props to enable adbd");
                prop.extend_from_slice(
                    b"ro.debuggable=1\nro.force.debuggable=1\nro.adb.secure=0\n",
                );
            }
            if let Some(extra) = adb_debug_prop {
                println!("- Adding custom props");
                prop.extend_from_slice(extra.as_bytes());
            }
            cpio.add("adb_debug.prop", CpioEntry::regular(0o644, Box::new(prop)))?;
        } else {
            if cpio.exists("force_debuggable") {
                println!("- Removing /force_debuggable");
                cpio.rm("force_debuggable", false);
            }
            if cpio.exists("adb_debug.prop") {
                println!("- Removing /adb_debug.prop");
                cpio.rm("adb_debug.prop", false);
            }
        }

        let mut new_cpio = Vec::<u8>::new();
        cpio.dump(&mut new_cpio)?;

        if let Some(idx) = vendor_ramdisk_idx {
            patcher.replace_vendor_ramdisk(idx, Box::new(Cursor::new(new_cpio)), false);
        } else {
            patcher.replace_ramdisk(Box::new(Cursor::new(new_cpio)), false);
        }

        println!("- Repacking boot image");
        let mut new_boot_buf = Cursor::new(Vec::<u8>::with_capacity(boot_image.get_size()));
        patcher.patch(&mut new_boot_buf)?;
        let new_boot_bytes = new_boot_buf.into_inner();

        // Free the source mmap so the boot partition is no longer mapped read-only,
        // otherwise some kernels reject the subsequent write.
        drop(boot_image);
        drop(boot_image_data);

        #[cfg(target_os = "android")]
        if flash {
            println!("- Flashing new boot image");
            let bootdevice = boot_image_file.display().to_string();
            flash_partition(&bootdevice, &new_boot_bytes, flash_backup.as_deref())?;
            if ota {
                post_ota()?;
            }
        }

        #[cfg(target_os = "android")]
        let should_write_output = patch_file || !flash || out_name.is_some() || out.is_some();
        #[cfg(not(target_os = "android"))]
        let should_write_output = true;

        if should_write_output {
            let output_dir = out.unwrap_or(std::env::current_dir()?);
            let name = out_name.unwrap_or_else(|| {
                let now = chrono::Utc::now();
                format!("kernelsu_patched_{}.img", now.format("%Y%m%d_%H%M%S"))
            });
            let output_image = output_dir.join(name);
            std::fs::write(&output_image, &new_boot_bytes).context("write out new boot failed")?;
            println!("- Output file is written to");
            println!("- {}", output_image.display().to_string().trim_matches('"'));
        }

        println!("- Done!");
        Ok(())
    };

    let result = inner();
    if let Err(ref e) = result {
        println!("- Patch Error: {e}");
    }
    result
}

#[derive(clap::Args, Debug)]
pub struct BootRestoreArgs {
    /// Rebuild only the explicit input copy, without device state or backups.
    #[arg(long, default_value_t = false)]
    pub file_only: bool,

    /// boot image path, if not specified, will try to find the boot image automatically
    #[arg(short, long)]
    pub boot: Option<PathBuf>,

    /// Flash it to boot partition after restore
    #[cfg(target_os = "android")]
    #[arg(short, long, default_value = "false")]
    pub flash: bool,

    /// Output path. If not specified, will use current directory.
    /// If specified, the boot image will be written to the directory
    /// even if --flash is specified.
    #[cfg(target_os = "android")]
    #[arg(short, long, default_value = None)]
    pub out: Option<PathBuf>,

    /// Output path. If not specified, will use current directory.
    #[cfg(not(target_os = "android"))]
    #[arg(short, long, default_value = None)]
    pub out: Option<PathBuf>,

    /// File name of the output. If specified, the boot image will be
    /// written to the output directory even if --flash is specified.
    #[cfg(target_os = "android")]
    #[arg(long, default_value = None)]
    pub out_name: Option<String>,

    /// File name of the output.
    #[cfg(not(target_os = "android"))]
    #[arg(long, default_value = None)]
    pub out_name: Option<String>,
}

pub fn restore(args: BootRestoreArgs) -> Result<()> {
    if args.file_only {
        return restore_file_copy(&args);
    }
    let BootRestoreArgs {
        file_only: _,
        boot: image,
        out_name,
        out,
        #[cfg(target_os = "android")]
        flash,
    } = args;

    #[cfg(target_os = "android")]
    let kmi = get_current_kmi().unwrap_or_default();

    #[cfg(target_os = "android")]
    let image_supplied = image.is_some();

    let boot_image_file = if let Some(image) = image {
        ensure!(image.exists(), "boot image not found");
        std::fs::canonicalize(image)?
    } else {
        #[cfg(target_os = "android")]
        {
            auto_boot_partition_path(&kmi, false, false, &None)
        }
        #[cfg(not(target_os = "android"))]
        {
            bail!("Please specify a boot image");
        }
    };

    #[cfg(target_os = "android")]
    println!("- Bootdevice: {}", boot_image_file.display());

    println!("- Unpacking boot image");
    let bootimage_data = map_file(&boot_image_file)?;
    let boot_image = BootImage::parse(&bootimage_data)?;
    enforce_bootimage_version(&boot_image)?;

    let (mut cpio, vendor_ramdisk_idx) =
        if let Some(ramdisk_image) = boot_image.get_blocks().get_ramdisk() {
            extract_ramdisk(ramdisk_image)?
        } else {
            bail!("No compatible ramdisk found.")
        };

    // W18b（0007b）：还原准入 —— 只有 Ours/Compatible 可还原；Foreign 一律拒绝
    // （fail-closed；7K 的 --force-foreign 逃生口未移植，见 manifest.todos）。
    let ramdisk_state = RamdiskState::of(&cpio);
    restore_admission(ramdisk_state)?;

    #[cfg(target_os = "android")]
    let mut stock_boot: Option<PathBuf> = None;

    #[cfg(target_os = "android")]
    if let Some(backup_file) = cpio.entry_by_name(BACKUP_FILENAME) {
        let sha = String::from_utf8(backup_file.data().unwrap_or_default().to_vec())?;
        let sha = sha.trim();
        let backup_path =
            PathBuf::from(KSU_BACKUP_DIR).join(format!("{KSU_BACKUP_FILE_PREFIX}{sha}"));
        if backup_path.is_file() {
            println!("- Using backup file {}", backup_path.display());
            stock_boot = Some(backup_path);
        } else {
            println!("- Warning: no backup {} found!", backup_path.display());
        }
        if let Err(e) = clean_backup(sha) {
            println!("- Warning: Cleanup backup image failed: {e}");
        }
    } else {
        println!("- Backup info is absent!");
    }

    #[cfg(target_os = "android")]
    let mut stock_source: Option<PathBuf> = None;

    let new_boot_bytes: Vec<u8> = {
        #[cfg(target_os = "android")]
        {
            if let Some(stock_path) = stock_boot {
                let bytes = std::fs::read(&stock_path)
                    .with_context(|| format!("read stock boot {}", stock_path.display()))?;
                stock_source = Some(stock_path);
                bytes
            } else {
                rebuild_without_ksu(&boot_image, &mut cpio, vendor_ramdisk_idx)?
            }
        }
        #[cfg(not(target_os = "android"))]
        {
            rebuild_without_ksu(&boot_image, &mut cpio, vendor_ramdisk_idx)?
        }
    };

    drop(boot_image);
    drop(bootimage_data);

    #[cfg(target_os = "android")]
    if flash {
        if let Some(ref source) = stock_source {
            println!("- Flashing new boot image from {}", source.display());
        } else {
            println!("- Flashing new boot image");
        }
        let bootdevice = boot_image_file.display().to_string();
        // 从原厂备份刷回时，备份本身就是回滚源；否则没有备份（明确提示勿重启）
        flash_partition(&bootdevice, &new_boot_bytes, stock_source.as_deref())?;
    }

    #[cfg(target_os = "android")]
    let should_write_output = image_supplied || !flash || out_name.is_some() || out.is_some();
    #[cfg(not(target_os = "android"))]
    let should_write_output = true;

    if should_write_output {
        let output_dir = out.unwrap_or(std::env::current_dir()?);
        let name = out_name.unwrap_or_else(|| {
            let now = chrono::Utc::now();
            format!("kernelsu_restore_{}.img", now.format("%Y%m%d_%H%M%S"))
        });
        let output_image = output_dir.join(name);
        std::fs::write(&output_image, &new_boot_bytes).context("copy out new boot failed")?;
        println!("- Output file is written to");
        println!("- {}", output_image.display().to_string().trim_matches('"'));
    }

    println!("- Done!");
    Ok(())
}


/// Rebuild an explicit image copy without consulting device state or backups.
fn restore_file_copy(args: &BootRestoreArgs) -> Result<()> {
    use std::io::Write;

    #[cfg(target_os = "android")]
    ensure!(!args.flash, "--file-only cannot be combined with --flash");
    let input = args.boot.as_deref().context("--file-only requires --boot")?;
    ensure!(std::fs::symlink_metadata(input)?.is_file(), "--boot must be a regular file copy");
    let directory = args.out.as_deref().context("--file-only requires --out")?;
    ensure!(directory.is_dir(), "output directory does not exist");
    let name = args.out_name.as_deref().context("--file-only requires --out-name")?;
    ensure!(
        !name.is_empty() && name != "." && name != ".."
            && !name.contains(['/', '\\'])
            && Path::new(name).file_name().and_then(|v| v.to_str()) == Some(name),
        "--out-name must be a file name"
    );
    let output = directory.join(name);

    println!("- Rebuilding boot image copy: {}", input.display());
    let data = map_file(input)?;
    let image = BootImage::parse(&data)?;
    enforce_bootimage_version(&image)?;
    let ramdisk = image.get_blocks().get_ramdisk().context("No compatible ramdisk found")?;
    let (mut cpio, vendor_idx) = extract_ramdisk(ramdisk)?;
    restore_admission(RamdiskState::of(&cpio))?;
    let rebuilt = rebuild_without_ksu(&image, &mut cpio, vendor_idx)?;

    let mut file = std::fs::OpenOptions::new().write(true).create_new(true)
        .open(&output).context("create rebuilt boot copy")?;
    let written = file.write_all(&rebuilt).and_then(|()| file.sync_all());
    drop(file);
    if let Err(error) = written {
        let _ = std::fs::remove_file(&output);
        return Err(error).context("write rebuilt boot copy");
    }
    println!("- Output file: {}", output.display());
    println!("- Done!");
    Ok(())
}


/// A creation marker covers the installed KSU shape, not arbitrary later files.
fn owned_empty_ramdisk_origin(cpio: &Cpio) -> bool {
    if cpio.exists("init.real") || crate::vr_bootstrap::present(cpio)
        || cpio.entry_by_name(OURS_MARKER_ENTRY).and_then(CpioEntry::data)
            != Some(OURS_MARKER_CONTENT)
        || !["init", OFFICIAL_KSU_ENTRY].iter().all(|name| {
            cpio.entry_by_name(name).and_then(CpioEntry::data)
                .map(|data| !data.is_empty()).unwrap_or(false)
        })
    {
        return false;
    }
    let Some(config) = cpio.entry_by_name("ksu_config").and_then(CpioEntry::data)
        .and_then(|data| std::str::from_utf8(data).ok()) else {
        return false;
    };
    let mut origins = config.split_ascii_whitespace()
        .filter(|value| value.starts_with("maplesu_original_ramdisk="));
    origins.next() == Some("maplesu_original_ramdisk=empty-v1") && origins.next().is_none()
}

fn rebuild_without_ksu(
    boot_image: &BootImage<'_>,
    cpio: &mut Cpio,
    vendor_ramdisk_idx: Option<usize>,
) -> Result<Vec<u8>> {
    println!("- Removing KernelSU from boot image");
    let restore_empty = owned_empty_ramdisk_origin(cpio);
    ensure!(restore_empty || cpio.exists("init.real") || crate::vr_bootstrap::present(cpio),
        "original init is absent; use the original boot image");
    if restore_empty {
        ensure!(vendor_ramdisk_idx.is_none() && matches!(
            boot_image.get_header().get_version(), BootImageVersion::Android(0..=4)),
            "EMPTY_RAMDISK_CONTAINER_UNSUPPORTED");
        ensure!(cpio.entries().keys().all(|name| matches!(name.as_str(),
            "init" | "kernelsu.ko" | "maplesu_id" | "ksu_config" |
            "stock_image.sha1" | "force_debuggable" | "adb_debug.prop")),
            "EMPTY_RAMDISK_CONTENT_CONFLICT");
    }
    crate::vr_bootstrap::remove(cpio)?;
    // W18b（0007b）：同时清掉我们的归属标记与官方名条目
    cpio.rm(OURS_MARKER_ENTRY, false);
    cpio.rm(OFFICIAL_KSU_ENTRY, false);
    cpio.rm("ksu_config", false);
    cpio.rm("stock_image.sha1", false);
    if cpio.exists("init.real") {
        cpio.mv("init.real", "init")?;
    }

    let mut new_cpio = Vec::<u8>::new();
    if !restore_empty { cpio.dump(&mut new_cpio)?; }

    println!("- Repacking boot image");
    let mut patcher = BootImagePatchOption::new(boot_image);
    if let Some(idx) = vendor_ramdisk_idx {
        patcher.replace_vendor_ramdisk(idx, Box::new(Cursor::new(new_cpio)), false);
    } else {
        // Already encoded empty input writes zero bytes, not a compressed empty CPIO.
        patcher.replace_ramdisk(Box::new(Cursor::new(new_cpio)), restore_empty);
    }

    let mut buf = Cursor::new(Vec::<u8>::with_capacity(boot_image.get_size()));
    patcher.patch(&mut buf)?;
    Ok(buf.into_inner())
}

#[cfg(test)]
mod block_modules_tests {
    use super::*;

    #[test]
    fn parse_block_module_accepts_valid_names() {
        assert_eq!(
            parse_block_module("oplus_secure_guard").unwrap(),
            "oplus_secure_guard"
        );
        assert_eq!(parse_block_module("vr").unwrap(), "vr");
        assert_eq!(parse_block_module("mkp0").unwrap(), "mkp0");
    }

    #[test]
    fn parse_block_module_rejects_invalid_names() {
        assert!(parse_block_module("").is_err());
        assert!(parse_block_module("bad-name").is_err());
        assert!(parse_block_module("a b").is_err());
        assert!(parse_block_module(&"a".repeat(65)).is_err());
    }

    #[test]
    fn apply_writes_and_clears_block_modules() {
        let args = KsuConfigArgs {
            block_module: vec!["vr".to_owned(), "vklp".to_owned()],
            ..Default::default()
        };
        // Unrelated entries are preserved; apply() only owns the keys it manages.
        let mut config = vec!["bundled=1".to_owned()];
        args.apply(&mut config);
        assert!(config.contains(&"block_modules=vr,vklp".to_owned()));
        assert!(config.contains(&"bundled=1".to_owned()));

        // Omitting the option removes a previously written entry.
        let empty = KsuConfigArgs::default();
        empty.apply(&mut config);
        assert!(!config.iter().any(|v| v.starts_with("block_modules=")));
    }

    #[test]
    fn apply_replaces_existing_block_modules() {
        let args = KsuConfigArgs {
            block_module: vec!["vr".to_owned()],
            ..Default::default()
        };
        let mut config = vec!["block_modules=old,stale".to_owned()];
        args.apply(&mut config);
        assert_eq!(
            config
                .iter()
                .filter(|v| v.starts_with("block_modules="))
                .count(),
            1
        );
        assert!(config.contains(&"block_modules=vr".to_owned()));
    }

    #[test]
    fn apply_keeps_sibling_keys_with_shared_prefix() {
        // A key that merely starts with "block_modules" but is not the exact
        // "block_modules=" entry must not be dropped by retain().
        let args = KsuConfigArgs {
            block_module: vec!["vr".to_owned()],
            ..Default::default()
        };
        let mut config = vec!["block_modules_foo=1".to_owned()];
        args.apply(&mut config);
        assert!(config.contains(&"block_modules_foo=1".to_owned()));
        assert!(config.contains(&"block_modules=vr".to_owned()));
    }

    #[test]
    fn validate_rejects_overlong_list() {
        // Many valid names whose joined length exceeds the kernel's 255-byte
        // value budget must be rejected rather than silently truncated.
        let names: Vec<String> = (0..30).map(|i| format!("module_name_{i:03}")).collect();
        assert!(names.join(",").len() > MAX_BLOCK_MODULES_LEN);
        let args = KsuConfigArgs {
            block_module: names,
            ..Default::default()
        };
        assert!(args.validate().is_err());

        // A short list is accepted.
        let ok = KsuConfigArgs {
            block_module: vec!["vr".to_owned(), "mkp".to_owned()],
            ..Default::default()
        };
        assert!(ok.validate().is_ok());
        assert!(KsuConfigArgs::default().validate().is_ok());
    }

    #[test]
    fn restore_removes_ultra_companion_and_preserves_both_init_types() {
        for symlink in [false, true] {
            let mut stock = Cpio::new();
            let init = if symlink { CpioEntry::symlink(0o777, "system/bin/init") } else {
                CpioEntry::regular(0o750, Box::new(b"ORIGINAL_INIT".to_vec()))
            };
            stock.add("init", init).unwrap();
            let mut ramdisk = Vec::new();
            stock.dump(&mut ramdisk).unwrap();
            let mut source = vec![0u8; 4096];
            source[..8].copy_from_slice(b"ANDROID!");
            source[12..16].copy_from_slice(&(ramdisk.len() as u32).to_le_bytes());
            source[20..24].copy_from_slice(&1580u32.to_le_bytes());
            source[40..44].copy_from_slice(&3u32.to_le_bytes());
            source.extend_from_slice(&ramdisk);
            source.resize(131072, 0);
            let patched = crate::vr_bootstrap::patch_image(&source, b"\x7fELFshim", b"\x7fELFmodule").unwrap();
            let image = BootImage::parse(&patched).unwrap();
            let mut raw = Vec::new();
            image.get_blocks().get_ramdisk().unwrap().dump(&mut raw, false).unwrap();
            let mut cpio = Cpio::load_from_data(&raw).unwrap();
            let restored = rebuild_without_ksu(&image, &mut cpio, None).unwrap();
            assert_eq!(RamdiskState::of(&cpio), RamdiskState::Stock);
            assert!(!cpio.exists(".maplesu_vr"));
            assert_eq!(cpio.entry_by_name("init").unwrap().data(), stock.entry_by_name("init").unwrap().data());
            let output = BootImage::parse(&restored).unwrap();
            raw.clear();
            output.get_blocks().get_ramdisk().unwrap().dump(&mut raw, false).unwrap();
            assert!(!Cpio::load_from_data(&raw).unwrap().exists(".maplesu_vr"));
        }
    }


    fn copy_test_image(cpio: &Cpio, version: u32) -> Vec<u8> {
        let mut ramdisk = Vec::new();
        cpio.dump(&mut ramdisk).unwrap();
        let mut image = vec![0u8; 4096];
        image[..8].copy_from_slice(b"ANDROID!");
        image[12..16].copy_from_slice(&(ramdisk.len() as u32).to_le_bytes());
        image[20..24].copy_from_slice(&(if version == 4 { 1584u32 } else { 1580u32 }).to_le_bytes());
        image[40..44].copy_from_slice(&version.to_le_bytes());
        image.extend_from_slice(&ramdisk);
        image.resize(131072, 0);
        image
    }

    fn copy_test_args(input: &Path, output: &Path, name: &str) -> BootRestoreArgs {
        BootRestoreArgs {
            file_only: true, boot: Some(input.to_owned()),
            out: Some(output.to_owned()), out_name: Some(name.to_owned()),
            #[cfg(target_os = "android")]
            flash: false,
        }
    }

    #[test]
    fn copy_restore_preserves_original_init_unknown_files_and_input() {
        for version in [3, 4] {
            for symlink in [false, true] {
                let mut cpio = Cpio::new();
                let init = if symlink { CpioEntry::symlink(0o777, "system/bin/init") } else {
                    CpioEntry::regular(0o750, Box::new(b"ORIGINAL_INIT".to_vec()))
                };
                cpio.add("init.real", init).unwrap();
                cpio.add("init", CpioEntry::regular(0o755, Box::new(b"KSU_INIT".to_vec()))).unwrap();
                cpio.add(OFFICIAL_KSU_ENTRY, CpioEntry::regular(0o755, Box::new(vec![1]))).unwrap();
                cpio.add(OURS_MARKER_ENTRY, CpioEntry::regular(0o644, Box::new(OURS_MARKER_CONTENT.to_vec()))).unwrap();
                for name in ["ksu_config", "stock_image.sha1", "force_debuggable", "vendor_file"] {
                    cpio.add(name, CpioEntry::regular(0o640, Box::new(b"KEEP_OR_CONFIG".to_vec()))).unwrap();
                }
                let mut before = Vec::new();
                cpio.dump(&mut before).unwrap();
                let mut expected = Cpio::load_from_data(&before).unwrap();
                expected.mv("init.real", "init").unwrap();
                for name in [OFFICIAL_KSU_ENTRY, OURS_MARKER_ENTRY, "ksu_config", "stock_image.sha1"] {
                    expected.rm(name, false);
                }
                let mut expected_bytes = Vec::new();
                expected.dump(&mut expected_bytes).unwrap();
                // Round-trip checks the original init entry's complete CPIO metadata.

                let temp = tempfile::tempdir().unwrap();
                let input = temp.path().join("input.img");
                let bytes = copy_test_image(&cpio, version);
                std::fs::write(&input, &bytes).unwrap();
                restore(copy_test_args(&input, temp.path(), "rebuilt.img")).unwrap();
                assert_eq!(std::fs::read(&input).unwrap(), bytes);
                let result = std::fs::read(temp.path().join("rebuilt.img")).unwrap();
                let image = BootImage::parse(&result).unwrap();
                let (restored, _) = extract_ramdisk(image.get_blocks().get_ramdisk().unwrap()).unwrap();
                let mut actual = Vec::new();
                restored.dump(&mut actual).unwrap();
                assert_eq!(actual, expected_bytes);
                assert!(restored.exists("force_debuggable") && restored.exists("vendor_file"));
            }
        }
    }

    #[test]
    fn copy_restore_requires_explicit_files_and_preserves_existing_output() {
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("input.img");
        let mut cpio = Cpio::new();
        cpio.add("init.real", CpioEntry::regular(0o750, Box::new(vec![2]))).unwrap();
        cpio.add(OFFICIAL_KSU_ENTRY, CpioEntry::regular(0o755, Box::new(vec![1]))).unwrap();
        let bytes = copy_test_image(&cpio, 4);
        std::fs::write(&input, &bytes).unwrap();
        for name in ["input.img", ".", "..", "../outside.img", "sub/out.img", "sub\\out.img", ""] {
            assert!(restore(copy_test_args(&input, temp.path(), name)).is_err(), "{name}");
        }
        assert_eq!(std::fs::read(&input).unwrap(), bytes);
        let existing = temp.path().join("existing.img");
        std::fs::write(&existing, b"KEEP").unwrap();
        assert!(restore(copy_test_args(&input, temp.path(), "existing.img")).is_err());
        assert_eq!(std::fs::read(existing).unwrap(), b"KEEP");
        std::fs::hard_link(&input, temp.path().join("linked.img")).unwrap();
        assert!(restore(copy_test_args(&input, temp.path(), "linked.img")).is_err());
        assert_eq!(std::fs::read(&input).unwrap(), bytes);
        let mut args = copy_test_args(&input, temp.path(), "out.img");
        args.boot = None;
        assert!(restore(args).is_err());
        let mut args = copy_test_args(&input, temp.path(), "out.img");
        args.out = None;
        assert!(restore(args).is_err());
        let mut args = copy_test_args(&input, temp.path(), "out.img");
        args.out_name = None;
        assert!(restore(args).is_err());
        assert!(restore(copy_test_args(temp.path(), temp.path(), "out.img")).is_err());
        assert!(!temp.path().join("out.img").exists());
    }

    #[test]
    fn copy_restore_never_leaves_ksu_init_without_its_module() {
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("input.img");
        let mut cpio = Cpio::new();
        for name in ["init", OFFICIAL_KSU_ENTRY, OURS_MARKER_ENTRY] {
            cpio.add(name, CpioEntry::regular(0o755, Box::new(vec![1]))).unwrap();
        }
        let bytes = copy_test_image(&cpio, 4);
        std::fs::write(&input, &bytes).unwrap();
        assert!(restore(copy_test_args(&input, temp.path(), "out.img")).is_err());
        assert!(!temp.path().join("out.img").exists());
        assert_eq!(std::fs::read(&input).unwrap(), bytes);
    }

    #[cfg(not(target_os = "android"))]
    #[test]
    fn empty_ramdisk_provenance_is_written_once_and_survives_repatch() {
        use clap::Parser;
        #[derive(Parser)]
        struct PatchCommand {
            #[command(flatten)]
            args: BootPatchArgs,
        }
        for empty in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let input = temp.path().join("input.img");
            let module = temp.path().join("module.ko");
            let init = temp.path().join("ksuinit");
            let mut cpio = Cpio::new();
            if !empty {
                cpio.add("init", CpioEntry::regular(0o750, Box::new(b"ORIGINAL_INIT".to_vec()))).unwrap();
            }
            let mut bytes = copy_test_image(&cpio, 4);
            if empty { bytes[12..16].fill(0); }
            std::fs::write(&input, &bytes).unwrap();
            std::fs::write(&module, b"TEST_MODULE").unwrap();
            std::fs::write(&init, b"TEST_KSUINIT").unwrap();
            let mut source = input.clone();
            for name in ["first.img", "second.img", "third.img"] {
                let args = PatchCommand::parse_from([
                    "test", "--boot", source.to_str().unwrap(), "--module", module.to_str().unwrap(),
                    "--init", init.to_str().unwrap(), "--out", temp.path().to_str().unwrap(),
                    "--out-name", name, "--allow-shell",
                ]).args;
                patch(args).unwrap();
                source = temp.path().join(name);
                let patched = std::fs::read(&source).unwrap();
                let image = BootImage::parse(&patched).unwrap();
                let (cpio, _) = extract_ramdisk(image.get_blocks().get_ramdisk().unwrap()).unwrap();
                let config = cpio.entry_by_name("ksu_config").and_then(CpioEntry::data).unwrap();
                let entries: Vec<_> = std::str::from_utf8(config).unwrap().split(' ')
                    .filter(|entry| entry.starts_with("maplesu_original_ramdisk=")).collect();
                assert_eq!(entries, if empty { vec!["maplesu_original_ramdisk=empty-v1"] } else { vec![] });
                assert_eq!(cpio.exists("init.real"), !empty);
                if !empty {
                    assert_eq!(cpio.entry_by_name("init.real").and_then(CpioEntry::data).unwrap(), b"ORIGINAL_INIT");
                }
            }
            assert_eq!(std::fs::read(input).unwrap(), bytes);
        }
    }


    fn empty_origin_archive() -> Cpio {
        let mut cpio = Cpio::new();
        for (name, data) in [
            ("init", b"KSU_INIT".as_slice()),
            (OFFICIAL_KSU_ENTRY, b"KSU_MODULE".as_slice()),
            (OURS_MARKER_ENTRY, OURS_MARKER_CONTENT),
            ("ksu_config", b"allow_shell=1 maplesu_original_ramdisk=empty-v1".as_slice()),
            ("stock_image.sha1", b"0123456789012345678901234567890123456789".as_slice()),
            ("force_debuggable", b"".as_slice()),
            ("adb_debug.prop", b"ro.debuggable=1\n".as_slice()),
        ] {
            cpio.add(name, CpioEntry::regular(0o644, Box::new(data.to_vec()))).unwrap();
        }
        cpio
    }

    fn empty_origin_image(cpio: Option<&Cpio>, version: u32, kernel: bool) -> Vec<u8> {
        let mut ramdisk = Vec::new();
        if let Some(cpio) = cpio { cpio.dump(&mut ramdisk).unwrap(); }
        let mut bytes = vec![0u8; 4096];
        bytes[..8].copy_from_slice(b"ANDROID!");
        bytes[8..12].copy_from_slice(&(if kernel { 71u32 } else { 0u32 }).to_le_bytes());
        bytes[40..44].copy_from_slice(&version.to_le_bytes());
        if version < 3 {
            bytes[16..20].copy_from_slice(&(ramdisk.len() as u32).to_le_bytes());
            bytes[36..40].copy_from_slice(&4096u32.to_le_bytes());
            if version > 0 {
                bytes[1644..1648].copy_from_slice(&(if version == 1 { 1648u32 } else { 1660u32 }).to_le_bytes());
            }
        } else {
            bytes[12..16].copy_from_slice(&(ramdisk.len() as u32).to_le_bytes());
            bytes[20..24].copy_from_slice(&(if version == 4 { 1584u32 } else { 1580u32 }).to_le_bytes());
        }
        if kernel { bytes.resize(8192, 0); bytes[4096..4167].fill(0x42); }
        bytes.extend_from_slice(&ramdisk);
        bytes.resize(131072, 0);
        bytes
    }

    fn assert_empty_origin_output(source: &[u8], restored: &[u8]) {
        let source = BootImage::parse(source).unwrap();
        let result = BootImage::parse(restored).unwrap();
        assert!(result.get_blocks().get_ramdisk().is_none());
        assert_eq!(result.get_header().get_ramdisk_size(), 0);
        assert_eq!(source.get_blocks().get_kernel().map(|v| v.get_data()),
            result.get_blocks().get_kernel().map(|v| v.get_data()));
    }

    #[test]
    fn own_empty_origin_copy_restores_zero_ramdisk_and_preserves_kernel() {
        for version in 0..=4 {
            for kernel in [true, false] {
                let temp = tempfile::tempdir().unwrap();
                let input = temp.path().join("input.img");
                let source = empty_origin_image(Some(&empty_origin_archive()), version, kernel);
                std::fs::write(&input, &source).unwrap();
                restore(copy_test_args(&input, temp.path(), "restored.img")).unwrap();
                let output = std::fs::read(temp.path().join("restored.img")).unwrap();
                assert_empty_origin_output(&source, &output);
                assert_eq!(std::fs::read(&input).unwrap(), source);
            }
        }
    }

    #[test]
    fn empty_origin_unknown_entries_and_invalid_identity_never_clear_ramdisk() {
        for change in 0..10 {
            let mut cpio = empty_origin_archive();
            match change {
                0 => cpio.rm(OURS_MARKER_ENTRY, false),
                1 => cpio.add(OURS_MARKER_ENTRY, CpioEntry::regular(0o644, Box::new(b"FOREIGN".to_vec()))).unwrap(),
                2 => cpio.rm(OFFICIAL_KSU_ENTRY, false),
                3 => cpio.rm("init", false),
                4 => cpio.add("ksu_config", CpioEntry::regular(0o644, Box::new(b"allow_shell=1".to_vec()))).unwrap(),
                5 => cpio.add("ksu_config", CpioEntry::regular(0o644, Box::new(b"maplesu_original_ramdisk=future-v9".to_vec()))).unwrap(),
                6 => cpio.add("ksu_config", CpioEntry::regular(0o644, Box::new(
                    b"maplesu_original_ramdisk=empty-v1 maplesu_original_ramdisk=empty-v1".to_vec()))).unwrap(),
                7 => cpio.add("fstab.foreign", CpioEntry::regular(0o640, Box::new(b"KEEP".to_vec()))).unwrap(),
                8 => cpio.add(".backup/.magisk", CpioEntry::regular(0o600, Box::new(b"KEEP".to_vec()))).unwrap(),
                _ => cpio.add("sevenk.ko", CpioEntry::regular(0o600, Box::new(b"KEEP".to_vec()))).unwrap(),
            }
            let temp = tempfile::tempdir().unwrap();
            let input = temp.path().join("input.img");
            let source = empty_origin_image(Some(&cpio), 4, true);
            std::fs::write(&input, &source).unwrap();
            let error = restore(copy_test_args(&input, temp.path(), "restored.img")).unwrap_err();
            if change >= 7 { assert!(format!("{error:#}").contains("EMPTY_RAMDISK_CONTENT_CONFLICT")); }
            assert!(!temp.path().join("restored.img").exists());
            assert_eq!(std::fs::read(&input).unwrap(), source);
        }
    }

    #[test]
    fn empty_origin_does_not_override_original_init_or_vr() {
        for vr in [false, true] {
            let mut cpio = empty_origin_archive();
            if vr {
                cpio.add(".maplesu_vr", CpioEntry::dir(0o700)).unwrap();
                cpio.add(".maplesu_vr/id", CpioEntry::regular(0o600,
                    Box::new(b"MAPLESU_VR_BOOTSTRAP_V1\n".to_vec()))).unwrap();
                cpio.add(".maplesu_vr/init.orig", CpioEntry::regular(0o750,
                    Box::new(b"ORIGINAL_INIT".to_vec()))).unwrap();
            } else {
                cpio.add("init.real", CpioEntry::regular(0o750, Box::new(b"ORIGINAL_INIT".to_vec()))).unwrap();
            }
            cpio.add("fstab.foreign", CpioEntry::regular(0o640, Box::new(b"KEEP".to_vec()))).unwrap();
            let source = empty_origin_image(Some(&cpio), 4, true);
            let image = BootImage::parse(&source).unwrap();
            assert!(!owned_empty_ramdisk_origin(&cpio));
            let bytes = rebuild_without_ksu(&image, &mut cpio, None).unwrap();
            let result = BootImage::parse(&bytes).unwrap();
            let (restored, _) = extract_ramdisk(result.get_blocks().get_ramdisk().unwrap()).unwrap();
            assert_eq!(restored.entry_by_name("init").and_then(CpioEntry::data), Some(b"ORIGINAL_INIT".as_slice()));
            assert_eq!(restored.entry_by_name("fstab.foreign").and_then(CpioEntry::data), Some(b"KEEP".as_slice()));
            assert!(!restored.exists(OURS_MARKER_ENTRY) && !restored.exists(OFFICIAL_KSU_ENTRY));
        }
    }

    #[cfg(not(target_os = "android"))]
    #[test]
    fn actual_empty_install_repatch_and_file_restore_share_one_origin() {
        use clap::Parser;
        #[derive(Parser)]
        struct PatchCommand { #[command(flatten)] args: BootPatchArgs }
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("input.img");
        let module = temp.path().join("module.ko");
        let init = temp.path().join("ksuinit");
        let original = empty_origin_image(None, 4, true);
        std::fs::write(&input, &original).unwrap();
        std::fs::write(&module, b"TEST_MODULE").unwrap();
        std::fs::write(&init, b"TEST_KSUINIT").unwrap();
        let mut source = input.clone();
        for generation in 0..3 {
            let name = format!("patched-{generation}.img");
            let args = PatchCommand::parse_from([
                "test", "--boot", source.to_str().unwrap(), "--module", module.to_str().unwrap(),
                "--init", init.to_str().unwrap(), "--out", temp.path().to_str().unwrap(),
                "--out-name", &name, "--allow-shell",
            ]).args;
            patch(args).unwrap();
            source = temp.path().join(name);
            let before = std::fs::read(&source).unwrap();
            let restored = format!("restored-{generation}.img");
            restore(copy_test_args(&source, temp.path(), &restored)).unwrap();
            assert_empty_origin_output(&before, &std::fs::read(temp.path().join(restored)).unwrap());
            assert_eq!(std::fs::read(&source).unwrap(), before);
        }
        assert_eq!(std::fs::read(&input).unwrap(), original);
    }


    #[cfg(not(target_os = "android"))]
    #[test]
    fn target_kernel_kmi_selection_uses_the_final_input() {
        use clap::Parser;
        #[derive(Parser)]
        struct PatchCommand { #[command(flatten)] args: BootPatchArgs }
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("target.img");
        let replacement = temp.path().join("replacement-kernel");
        let mut cpio = Cpio::new();
        cpio.add("init", CpioEntry::regular(0o750, Box::new(b"ORIGINAL_INIT".to_vec()))).unwrap();
        let mut original = copy_test_image(&cpio, 4);
        // An init_boot has no target kernel; its existing platform default remains valid.
        assert!(BootImage::parse(&original).unwrap().get_blocks().get_kernel().is_none());
        let kernel_bytes = |banner: &[u8]| {
            let mut bytes = vec![0u8; 4096];
            bytes[64..64 + banner.len()].copy_from_slice(banner);
            bytes
        };
        let kernel = kernel_bytes(b"Linux version 5.10.252-android13-4-gfixture\0");
        let replacement_kernel = kernel_bytes(b"Linux version 5.15.200-android14-7-gfixture\0");
        original[8..12].copy_from_slice(&4096u32.to_le_bytes());
        original.splice(4096..4096, kernel.iter().copied());
        std::fs::write(&input, &original).unwrap();
        std::fs::write(&replacement, &replacement_kernel).unwrap();
        for (name, extra, expected_kmi, expected_kernel) in [
            ("from-boot.img", vec![], "android13-5.10", &kernel),
            ("explicit.img", vec!["--kmi", "android15-6.6"], "android15-6.6", &kernel),
            ("replacement.img", vec!["--kernel", replacement.to_str().unwrap()], "android14-5.15", &replacement_kernel),
        ] {
            let mut argv = vec!["test", "--boot", input.to_str().unwrap(), "--arch", "aarch64",
                "--out", temp.path().to_str().unwrap(), "--out-name", name];
            argv.extend(extra);
            patch(PatchCommand::parse_from(argv).args).unwrap();
            let result = std::fs::read(temp.path().join(name)).unwrap();
            let image = BootImage::parse(&result).unwrap();
            let (result_cpio, _) = extract_ramdisk(image.get_blocks().get_ramdisk().unwrap()).unwrap();
            let module = assets::get_asset(&format!("aarch64/{expected_kmi}_kernelsu.ko")).unwrap();
            assert_eq!(result_cpio.entry_by_name(OFFICIAL_KSU_ENTRY).and_then(CpioEntry::data).unwrap(),
                module.as_ref().as_ref());
            assert_eq!(result_cpio.entry_by_name("init.real").and_then(CpioEntry::data).unwrap(), b"ORIGINAL_INIT");
            let mut result_kernel = Vec::new();
            image.get_blocks().get_kernel().unwrap().dump(&mut result_kernel, false).unwrap();
            assert_eq!(&result_kernel, expected_kernel);
        }
        assert_eq!(std::fs::read(&input).unwrap(), original);
        let mut unknown = original.clone();
        unknown[4096..8192].fill(0);
        std::fs::write(&input, &unknown).unwrap();
        let error = patch(PatchCommand::parse_from([
            "test", "--boot", input.to_str().unwrap(), "--arch", "aarch64",
            "--out", temp.path().to_str().unwrap(), "--out-name", "unparseable.img",
        ]).args).unwrap_err();
        assert_eq!(error.to_string(), "Try to choose LKM manually");
        assert!(!temp.path().join("unparseable.img").exists());
        assert_eq!(std::fs::read(&input).unwrap(), unknown);
    }
}
