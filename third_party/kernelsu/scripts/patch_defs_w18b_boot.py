#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""W18b 续：0012 = 0007b boot-patch 安全增强完整接线；0013 = 0008b restore-user-data 接线。

两个补丁都以 `.research/7kimisu` 的 pinned 源为参照（行号写在注释里），
但**必须**适配上游 528bafc 的代码形状（7K 的 boot_patch.rs 是结构性重写，
03 分册 §1.4 已记录 2252 行差异）。因此：
  · 纯判据/算法（四态、init 处置、备份登记、写后校验、回滚、准入）**逐字移植**；
  · 接线点按上游 patch()/restore() 的真实控制流插入，并用 rustfmt 做语法校验；
  · 与 7K 的有意差异逐条写进注释与 manifest blockers。
"""
from __future__ import annotations

import ksu_common as C

S7K_KS = "userspace/ksud/src"
UP_KS = "userspace/ksud/src"

# ---------------------------------------------------------------- 0012 片段
BOOT_HELPERS = r'''
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
        if cpio.exists(OURS_MARKER_ENTRY) {
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
'''

BOOT_IMPORTS_AND_DOBACKUP = r'''
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
'''

PATCH_INIT_BLOCK_OLD = """            println!("- Adding KernelSU LKM");
            let is_kernelsu_patched = cpio.exists("kernelsu.ko");

            if !is_kernelsu_patched && cpio.exists("init") {
                cpio.mv("init", "init.real")?;
            }

            cpio.add("init", CpioEntry::regular(0o755, ksu_init))?;
            cpio.add("kernelsu.ko", CpioEntry::regular(0o755, kernelsu_ko))?;

            #[cfg(target_os = "android")]
            if (backup || (!is_kernelsu_patched && flash))
                && let Err(e) = do_backup(&mut cpio, &boot_image_file)
            {
                println!("- Backup stock image failed: {e:?}");
            }
"""

PATCH_INIT_BLOCK_NEW = '''            println!("- Adding KernelSU LKM");
            // W18b（0007b）：先按 ramdisk 布局定性，再决定 init 处置与刷写闸。
            let ramdisk_state = RamdiskState::of(&cpio);
            println!("- Ramdisk state: {}", ramdisk_state.as_str());

            // 写分区的唯一闸：Foreign 布局（畸形 / 别的 root 方案）拒绝刷写；
            // 离线打补丁到文件仍然允许（那是安全退路）。
            #[cfg(target_os = "android")]
            if flash && ramdisk_state == RamdiskState::Foreign {
                bail!(
                    "the target boot image was patched by an INCOMPATIBLE root solution, so\\n\\
                     writing it has been refused (Foreign layout: `kernelsu.ko` without `init.real`,\\n\\
                     or another root solution's `init.real`). NOTHING was written; the partition is untouched.\\n\\
                     Patch the STOCK boot/init_boot image to a FILE instead (ksud boot-patch -b <stock> -o <dir>),\\n\\
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
                            if flash {
                                return Err(e).context(
                                    "backup before flash failed; refusing to write the partition",
                                );
                            }
                            println!("- Backup stock image failed: {e:?}");
                        }
                    }
                }
            }
'''


def patch_0012(tree, s7k) -> list[str]:
    """0007b：boot-patch 安全增强的完整接线（四态/init 处置/写后校验/回滚/准入）。"""
    boot = f"{UP_KS}/boot_patch.rs"
    # 1) 顶层判据/算法（移植块）
    # 注意：BootPatchArgs 前还有一行 `#[allow(clippy::struct_excessive_bools)]`（上游 528bafc）。
    tree.replace_once(
        boot,
        "    Ok(())\n}\n\n#[allow(clippy::struct_excessive_bools)]\n"
        "#[derive(clap::Args, Debug)]\npub struct BootPatchArgs {",
        "    Ok(())\n}\n\n" + BOOT_HELPERS +
        "\n#[allow(clippy::struct_excessive_bools)]\n"
        "#[derive(clap::Args, Debug)]\npub struct BootPatchArgs {",
    )
    # 2) android 子模块 imports：Read/Seek/SeekFrom + super 判据
    tree.replace_once(
        boot,
        "    use super::Result;\n"
        "    pub(super) use crate::defs::{BACKUP_FILENAME, KSU_BACKUP_DIR, KSU_BACKUP_FILE_PREFIX};",
        "    use super::Result;\n"
        "    use super::{FlashFailureAction, flash_failure_action, image_fits_partition};\n"
        "    pub(super) use crate::defs::{BACKUP_FILENAME, KSU_BACKUP_DIR, KSU_BACKUP_FILE_PREFIX};",
    )
    tree.replace_once(boot, "    use std::io::Write;\n", "    use std::io::{Read, Seek, SeekFrom, Write};\n")

    # 3) do_backup：替换为「回读校验 + 条件登记 + 返回路径」版本
    old_backup_start = "    pub(super) fn do_backup(cpio: &mut Cpio, image: &Path) -> Result<()> {"
    old_backup_end = "    pub(super) fn clean_backup(sha1: &str) -> Result<()> {"
    i = tree.read(boot).index(old_backup_start)
    j = tree.read(boot).index(old_backup_end, i)
    tree.write(boot, tree.read(boot)[:i] + BOOT_IMPORTS_AND_DOBACKUP.strip("\n") + "\n\n" + tree.read(boot)[j:])

    # 3b) 删除上游旧 flash_partition：新实现（长度闸+读回校验+回滚）已在移植块中
    text = tree.read(boot)
    old_flash_start = ("    pub(super) fn flash_partition(partition: &str, data: &[u8]) "
                       "-> Result<()> {")
    next_fn = "    pub fn choose_boot_partition("
    if old_flash_start in text:
        i = text.index(old_flash_start)
        j = text.index(next_fn, i)
        tree.write(boot, text[:i] + text[j:])

    # 4) patch()：备份路径变量 + 新 init/backup 块 + flash 调用带备份
    tree.replace_once(
        boot,
        "        if !no_install {\n            ensure!(\n                !cpio.is_magisk_patched(),\n",
        "        // 刷写前备份的落盘路径（B1/B3）：校验失败时要拿它回滚\n"
        "        #[cfg(target_os = \"android\")]\n"
        "        let mut flash_backup: Option<PathBuf> = None;\n\n"
        "        if !no_install {\n            ensure!(\n                !cpio.is_magisk_patched(),\n",
    )
    tree.replace_once(boot, PATCH_INIT_BLOCK_OLD, PATCH_INIT_BLOCK_NEW)
    tree.replace_once(
        boot,
        "            flash_partition(&bootdevice, &new_boot_bytes)?;",
        "            flash_partition(&bootdevice, &new_boot_bytes, flash_backup.as_deref())?;",
    )

    # 5) restore()：准入判据 + 带备份刷写 + 重建时清标记
    tree.replace_once(
        boot,
        '    ensure!(\n        cpio.exists("kernelsu.ko"),\n'
        '        "boot image is not patched by KernelSU"\n    );\n',
        "    // W18b（0007b）：还原准入 —— 只有 Ours/Compatible 可还原；Foreign 一律拒绝\n"
        "    // （fail-closed；7K 的 --force-foreign 逃生口未移植，见 manifest.todos）。\n"
        "    let ramdisk_state = RamdiskState::of(&cpio);\n"
        "    restore_admission(ramdisk_state)?;\n",
    )
    tree.replace_once(
        boot,
        "        let bootdevice = boot_image_file.display().to_string();\n"
        "        flash_partition(&bootdevice, &new_boot_bytes)?;",
        "        let bootdevice = boot_image_file.display().to_string();\n"
        "        // 从原厂备份刷回时，备份本身就是回滚源；否则没有备份（明确提示勿重启）\n"
        "        flash_partition(&bootdevice, &new_boot_bytes, stock_source.as_deref())?;",
    )
    tree.replace_once(
        boot,
        '    println!("- Removing KernelSU from boot image");\n'
        '    cpio.rm("kernelsu.ko", false);\n',
        '    println!("- Removing KernelSU from boot image");\n'
        "    // W18b（0007b）：同时清掉我们的归属标记与官方名条目\n"
        "    cpio.rm(OURS_MARKER_ENTRY, false);\n"
        '    cpio.rm(OFFICIAL_KSU_ENTRY, false);\n',
    )

    # 6) CLI：boot-info ramdisk-state（android 与 host 两个 CLI）
    cli = f"{UP_KS}/cli.rs"
    tree.replace_once(
        cli,
        "    SlotSuffix {\n        /// toggle to another slot\n"
        "        #[arg(short = 'u', long, default_value = \"false\")]\n        ota: bool,\n    },\n}",
        "    SlotSuffix {\n        /// toggle to another slot\n"
        "        #[arg(short = 'u', long, default_value = \"false\")]\n        ota: bool,\n    },\n\n"
        "    /// print the ramdisk state of a boot image:\n"
        "    /// `ours` | `compatible` | `foreign` | `stock` (or `unknown` when it cannot be read).\n"
        "    /// READ-ONLY: never writes anything.\n"
        "    RamdiskState {\n        /// boot image path\n"
        "        #[arg(short, long, default_value = None)]\n        boot: Option<PathBuf>,\n    },\n}",
    )
    tree.replace_once(
        cli,
        "            BootInfo::AvailablePartitions => {\n"
        "                let parts = crate::boot_patch::list_available_partitions();\n"
        "                for p in &parts {\n                    println!(\"{p}\");\n                }\n"
        "                return Ok(());\n            }\n        },",
        "            BootInfo::AvailablePartitions => {\n"
        "                let parts = crate::boot_patch::list_available_partitions();\n"
        "                for p in &parts {\n                    println!(\"{p}\");\n                }\n"
        "                return Ok(());\n            }\n"
        "            BootInfo::RamdiskState { boot } => {\n"
        "                // 与 host CLI 同源同判据（query_ramdisk_state）；输出恰好一个词\n"
        "                println!(\"{}\", crate::boot_patch::query_ramdisk_state(boot.as_deref()));\n"
        "                return Ok(());\n            }\n        },",
    )
    host = f"{UP_KS}/cli_non_android.rs"
    tree.replace_once(
        host,
        "    /// show supported kmi versions\n    SupportedKmis,\n}",
        "    /// show supported kmi versions\n    SupportedKmis,\n\n"
        "    /// print the ramdisk state of a boot image:\n"
        "    /// `ours` | `compatible` | `foreign` | `stock` (or `unknown` when it cannot be read).\n"
        "    RamdiskState {\n        /// boot image path\n        #[arg(short, long)]\n"
        "        boot: PathBuf,\n    },\n}",
    )
    tree.replace_once(
        host,
        "        Commands::SupportedKmis => {\n"
        "            let kmi = crate::assets::list_supported_kmi();\n"
        "            for kmi in &kmi {\n                println!(\"{kmi}\");\n            }\n"
        "            Ok(())\n        }\n    };",
        "        Commands::SupportedKmis => {\n"
        "            let kmi = crate::assets::list_supported_kmi();\n"
        "            for kmi in &kmi {\n                println!(\"{kmi}\");\n            }\n"
        "            Ok(())\n        }\n\n"
        "        Commands::RamdiskState { boot } => {\n"
        "            println!(\"{}\", crate::boot_patch::query_ramdisk_state(Some(&boot)));\n"
        "            Ok(())\n        }\n    };",
    )
    return [boot, cli, host]


# ---------------------------------------------------------------- 0013
def patch_0013(tree, s7k) -> list[str]:
    """0008b：restore-user-data 接线（备份+恢复路径、权限、失败语义）。"""
    rp = f"{UP_KS}/restore_user_data.rs"
    utils = f"{UP_KS}/utils.rs"
    cli = f"{UP_KS}/cli.rs"
    main = f"{UP_KS}/main.rs"

    # 1) restore_user_data.rs：migrate 常量就地定义（不采用 migrate.rs，03 §2.2.7）
    tree.replace_once(
        rp,
        "use crate::migrate::{ALLOWLIST_FILE, STEALTH_CODE_FILE, STEALTH_FILE};\n",
        "// MapleSU W18b（0008b）：7K 的这三个常量来自 `crate::migrate`（5985 行的\n"
        "// /data/adb/sevenk 迁移链，03 分册 §2.2.7 明确不采用）。这里就地定义同值常量，\n"
        "// 避免把不采用的迁移模块拖进树里（7K 源：userspace/ksud/src/migrate.rs:109-115）。\n"
        "const ALLOWLIST_FILE: &str = \".allowlist\";\n"
        "const STEALTH_FILE: &str = \"stealth\";\n"
        "const STEALTH_CODE_FILE: &str = \"stealth_code\";\n",
    )

    # 2) utils.rs：backup_user_data + copy_dir_all + restore_user_data（7K :400-530 移植）
    s7k_utils = s7k.read(f"{S7K_KS}/utils.rs")
    backup_block = _slice_between(
        s7k_utils,
        "/// 🔴1（v2.4）：卸载之前把**用户数据**备份到 "
        "`/data/adb/sevenk_uninstall_backup_<ts>/`。",
        "pub fn uninstall(package_name: &str) -> Result<()> {",
    )
    backup_block = backup_block.replace("crate::migrate::KEY_FILES", "KEY_FILES")
    # 7K 的卸载辅助块里还有 remove_legacy_compat_symlink（/data/adb/sevenk → ksu 兼容软链，
    # 依赖 5985 行 migrate 模块）。本分支数据目录就是 /data/adb/ksu，不采用兼容软链，
    # 因此整段剔除（保留 remove_dir_all_checked 等纯 std helper）。
    legacy_start = "/// 🔴1（v2.10）：卸载时删掉 `/data/adb/ksu` **兼容软链本身**"
    if legacy_start in backup_block:
        i = backup_block.index(legacy_start)
        # 函数体以 "\n}\n" 结束；找下一个以 "\n/// " 或 EOF 分隔的定义
        rest = backup_block[i:]
        end_rel = rest.find("\n}\n")
        assert end_rel > 0, "remove_legacy_compat_symlink 结束位置未找到"
        backup_block = backup_block[:i] + backup_block[i + end_rel + 3:]
    if "crate::migrate" in backup_block:
        raise C.KsuError("0013 追加块仍引用 crate::migrate（应已剔除）")
    backup_block = backup_block.replace(
        'join(format!("sevenk_uninstall_backup_{stamp}"))',
        'join(format!("ksu_uninstall_backup_{stamp}"))',
    )
    # 追加前去掉尾部空行：git apply --whitespace=error-all 会把「文件末尾多一空行」判为
    # whitespace error（W12d 实测：0013 曾因此被 verify 拒绝）。
    backup_block = backup_block.rstrip("\n") + "\n"
    tree.append(
        utils,
        "\n// ══════════════════════════════════════════════════════════════════════\n"
        "// MapleSU W18b（0008b）· 卸载前备份 / restore-user-data\n"
        "// 移植自 7K `userspace/ksud/src/utils.rs:400-530`（逐字，仅改：\n"
        "//   · `crate::migrate::KEY_FILES` → 本地常量（不采用 migrate.rs）；\n"
        "//   · 备份目录名 `sevenk_` → `ksu_`（我们的数据目录是 /data/adb/ksu）。\n"
        "// 失败语义：任一项备份失败 → bail，**什么都不删**（绝不假装备份过了）。\n"
        "// ══════════════════════════════════════════════════════════════════════\n\n"
        "/// 卸载前必须保住的关键文件（7K migrate.rs:109-115 的同值清单）。\n"
        "const KEY_FILES: [&str; 3] = [\".allowlist\", \"stealth\", \"stealth_code\"];\n\n"
        + backup_block,
    )

    # 3) uninstall 顺序修正：先还原启动镜像 → 备份用户数据 → 才删目录
    tree.replace_once(
        utils,
        '    println!("- Removing directories..");\n'
        "    std::fs::remove_dir_all(defs::WORKING_DIR).ok();\n",
        "    // W18b（0008b）：顺序修正 —— 先还原启动镜像、再备份用户数据、最后才删。\n"
        "    // 7K 依据：userspace/ksud/src/utils.rs:626-700（旧顺序先删 WORKING_DIR，\n"
        "    // 会把 restore 依赖的原厂备份一起删掉）。\n"
        '    println!("- Restore boot image.. (your data is NOT deleted yet)");\n'
        "    boot_patch::restore(BootRestoreArgs {\n"
        "        boot: None,\n"
        "        flash: true,\n"
        "        out: None,\n"
        "        out_name: None,\n"
        "    })?;\n\n"
        "    // 删之前先备份用户数据；备份失败 → 中止（不删、不重启）\n"
        "    match backup_user_data()? {\n"
        "        Some(dir) => println!(\n"
        '            "- YOU CAN GET IT BACK LATER with: ksud restore-user-data\\n\\\n'
        "             - backup kept at: {}\",\n"
        "            dir.display()\n"
        "        ),\n"
        '        None => println!("- No user data found to back up"),\n'
        "    }\n\n"
        '    println!("- Removing directories..");\n'
        "    std::fs::remove_dir_all(defs::WORKING_DIR).ok();\n",
    )
    # 原 restore 调用已前移 → 删除旧的重复调用块
    tree.replace_once(
        utils,
        '    println!("- Restore boot image..");\n'
        "    boot_patch::restore(BootRestoreArgs {\n"
        "        boot: None,\n"
        "        flash: true,\n"
        "        out: None,\n"
        "        out_name: None,\n"
        "    })?;\n"
        '    println!("- Uninstall KernelSU manager..");\n',
        '    println!("- Uninstall KernelSU manager..");\n',
    )

    # 4) main.rs 接线（7K main.rs 里 restore_user_data 不限定 cfg：纯 std + webadmin 工具）
    tree.insert_before(
        main,
        "mod res_label;\n",
        "// MapleSU W18b（0008b）：卸载备份恢复（纯 std 实现 + CLI，7K main.rs:50）\n"
        "mod restore_user_data;\n",
    )

    # 5) cli.rs：RestoreUserData 子命令 + 分发
    tree.insert_after(
        cli,
        "    Uninstall {\n"
        "        #[arg(long, default_value_t = String::from(defs::DEFAULT_PACKAGE_NAME))]\n"
        "        package_name: String,\n    },\n",
        "\n    /// 从卸载备份恢复用户数据（.allowlist / stealth / stealth_code /\n"
        "    /// module_configs/ / profile/ / .feature_config）；默认取最新一份，\n"
        "    /// 逐字节校验后覆盖回 /data/adb/ksu，先把当前数据快照到 <备份>/pre_restore_<ts>/。\n"
        "    RestoreUserData {\n"
        "        /// 指定备份目录（绝对路径，或相对 /data/adb 的目录名）；默认最新一份\n"
        "        #[arg(long)]\n        from: Option<PathBuf>,\n    },\n",
    )
    tree.insert_after(
        cli,
        "        Commands::Uninstall { package_name } => utils::uninstall(&package_name),\n",
        "        Commands::RestoreUserData { from } => utils::restore_user_data(from.as_deref()),\n",
    )
    return [rp, utils, main, cli]


def _slice_between(text: str, start_marker: str, stop_marker: str) -> str:
    start = text.index(start_marker)
    stop = text.index(stop_marker, start)
    return text[start:stop].rstrip("\n") + "\n"


BOOT_COPY_HELPER = r'''
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

'''

BOOT_COPY_TESTS = r'''

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
'''

RAMDISK_MODULE_PARAMS = r'''
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

'''


def patch_0022(tree, _source) -> list[str]:
    boot = f"{UP_KS}/boot_patch.rs"
    utils = f"{UP_KS}/utils.rs"
    init = "userspace/ksuinit/src/init.rs"
    tree.replace_once(boot, "        let (mut cpio, vendor_ramdisk_idx) =\n",
        "        let source_without_ramdisk = boot_image.get_blocks().get_ramdisk().is_none();\n"
        "        let (mut cpio, vendor_ramdisk_idx) =\n")
    tree.insert_after(boot, "        config.apply(&mut ksu_config);\n",
        "        if !no_install && source_without_ramdisk {\n"
        '            ksu_config.retain(|v| !v.starts_with("maplesu_original_ramdisk="));\n'
        '            ksu_config.push("maplesu_original_ramdisk=empty-v1".to_owned());\n'
        "        }\n")
    tree.replace_once(boot, "pub struct BootRestoreArgs {\n", "pub struct BootRestoreArgs {\n"
        "    /// Rebuild only the explicit input copy, without device state or backups.\n"
        "    #[arg(long, default_value_t = false)]\n    pub file_only: bool,\n\n")
    tree.replace_once(boot, "pub fn restore(args: BootRestoreArgs) -> Result<()> {\n",
        "pub fn restore(args: BootRestoreArgs) -> Result<()> {\n"
        "    if args.file_only {\n        return restore_file_copy(&args);\n    }\n")
    tree.replace_once(boot, "    let BootRestoreArgs {\n", "    let BootRestoreArgs {\n        file_only: _,\n")
    tree.insert_before(boot, "fn rebuild_without_ksu(\n", BOOT_COPY_HELPER)
    tree.replace_once(boot, '    println!("- Removing KernelSU from boot image");\n',
        '    println!("- Removing KernelSU from boot image");\n'
        '    ensure!(cpio.exists("init.real") || crate::vr_bootstrap::present(cpio),\n'
        '        "original init is absent; use the original boot image");\n')
    tree.replace_once(boot, '    cpio.rm(OFFICIAL_KSU_ENTRY, false);\n',
        '    cpio.rm(OFFICIAL_KSU_ENTRY, false);\n'
        '    cpio.rm("ksu_config", false);\n    cpio.rm("stock_image.sha1", false);\n')
    tree.replace_once(utils, "    boot_patch::restore(BootRestoreArgs {\n",
        "    boot_patch::restore(BootRestoreArgs {\n        file_only: false,\n")
    tree.insert_before(init, "fn load_module_from_path(path: &str) -> Result<()> {\n", RAMDISK_MODULE_PARAMS)
    tree.replace_once(init, '    let params = std::fs::read("/ksu_config").unwrap_or_default();\n',
        '    let params = std::fs::read("/ksu_config").unwrap_or_default();\n'
        '    let params = module_params_without_image_metadata(&params);\n')
    text = tree.read(boot)
    assert text.endswith("}\n")
    tree.write(boot, text[:-2] + BOOT_COPY_TESTS + "}\n")
    return [boot, utils, init]


PATCHES_BOOT_COPY = [{
    "name": "0022-boot-copy-rebuild.patch",
    "summary": "Rebuild an explicit boot image copy without device state, partition writes or global backup cleanup",
    "apply": patch_0022,
    "status": "implemented",
    "checks": [[f"{UP_KS}/boot_patch.rs", ["pub file_only: bool", "fn restore_file_copy", "copy_restore_preserves_original_init_unknown_files_and_input"]]],
}]


PATCHES_W18B_BOOT = [
    {
        "name": "0012-boot-patch-safety-wiring.patch",
        "summary": "0007b：boot-patch 安全增强完整接线（四态 RamdiskState/init 处置防串位/"
                   "备份回读校验/写后 SHA-256 读回/失败回滚/还原准入/ramdisk-state CLI）",
        "apply": patch_0012,
        "status": "implemented",
        "compile_verified": False,
        "compile_note": "本机无 Rust 依赖（android-bootimg 等 git 源离线不可得）→ 无法 cargo check；"
                        "已用 rustfmt 做语法校验，语义/类型校验留给 CI aarch64 构建。"
                        "7K 的内核归属探测闸（KernelOwner/stealth_probe_get）与 --force-foreign "
                        "逃生口未移植，见 manifest.patchSeries.todo（W18b blockers）",
        "checks": [
            ["userspace/ksud/src/boot_patch.rs",
             ["pub enum RamdiskState", "fn init_disposition", "fn should_record_stock",
              "fn write_and_verify", "fn rollback_partition", "fn flash_failure_error",
              "fn restore_admission", "pub fn query_ramdisk_state", "OURS_MARKER_ENTRY"]],
            ["userspace/ksud/src/cli.rs", ["BootInfo::RamdiskState", "RamdiskState {"]],
            ["userspace/ksud/src/cli_non_android.rs", ["RamdiskState { boot"]],
        ],
    },
    {
        "name": "0013-restore-user-data-wiring.patch",
        "summary": "0008b：restore-user-data 接线（卸载前备份+失败即中止/顺序修正：先还原镜像再删/"
                   "pre_restore 快照/逐字节校验恢复/CLI RestoreUserData/mod 接线）",
        "apply": patch_0013,
        "status": "implemented",
        "compile_verified": False,
        "compile_note": "同 0012：rustfmt 语法校验通过，cargo check 需 CI。7K 的 uninstall 全量重写"
                        "（remove_dir_all_checked 等失败语义硬化）未整段移植，保留上游 .ok() 语义，"
                        "见 manifest.patchSeries.todo",
        "checks": [
            ["userspace/ksud/src/restore_user_data.rs",
             ["const ALLOWLIST_FILE", "pub fn restore_user_data", "pre_restore"]],
            ["userspace/ksud/src/utils.rs",
             ["fn backup_user_data", "fn restore_user_data", "ksu_uninstall_backup_"]],
            ["userspace/ksud/src/main.rs", ["mod restore_user_data;"]],
            ["userspace/ksud/src/cli.rs", ["RestoreUserData {"]],
        ],
    },
]


# ---------------------------------------------------------------- 0024
# Keep 0022/0023 immutable. The generator registers this after backup-optional.
EMPTY_RAMDISK_ORIGIN_HELPER = r"""
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

"""

EMPTY_RAMDISK_RESTORE_TESTS = r"""

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
"""


def patch_0024_empty_origin_restore(tree, _source) -> list[str]:
    boot = f"{UP_KS}/boot_patch.rs"
    tree.insert_before(boot, "fn rebuild_without_ksu(\n", EMPTY_RAMDISK_ORIGIN_HELPER)
    tree.replace_once(boot,
        '    ensure!(cpio.exists("init.real") || crate::vr_bootstrap::present(cpio),\n'
        '        "original init is absent; use the original boot image");\n',
        '    let restore_empty = owned_empty_ramdisk_origin(cpio);\n'
        '    ensure!(restore_empty || cpio.exists("init.real") || crate::vr_bootstrap::present(cpio),\n'
        '        "original init is absent; use the original boot image");\n'
        '    if restore_empty {\n'
        '        ensure!(vendor_ramdisk_idx.is_none() && matches!(\n'
        '            boot_image.get_header().get_version(), BootImageVersion::Android(0..=4)),\n'
        '            "EMPTY_RAMDISK_CONTAINER_UNSUPPORTED");\n'
        '        ensure!(cpio.entries().keys().all(|name| matches!(name.as_str(),\n'
        '            "init" | "kernelsu.ko" | "maplesu_id" | "ksu_config" |\n'
        '            "stock_image.sha1" | "force_debuggable" | "adb_debug.prop")),\n'
        '            "EMPTY_RAMDISK_CONTENT_CONFLICT");\n'
        '    }\n')
    tree.replace_once(boot,
        '    let mut new_cpio = Vec::<u8>::new();\n'
        '    cpio.dump(&mut new_cpio)?;\n\n'
        '    println!("- Repacking boot image");\n',
        '    let mut new_cpio = Vec::<u8>::new();\n'
        '    if !restore_empty { cpio.dump(&mut new_cpio)?; }\n\n'
        '    println!("- Repacking boot image");\n')
    tree.replace_once(boot,
        '        patcher.replace_ramdisk(Box::new(Cursor::new(new_cpio)), false);\n'
        '    }\n\n'
        '    let mut buf = Cursor::new(Vec::<u8>::with_capacity(boot_image.get_size()));\n',
        '        // Already encoded empty input writes zero bytes, not a compressed empty CPIO.\n'
        '        patcher.replace_ramdisk(Box::new(Cursor::new(new_cpio)), restore_empty);\n'
        '    }\n\n'
        '    let mut buf = Cursor::new(Vec::<u8>::with_capacity(boot_image.get_size()));\n')
    text = tree.read(boot)
    if not text.endswith("}\n"):
        raise ValueError("boot_patch test module closing anchor changed")
    tree.write(boot, text[:-2] + EMPTY_RAMDISK_RESTORE_TESTS + "}\n")
    return [boot]


PATCHES_EMPTY_RAMDISK_RESTORE = [{
    "name": "0024-boot-empty-origin-restore.patch",
    "summary": "Restore explicitly owned empty-v1 ramdisk origins without backups and preserve unknown later content",
    "apply": patch_0024_empty_origin_restore,
    "status": "implemented",
    "checks": [[f"{UP_KS}/boot_patch.rs", ["fn owned_empty_ramdisk_origin", "EMPTY_RAMDISK_CONTENT_CONFLICT",
        "actual_empty_install_repatch_and_file_restore_share_one_origin"]]],
}]


TARGET_KERNEL_KMI_FIRST = r"""                // Explicit KMI is handled by map_or_else before this default path.
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
"""


TARGET_KERNEL_KMI_TESTS = r"""

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
"""


def patch_0025_target_kernel_kmi(tree, _source) -> list[str]:
    boot = f"{UP_KS}/boot_patch.rs"
    tree.insert_before(boot,
        '                #[cfg(target_os = "android")]\n'
        '                if ota {\n',
        TARGET_KERNEL_KMI_FIRST)
    tree.replace_once(boot,
        '                } else if let Some(kernel_path) = &kernel {\n'
        '                    println!(\n'
        '                        "- Trying to auto detect KMI version for {}",\n'
        '                        kernel_path.display()\n'
        '                    );\n'
        '                    parse_kmi_from_kernel(kernel_path)?\n',
        '')
    text = tree.read(boot)
    if not text.endswith("}\n"):
        raise ValueError("boot_patch test module closing anchor changed")
    tree.write(boot, text[:-2] + TARGET_KERNEL_KMI_TESTS + "}\n")
    manifest = "userspace/ksud/Cargo.toml"
    tree.insert_before(manifest, '[build-dependencies]\n', '[dev-dependencies]\nlz4 = "1"\n\n')
    tree.replace_once("Cargo.lock", ' "ksuinit",\n "libc",\n "log",\n "memmap2",',
        ' "ksuinit",\n "libc",\n "log",\n "lz4",\n "memmap2",')
    return [boot, manifest, "Cargo.lock"]


PATCHES_TARGET_KERNEL_KMI = [{
    "name": "0025-target-kernel-kmi.patch",
    "summary": "Resolve default KMI from the final replacement kernel or explicit boot kernel before running-device state",
    "apply": patch_0025_target_kernel_kmi,
    "status": "implemented",
    "compile_verified": False,
    "compile_note": "Source generation only; userland compilation and behavior verification await the sole validation owner.",
    "checks": [[f"{UP_KS}/boot_patch.rs", ["KMI source: replacement kernel", "KMI source: target boot",
        "if target.get_blocks().get_kernel().is_some()"]]],
}]
