// SPDX-License-Identifier: GPL-3.0-or-later
// SakiSU rmvr semantics, ported from 6f9672837b9359f8853f47e18e00261edbf6d31e.
// Candidate producer only; partition writes belong to the Manager transaction.
use std::collections::BTreeSet;
use std::io::{Cursor, Write};
use std::path::PathBuf;
use anyhow::{Context, Result, ensure};
use android_bootimg::parser::{BootImage, BootImageVersion};
use android_bootimg::patcher::BootImagePatchOption;

const DEFAULT_VENDOR_RMVR_MODULES: [&str; 2] = ["vr", "vklp"];

#[derive(Debug, Default, PartialEq, Eq)]
pub struct CleanupReport {
    pub removed_modules: usize,
    pub updated_indexes: usize,
    pub changed_fragments: usize,
}
impl CleanupReport {
    pub fn changed(&self) -> bool { self.removed_modules != 0 || self.updated_indexes != 0 }
    fn merge(&mut self, other: Self) {
        self.removed_modules += other.removed_modules;
        self.updated_indexes += other.updated_indexes;
        self.changed_fragments += usize::from(other.changed());
    }
}

fn strip_module_compression_suffix(name: &str) -> &str {
    [".gz", ".xz", ".zst", ".lz4"]
        .into_iter()
        .find_map(|suffix| name.strip_suffix(suffix))
        .unwrap_or(name)
}

fn normalize_module_stem(value: &str, require_ko_suffix: bool) -> Option<String> {
    let value = value.trim().trim_matches(|c| matches!(c, ':' | ','));
    let basename = value.rsplit('/').next().unwrap_or(value);
    let basename = strip_module_compression_suffix(basename);
    let stem = if let Some(stem) = basename.strip_suffix(".ko") {
        stem
    } else if require_ko_suffix {
        return None;
    } else {
        basename
    };

    (!stem.is_empty()).then(|| stem.replace('-', "_").to_ascii_lowercase())
}

fn is_target_module_reference(value: &str, targets: &BTreeSet<String>) -> bool {
    normalize_module_stem(value, false).is_some_and(|stem| targets.contains(&stem))
}

fn normalized_cpio_path(path: &str) -> &str {
    let mut normalized = path.trim_start_matches('/');
    while let Some(stripped) = normalized.strip_prefix("./") {
        normalized = stripped;
    }
    normalized
}

fn is_target_module_path(path: &str, targets: &BTreeSet<String>) -> bool {
    let path = normalized_cpio_path(path);
    path.starts_with("lib/modules/")
        && normalize_module_stem(path, true).is_some_and(|stem| targets.contains(&stem))
}

fn rewrite_module_index_line(
    index_name: &str,
    line: &str,
    targets: &BTreeSet<String>,
) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return Some(line.to_string());
    }

    let (content, comment) = line
        .split_once('#')
        .map_or((line, None), |(content, comment)| (content, Some(comment)));
    let tokens = content.split_whitespace().collect::<Vec<_>>();

    let attach_comment = |mut rebuilt: String| {
        if let Some(comment) = comment {
            if !rebuilt.is_empty() && !rebuilt.ends_with(' ') {
                rebuilt.push(' ');
            }
            rebuilt.push('#');
            rebuilt.push_str(comment);
        }
        rebuilt
    };

    match index_name {
        "modules.dep" => {
            let Some((module, dependencies)) = content.split_once(':') else {
                return Some(line.to_string());
            };
            if is_target_module_reference(module, targets) {
                return None;
            }

            if !dependencies.split_whitespace().any(|token| is_target_module_reference(token, targets)) {
                return Some(line.to_string());
            }
            let kept = dependencies
                .split_whitespace()
                .filter(|dependency| !is_target_module_reference(dependency, targets))
                .collect::<Vec<_>>();
            let rebuilt = if kept.is_empty() {
                format!("{}:", module.trim_end())
            } else {
                format!("{}: {}", module.trim_end(), kept.join(" "))
            };
            Some(attach_comment(rebuilt))
        }
        "modules.softdep" => {
            if tokens.len() >= 2 && is_target_module_reference(tokens[1], targets) {
                return None;
            }
            if !tokens.iter().skip(2).any(|token| !matches!(*token, "pre:" | "post:") && is_target_module_reference(token, targets)) {
                return Some(line.to_string());
            }
            let rebuilt = tokens
                .into_iter()
                .filter(|token| {
                    matches!(*token, "softdep" | "pre:" | "post:")
                        || !is_target_module_reference(token, targets)
                })
                .collect::<Vec<_>>()
                .join(" ");
            Some(attach_comment(rebuilt))
        }
        "modules.alias" => {
            if tokens.first() == Some(&"alias")
                && tokens
                    .last()
                    .is_some_and(|module| is_target_module_reference(module, targets))
            {
                None
            } else {
                Some(line.to_string())
            }
        }
        "modules.options" | "modules.blocklist" => {
            if tokens.len() >= 2 && is_target_module_reference(tokens[1], targets) {
                None
            } else {
                Some(line.to_string())
            }
        }
        name if name == "modules.load"
            || name.starts_with("modules.load.")
            || name == "modules.order" =>
        {
            if tokens
                .first()
                .is_some_and(|module| is_target_module_reference(module, targets))
            {
                None
            } else {
                Some(line.to_string())
            }
        }
        _ => Some(line.to_string()),
    }
}

fn rewrite_module_index(
    index_path: &str,
    data: &[u8],
    targets: &BTreeSet<String>,
) -> Result<Option<Vec<u8>>> {
    let index_name = index_path.rsplit('/').next().unwrap_or(index_path);
    let text = std::str::from_utf8(data)
        .with_context(|| format!("{index_path} is not a UTF-8 module index"))?;
    let mut changed = false;
    let mut output = String::new();
    for original in text.split_inclusive('\n') {
        let (line, ending) = original.strip_suffix("\r\n").map(|s| (s, "\r\n"))
            .or_else(|| original.strip_suffix('\n').map(|s| (s, "\n")))
            .unwrap_or((original, ""));
        match rewrite_module_index_line(index_name, line, targets) {
            Some(rebuilt) => {
                changed |= rebuilt != line;
                output.push_str(&rebuilt);
                output.push_str(ending);
            }
            None => changed = true,
        }
    }
    Ok(changed.then(|| output.into_bytes()))
}

fn is_supported_module_index(path: &str) -> bool {
    let path = normalized_cpio_path(path);
    if !path.starts_with("lib/modules/") {
        return false;
    }
    let name = path.rsplit('/').next().unwrap_or(path);
    matches!(
        name,
        "modules.dep"
            | "modules.softdep"
            | "modules.alias"
            | "modules.options"
            | "modules.blocklist"
            | "modules.load"
            | "modules.order"
    ) || name.starts_with("modules.load.")
}

// Edit newc records in place conceptually: never round-trip through Cpio::dump,
// which drops inode/link count/mtime and resets ownership on replaced entries.
fn clean_cpio(data: &[u8]) -> Result<(Vec<u8>, CleanupReport)> {
    let targets = DEFAULT_VENDOR_RMVR_MODULES.into_iter().map(str::to_string).collect();
    let mut output = Vec::with_capacity(data.len());
    let mut report = CleanupReport::default();
    let mut offset = 0usize;
    let mut trailer = false;
    while offset < data.len() {
        if data[offset] == 0 && trailer {
            let end = data[offset..].iter().position(|b| *b != 0).map_or(data.len(), |n| offset + n);
            output.extend_from_slice(&data[offset..end]);
            offset = end;
            continue;
        }
        let header = data.get(offset..offset.checked_add(110).context("CPIO overflow")?)
            .context("truncated CPIO header")?;
        ensure!(&header[..6] == b"070701" || &header[..6] == b"070702", "invalid newc magic");
        let field = |at: usize| -> Result<usize> {
            Ok(usize::from_str_radix(std::str::from_utf8(&header[at..at + 8])?, 16)?)
        };
        let mode = field(14)?;
        let links = field(38)?;
        let size = field(54)?;
        let namesize = field(94)?;
        ensure!((1..=4096).contains(&namesize), "invalid CPIO name size");
        let name_end = offset.checked_add(110 + namesize).context("CPIO overflow")?;
        let name = data.get(offset + 110..name_end).context("truncated CPIO name")?;
        ensure!(name.last() == Some(&0) && !name[..namesize - 1].contains(&0), "invalid CPIO name");
        let path = std::str::from_utf8(&name[..namesize - 1])?;
        let start = name_end.checked_add(3).context("CPIO overflow")? & !3;
        let end = start.checked_add(size).context("CPIO overflow")?;
        let padded = end.checked_add(3).context("CPIO overflow")? & !3;
        let payload = data.get(start..end).context("truncated CPIO data")?;
        ensure!(padded <= data.len(), "truncated CPIO padding");
        trailer = path == "TRAILER!!!";
        if trailer { ensure!(size == 0, "invalid CPIO trailer"); }
        let regular = mode & 0o170000 == 0o100000;
        if regular && is_target_module_path(path, &targets) {
            // Removing the sole data-bearing record of a hard link can corrupt
            // a surviving alias. Reject the whole candidate instead of guessing.
            ensure!(links <= 1, "target module is hard-linked: {path}");
            report.removed_modules += 1;
        } else if regular && is_supported_module_index(path) {
            if let Some(rebuilt) = rewrite_module_index(path, payload, &targets)? {
                ensure!(links <= 1, "module index is hard-linked: {path}");
                let mut edited = header.to_vec();
                edited[54..62].copy_from_slice(format!("{:08x}", rebuilt.len()).as_bytes());
                if &header[..6] == b"070702" {
                    let checksum = rebuilt.iter().fold(0u32, |sum, b| sum.wrapping_add(u32::from(*b)));
                    edited[102..110].copy_from_slice(format!("{checksum:08x}").as_bytes());
                }
                output.extend_from_slice(&edited);
                output.extend_from_slice(&data[offset + 110..start]);
                output.extend_from_slice(&rebuilt);
                output.resize((output.len() + 3) & !3, 0);
                report.updated_indexes += 1;
            } else {
                output.extend_from_slice(&data[offset..padded]);
            }
        } else {
            output.extend_from_slice(&data[offset..padded]);
        }
        offset = padded;
    }
    ensure!(trailer, "missing CPIO trailer");
    Ok((output, report))
}

struct RamdiskBuffer(Vec<u8>);
impl Write for RamdiskBuffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > (256 * 1024 * 1024usize).saturating_sub(self.0.len()) {
            return Err(std::io::Error::other("vendor ramdisk exceeds 256 MiB"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
}

pub fn clean_vendor_boot(source: &[u8]) -> Result<(Vec<u8>, CleanupReport)> {
    let image = BootImage::parse(source)?;
    ensure!(matches!(image.get_header().get_version(), BootImageVersion::Vendor(_)), "rmvr requires vendor_boot");
    let ramdisk = image.get_blocks().get_ramdisk().context("vendor_boot has no ramdisk")?;
    let mut patcher = BootImagePatchOption::new(&image);
    let mut total = CleanupReport::default();
    if ramdisk.is_vendor_ramdisk() {
        for (index, fragment) in ramdisk.iter_vendor_ramdisk().enumerate() {
            let mut data = RamdiskBuffer(Vec::new());
            fragment.dump(&mut data, false).with_context(|| format!("unpack vendor fragment {index}"))?;
            let (rebuilt, report) = clean_cpio(&data.0).with_context(|| format!("parse vendor fragment {index}"))?;
            if report.changed() { patcher.replace_vendor_ramdisk(index, Box::new(Cursor::new(rebuilt)), false); }
            total.merge(report);
        }
    } else {
        let mut data = RamdiskBuffer(Vec::new());
        ramdisk.dump(&mut data, false)?;
        let (rebuilt, report) = clean_cpio(&data.0)?;
        if report.changed() { patcher.replace_ramdisk(Box::new(Cursor::new(rebuilt)), false); }
        total.merge(report);
    }
    if !total.changed() { return Ok((source.to_vec(), total)); }
    let mut output = Cursor::new(Vec::new());
    patcher.patch(&mut output)?;
    let rebuilt = output.into_inner();
    let verified = BootImage::parse(&rebuilt).context("validate rebuilt vendor_boot")?;
    ensure!(matches!(verified.get_header().get_version(), BootImageVersion::Vendor(_)), "invalid rebuilt image");
    Ok((rebuilt, total))
}

#[derive(clap::Args, Debug)]
pub struct VendorBootRmvrArgs {
    /// Input vendor_boot image. No implicit partition discovery or flashing.
    #[arg(short, long)]
    pub boot: PathBuf,
    #[arg(short, long)]
    pub out: PathBuf,
    #[arg(long, default_value = "vendor_boot-rmvr.img")]
    pub out_name: String,
    /// Optional machine-readable receipt, created only after candidate validation.
    #[arg(long)]
    pub report: Option<PathBuf>,
}

pub fn patch_rmvr(args: VendorBootRmvrArgs) -> Result<()> {
    ensure!(std::path::Path::new(&args.out_name).file_name().and_then(|s| s.to_str()) == Some(&args.out_name), "invalid output name");
    let source = std::fs::read(&args.boot)?;
    ensure!(source.len() <= 512 * 1024 * 1024, "image exceeds 512 MiB");
    let (candidate, report) = clean_vendor_boot(&source)?;
    std::fs::create_dir_all(&args.out)?;
    let output = args.out.join(&args.out_name);
    ensure!(!output.exists(), "output already exists");
    let mut temp = tempfile::NamedTempFile::new_in(&args.out)?;
    temp.write_all(&candidate)?;
    temp.as_file().sync_all()?;
    temp.persist_noclobber(&output)?;
    let receipt = serde_json::json!({
        "schema": 1, "partition": "vendor_boot", "sourceSha256": sha256::digest(&source),
        "candidateSha256": sha256::digest(&candidate), "changed": report.changed(),
        "removedModules": report.removed_modules, "updatedIndexes": report.updated_indexes,
        "changedFragments": report.changed_fragments,
    });
    if let Some(path) = args.report {
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(path)?;
        file.write_all(receipt.to_string().as_bytes())?;
        file.sync_all()?;
    }
    println!("{receipt}");
    Ok(())
}


#[cfg(test)]
#[path = "vendor_boot_tests.rs"]
mod tests;
