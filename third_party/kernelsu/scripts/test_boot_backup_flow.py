#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Run the production backup function and its Android call-site without cargo.

The Rust source is extracted verbatim. Filesystem failures are real; cpio and
digest helpers are narrow host fixtures. This does not flash a device partition.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parent.parent


def between(text: str, start: str, end: str) -> str:
    if text.count(start) != 1:
        raise ValueError(f"expected one source anchor: {start}")
    begin = text.index(start)
    return text[begin:text.index(end, begin)]


PRELUDE = r'''
#![allow(dead_code)]
use std::cell::RefCell;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
trait Context<T> {
    fn context(self, message: &str) -> Result<T>;
    fn with_context<F: FnOnce() -> String>(self, message: F) -> Result<T>;
}
impl<T, E: std::fmt::Display> Context<T> for std::result::Result<T, E> {
    fn context(self, message: &str) -> Result<T> {
        self.map_err(|e| format!("{message}: {e}").into())
    }
    fn with_context<F: FnOnce() -> String>(self, message: F) -> Result<T> {
        self.map_err(|e| format!("{}: {e}", message()).into())
    }
}
macro_rules! bail { ($($arg:tt)*) => { return Err(format!($($arg)*).into()) }; }
#[derive(Clone, Copy, PartialEq, Eq)]
enum RamdiskState { Stock, Ours, Compatible, Foreign }
#[derive(Default)]
struct Cpio { stock_marker: bool }
struct CpioEntry;
impl CpioEntry { fn regular(_: u32, _: Box<String>) -> Self { Self } }
impl Cpio {
    fn add(&mut self, name: &str, _: CpioEntry) -> Result<()> {
        assert_eq!(name, BACKUP_FILENAME);
        self.stock_marker = true;
        Ok(())
    }
}
const BACKUP_FILENAME: &str = "stock_image.sha1";
thread_local! { static DESTINATION: RefCell<PathBuf> = RefCell::new(PathBuf::new()); }
// For this control-flow test, compare complete file bytes instead of a digest.
fn calculate_sha1(path: impl AsRef<Path>) -> Result<String> {
    Ok(std::fs::read(path)?.iter().map(|byte| format!("{byte:02x}")).collect())
}
fn find_backup_location(_: &str) -> Result<(File, String)> {
    DESTINATION.with(|target| {
        let target = target.borrow();
        let file = OpenOptions::new().create(true).truncate(true).read(true).write(true).open(&*target)?;
        Ok((file, target.to_string_lossy().into_owned()))
    })
}
mod production {
    use super::*;
'''

RUNNER = r'''
use production::do_backup;
#[derive(Debug)]
struct Outcome { backup: Option<PathBuf>, stock_marker: bool }
fn production_call_site(
    backup: bool, flash: bool, ramdisk_state: RamdiskState, boot_image_file: PathBuf,
) -> Result<Outcome> {
    let mut cpio = Cpio::default();
    let mut flash_backup: Option<PathBuf> = None;
__CALL_SITE__
    Ok(Outcome { backup: flash_backup, stock_marker: cpio.stock_marker })
}
fn main() {
    let root = PathBuf::from(std::env::args_os().nth(1).expect("fixture root"));
    let cases = [
        ("flash_destination_failure", false, true, RamdiskState::Stock, 1),
        ("flash_explicit_source_failure", true, true, RamdiskState::Stock, 2),
        ("offline_backup_failure", true, false, RamdiskState::Stock, 1),
        ("flash_stock_backup_success", false, true, RamdiskState::Stock, 0),
        ("flash_compatible_backup_success", false, true, RamdiskState::Compatible, 0),
        ("offline_no_backup", false, false, RamdiskState::Stock, 1),
        ("offline_explicit_backup_success", true, false, RamdiskState::Stock, 0),
        ("flash_ours_backup_success", false, true, RamdiskState::Ours, 0),
    ];
    let mut failures = 0;
    for (name, backup, flash, state, failure) in cases {
        let dir = root.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        let input = dir.join("input.img");
        let target = if failure == 1 { dir.join("missing-parent/backup.img") } else { dir.join("backup.img") };
        if failure != 2 { std::fs::write(&input, b"IMAGE_BYTES").unwrap(); }
        DESTINATION.with(|dest| *dest.borrow_mut() = target.clone());
        let expected_backup = failure == 0 && (backup || flash);
        let outcome = production_call_site(backup, flash, state, input);
        let verdict = match outcome {
            Ok(outcome) => {
                outcome.backup.is_some() == expected_backup
                    && outcome.stock_marker == (expected_backup && state == RamdiskState::Stock)
                    && (!expected_backup || std::fs::read(&target).unwrap() == b"IMAGE_BYTES")
            }
            Err(error) => { eprintln!("{name}: terminated before the next phase: {error}"); false }
        };
        println!("{} {name}", if verdict { "PASS" } else { "FAIL" });
        if !verdict { failures += 1; }
    }
    println!("RESULT cases=8 failures={failures}");
    std::process::exit(if failures == 0 { 0 } else { 1 });
}
'''


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT / "applied/userspace/ksud/src/boot_patch.rs")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--rustc", type=Path)
    args = parser.parse_args()
    source_bytes = args.source.read_bytes()
    source = source_bytes.decode("utf-8")
    function = between(source, "    pub(super) fn do_backup(", "\n    /// 把校验失败的分区")
    policy = between(source, "fn should_record_stock(", "\n/// 镜像长度必须")
    call_site = between(source, "                let record_stock = should_record_stock(", "\n            }\n        }\n\n        let mut ksu_config")
    rustc = args.rustc
    if rustc is None:
        found = shutil.which("rustc")
        rustc = Path(found) if found else Path.home() / ".rustup/toolchains/stable-x86_64-pc-windows-gnu/bin/rustc.exe"
    args.out.mkdir(parents=True, exist_ok=True)
    harness = args.out / "backup-flow.rs"
    harness.write_bytes((PRELUDE + function + "\n}\n" + policy + RUNNER.replace("__CALL_SITE__", call_site)).encode("utf-8"))
    binary = args.out / ("backup-flow.exe" if os.name == "nt" else "backup-flow")
    command = [str(rustc), "--edition=2024", "-C", "debuginfo=0", str(harness), "-o", str(binary)]
    if os.name == "nt" and "windows-gnu" in str(rustc):
        linker = rustc.parent.parent / "lib/rustlib/x86_64-pc-windows-gnu/bin/rust-lld.exe"
        command += ["-C", f"linker={linker}", "-C", "linker-flavor=ld.lld", "-C", "link-self-contained=yes"]
    compiled = subprocess.run(command, capture_output=True, text=True, encoding="utf-8")
    (args.out / "compile.stdout.txt").write_bytes(compiled.stdout.encode("utf-8"))
    (args.out / "compile.stderr.txt").write_bytes(compiled.stderr.encode("utf-8"))
    result = {"source": str(args.source.resolve()), "sourceSha256": hashlib.sha256(source_bytes).hexdigest(),
              "harnessSha256": hashlib.sha256(harness.read_bytes()).hexdigest(), "compileCommand": command,
              "compileExit": compiled.returncode,
              "scope": "Verbatim production do_backup, should_record_stock and Android backup call-site; real file copy/open/sync. Cpio and digest are host fixtures. No partition write or Android runtime test."}
    if compiled.returncode == 0:
        executed = subprocess.run([str(binary.resolve()), str((args.out / "fixtures").resolve())], capture_output=True, text=True, encoding="utf-8")
        (args.out / "run.stdout.txt").write_bytes(executed.stdout.encode("utf-8"))
        (args.out / "run.stderr.txt").write_bytes(executed.stderr.encode("utf-8"))
        result["runExit"] = executed.returncode
        print(executed.stdout, end="")
        print(executed.stderr, end="", file=sys.stderr)
    else:
        print(compiled.stderr, end="", file=sys.stderr)
    (args.out / "RESULT.json").write_bytes((json.dumps(result, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
    return compiled.returncode or result["runExit"]


if __name__ == "__main__":
    raise SystemExit(main())
