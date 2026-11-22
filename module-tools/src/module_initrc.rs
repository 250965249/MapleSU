// SPDX-License-Identifier: GPL-3.0-or-later
// next-boot ordering follows the pinned KernelSU module.rs collect_rc_files /
// next_boot_modules contract. Ultra ownership and pending-v2 are checked here.
use std::collections::BTreeMap;
use std::ffi::{CString, OsStr, OsString};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;

const LIMIT: usize = 1024 * 1024;

fn error(message: &'static str) -> io::Error { io::Error::other(message) }
fn trusted(file: &File, directory: bool) -> io::Result<()> {
    let m = file.metadata()?;
    if m.uid() != 0 || m.mode() & 0o022 != 0 ||
        (directory && !m.is_dir()) || (!directory && (!m.is_file() || m.nlink() != 1)) {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "untrusted initrc source"));
    }
    Ok(())
}
fn open_child(parent: &File, name: &OsStr, directory: bool) -> io::Result<File> {
    let name = CString::new(name.as_bytes()).map_err(|_| error("invalid initrc component"))?;
    let flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK |
        if directory { libc::O_DIRECTORY } else { 0 };
    let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    if fd < 0 { return Err(io::Error::last_os_error()); }
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn child(parent: &File, name: &OsStr, directory: bool) -> io::Result<File> {
    let file = open_child(parent, name, directory)?; trusted(&file, directory)?; Ok(file)
}
fn optional(parent: &File, name: &str, directory: bool) -> io::Result<Option<File>> {
    match child(parent, OsStr::new(name), directory) {
        Ok(file) => Ok(Some(file)), Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None), Err(e) => Err(e),
    }
}
fn names(parent: &File) -> io::Result<Vec<OsString>> {
    let mut result = Vec::new();
    for entry in fs::read_dir(format!("/proc/self/fd/{}", parent.as_raw_fd()))? { result.push(entry?.file_name()); }
    result.sort(); Ok(result)
}
fn text(parent: &File, name: &str, limit: usize) -> io::Result<String> {
    let mut file = child(parent, OsStr::new(name), false)?;
    if file.metadata()?.len() > limit as u64 { return Err(error("oversize initrc identity")); }
    let mut out = String::new(); Read::by_ref(&mut file).take((limit + 1) as u64).read_to_string(&mut out)?;
    if out.len() > limit { return Err(error("oversize initrc identity")); }
    Ok(out.trim_end_matches('\n').to_owned())
}
fn marker(parent: &File, name: &str) -> io::Result<bool> {
    let name = CString::new(name).unwrap();
    let mut info = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstatat(parent.as_raw_fd(), name.as_ptr(), info.as_mut_ptr(), libc::AT_SYMLINK_NOFOLLOW) } == 0 {
        let info = unsafe { info.assume_init() };
        if info.st_mode & libc::S_IFMT != libc::S_IFREG || info.st_uid != 0 {
            return Err(error("invalid module initrc marker"));
        }
        return Ok(true);
    }
    let e = io::Error::last_os_error(); if e.kind() == io::ErrorKind::NotFound { Ok(false) } else { Err(e) }
}
fn id(name: &str) -> bool {
    name.as_bytes().first().is_some_and(u8::is_ascii_alphabetic) &&
        name.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
}
fn revision(module: &File, owners: Option<&File>) -> io::Result<String> {
    let info = module.metadata()?;
    let name = format!("{}-{}", info.dev(), info.ino());
    let value = if let Some(owners) = owners {
        match text(owners, &name, 65) {
            Ok(value) => value,
            Err(e) if e.kind() == io::ErrorKind::NotFound => text(module, ".maplesu-ultra", 65)?,
            Err(e) => return Err(e),
        }
    } else { text(module, ".maplesu-ultra", 65)? };
    if value.len() != 64 || !value.bytes().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()) {
        return Err(error("invalid Ultra module revision"));
    }
    Ok(value)
}
fn pending_committed(tx: Option<&File>, module: &File, rev: &str) -> io::Result<bool> {
    let Some(tx) = tx else { return Ok(true); };
    if text(tx, "layout", 32)? != "pending-v2" { return Err(error("module initrc transaction pending")); }
    let Some(_) = optional(tx, "ready", false)? else { return Ok(false); };
    let token = text(tx, "catalog-token", 33)?;
    if token.len() != 32 || !token.bytes().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()) ||
        text(tx, "ready", 33)? != token || text(tx, "next", 65)? != rev {
        return Err(error("module initrc transaction identity mismatch"));
    }
    let m = module.metadata()?;
    if text(tx, "candidate", 64)? != format!("{}:{}", m.dev(), m.ino()) {
        return Err(error("module initrc candidate changed"));
    }
    Ok(true)
}
fn collect(directory: &File, common: bool, out: &mut Vec<u8>) -> io::Result<()> {
    for name in names(directory)? {
        if !name.as_bytes().ends_with(b".rc") { continue; }
        let mut source = child(directory, &name, false)?;
        let before = source.metadata()?;
        if common && before.mode() & 0o111 == 0 { continue; }
        if before.len() > LIMIT as u64 || out.len() + before.len() as usize + 2 > LIMIT {
            return Err(error("module initrc exceeds 1 MiB"));
        }
        out.push(b'\n');
        let remaining = LIMIT - out.len();
        Read::by_ref(&mut source).take(remaining as u64).read_to_end(out)?;
        out.push(b'\n');
        if out.len() > LIMIT { return Err(error("module initrc exceeds 1 MiB")); }
        let after = source.metadata()?;
        let linked = child(directory, &name, false)?.metadata()?;
        if before.dev() != after.dev() || before.ino() != after.ino() || before.len() != after.len() ||
            before.mtime() != after.mtime() || before.mtime_nsec() != after.mtime_nsec() ||
            after.dev() != linked.dev() || after.ino() != linked.ino() {
            return Err(error("module initrc changed while reading"));
        }
    }
    Ok(())
}
fn selected_modules(adb: &File) -> io::Result<BTreeMap<String, File>> {
    let modules = optional(adb, "modules", true)?;
    let updates = optional(adb, "modules_update", true)?;
    let working = optional(adb, "maplesu", true)?;
    let transactions = match &working { Some(w) => optional(w, "module-transactions", true)?, None => None };
    let owners = match &modules { Some(m) => optional(m, ".maplesu-ultra", true)?, None => None };
    let mut selected: BTreeMap<String, Option<File>> = BTreeMap::new();
    for (pending, root) in [(true, updates.as_ref()), (false, modules.as_ref())] {
        let Some(root) = root else { continue; };
        for name in names(root)? {
            let Some(name) = name.to_str().filter(|n| id(n)) else { continue; };
            let module = match child(root, OsStr::new(name), true) {
                Ok(module) => module, Err(e) if matches!(e.raw_os_error(), Some(libc::ENOTDIR) | Some(libc::ELOOP)) => continue, Err(e) => return Err(e),
            };
            let rev = match revision(&module, owners.as_ref()) {
                Ok(rev) => rev, Err(e) if e.kind() == io::ErrorKind::NotFound => continue, Err(e) => return Err(e),
            };
            let tx = match &transactions { Some(t) => optional(t, name, true)?, None => None };
            if pending && !pending_committed(tx.as_ref(), &module, &rev)? { continue; }
            if !pending && tx.is_some() && !selected.contains_key(name) {
                // Before the pending commit, a fresh live placeholder has no
                // previous module. Do not promote its incomplete declaration.
                let tx = tx.as_ref().unwrap();
                if text(tx, "layout", 32)? != "pending-v2" || text(tx, "live", 64)?.is_empty() { continue; }
            }
            if marker(&module, "disable")? || marker(&module, "remove")? {
                selected.insert(name.to_owned(), None); continue;
            }
            selected.entry(name.to_owned()).or_insert(Some(module));
        }
    }
    Ok(selected.into_iter().filter_map(|(id, module)| module.map(|m| (id, m))).collect())
}
fn contents(adb: &File, selected: &BTreeMap<String, File>) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    if let Some(common) = optional(adb, "initrc.d", true)? { collect(&common, true, &mut out)?; }
    for module in selected.values() {
        if let Some(rc) = optional(&module, "initrc", true)? { collect(&rc, false, &mut out)?; }
    }
    Ok(out)
}
#[cfg(target_os = "android")]
fn label_like(file: &File, parent: &File) -> io::Result<()> {
    let mut label = [0u8; 256];
    let count = unsafe { libc::fgetxattr(parent.as_raw_fd(), c"security.selinux".as_ptr(), label.as_mut_ptr().cast(), label.len()) };
    if count <= 0 { return Err(io::Error::last_os_error()); }
    if unsafe { libc::fsetxattr(file.as_raw_fd(), c"security.selinux".as_ptr(), label.as_ptr().cast(), count as usize, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
#[cfg(not(target_os = "android"))]
fn label_like(_: &File, _: &File) -> io::Result<()> { Ok(()) }
fn publish(adb: &File, metadata: &File) -> io::Result<()> {
    let base = if let Some(vold) = optional(metadata, "vold", true)? { vold }
        else if let Some(watchdog) = optional(metadata, "watchdog", true)? { watchdog }
        else { metadata.try_clone()? };
    if unsafe { libc::mkdirat(base.as_raw_fd(), c"maplesu".as_ptr(), 0o700) } != 0 {
        let e = io::Error::last_os_error(); if e.kind() != io::ErrorKind::AlreadyExists { return Err(e); }
    }
    let destination = child(&base, OsStr::new("maplesu"), true)?;
    label_like(&destination, &base)?;
    let lock = unsafe { libc::openat(destination.as_raw_fd(), c".initrc.lock".as_ptr(),
        libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_CREAT, 0o600) };
    if lock < 0 { return Err(io::Error::last_os_error()); }
    let lock = unsafe { File::from_raw_fd(lock) }; trusted(&lock, false)?;
    while unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0 {
        let e = io::Error::last_os_error(); if e.kind() != io::ErrorKind::Interrupted { return Err(e); }
    }
    let selected = selected_modules(adb)?;
    let content = contents(adb, &selected)?;
    // Both products use the exact committed/owned next-boot inventory under
    // this same lock. Holding the module fds pins paths while preinit scans.
    let sources = selected.iter().map(|(id, module)|
        (id.clone(), std::path::PathBuf::from(format!("/proc/self/fd/{}", module.as_raw_fd())))).collect();
    for module in selected.values() { let _ = optional(module, "preinit", true)?; }
    let destination_path = fs::canonicalize(format!("/proc/self/fd/{}", destination.as_raw_fd()))?;
    let destination_info = destination.metadata()?;
    let stale: Vec<_> = ["/metadata/vold/maplesu", "/metadata/watchdog/maplesu", "/metadata/maplesu"]
        .into_iter().map(std::path::PathBuf::from).filter(|p|
            fs::symlink_metadata(p).ok().filter(|m| m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0).map(|m| m.dev() != destination_info.dev() || m.ino() != destination_info.ino()).unwrap_or(false)).collect();
    let stale_refs: Vec<_> = stale.iter().map(|p| p.as_path()).collect();
    #[cfg(target_os = "android")]
    let context = {
        let mut bytes = [0u8; 256];
        let count = unsafe { libc::fgetxattr(base.as_raw_fd(), c"security.selinux".as_ptr(), bytes.as_mut_ptr().cast(), bytes.len()) };
        if count <= 0 { return Err(io::Error::last_os_error()); }
        String::from_utf8(bytes[..count as usize].strip_suffix(&[0]).unwrap_or(&bytes[..count as usize]).to_vec())
            .map_err(|_| error("invalid metadata SELinux context"))?
    };
    #[cfg(not(target_os = "android"))]
    let context = String::new();
    crate::module_preinit::sync(&destination_path, &stale_refs, &sources, &context, true)
        .map_err(|e| io::Error::other(format!("preinit: {e:#}")))?;
    if let Some(mut current) = optional(&destination, "modules.rc", false)? {
        if current.metadata()?.len() <= LIMIT as u64 {
            let mut bytes = Vec::new();
            Read::by_ref(&mut current).take((LIMIT + 1) as u64).read_to_end(&mut bytes)?;
            if bytes == content { label_like(&current, &base)?; return Ok(()); }
        }
    }
    let mut template = format!("/proc/self/fd/{}/.modules.rc.XXXXXX\0", destination.as_raw_fd()).into_bytes();
    let fd = unsafe { libc::mkstemp(template.as_mut_ptr().cast()) };
    if fd < 0 { return Err(io::Error::last_os_error()); }
    let mut file = unsafe { File::from_raw_fd(fd) };
    let name = template[..template.len()-1].rsplit(|b| *b == b'/').next().unwrap();
    let name = CString::new(name).unwrap();
    let result = (|| -> io::Result<()> {
        label_like(&file, &base)?; file.write_all(&content)?; file.sync_all()?;
        if unsafe { libc::renameat(destination.as_raw_fd(), name.as_ptr(), destination.as_raw_fd(), c"modules.rc".as_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        destination.sync_all()?; base.sync_all()
    })();
    if result.is_err() { unsafe { libc::unlinkat(destination.as_raw_fd(), name.as_ptr(), 0); } }
    result
}
pub fn run(args: &[OsString]) -> i32 {
    if !args.is_empty() { eprintln!("maplesu-tools: usage: module-initrc"); return 64; }
    let result = (|| -> io::Result<()> {
        if unsafe { libc::getuid() != 0 || libc::geteuid() != 0 } {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "Root required"));
        }
        let root = File::open("/")?;
        let data = open_child(&root, OsStr::new("data"), true)?;
        let adb = child(&data, OsStr::new("adb"), true)?;
        let metadata = child(&root, OsStr::new("metadata"), true)?;
        publish(&adb, &metadata)
    })();
    match result { Ok(()) => 0, Err(e) => { eprintln!("maplesu-tools: module-initrc: {e}"); 74 } }
}
