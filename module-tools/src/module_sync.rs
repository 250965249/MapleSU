use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn open_child(parent: &File, name: &OsStr, directory: bool) -> io::Result<File> {
    let name = CString::new(name.as_bytes()).map_err(|_| invalid("invalid path component"))?;
    let flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK
        | if directory { libc::O_DIRECTORY } else { 0 };
    let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    if fd < 0 { return Err(io::Error::last_os_error()); }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn anchor() -> io::Result<File> {
    let fd = unsafe {
        libc::open(c"/".as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC)
    };
    if fd < 0 { return Err(io::Error::last_os_error()); }
    let root = unsafe { File::from_raw_fd(fd) };
    let data = open_child(&root, OsStr::new("data"), true)?;
    let adb = open_child(&data, OsStr::new("adb"), true)?;
    let info = adb.metadata()?;
    if info.uid() != 0 || info.mode() & 0o022 != 0 {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "untrusted module storage root"));
    }
    Ok(adb)
}

struct Entries(*mut libc::DIR);
impl Drop for Entries {
    fn drop(&mut self) { unsafe { libc::closedir(self.0); } }
}

fn child_identity(parent: &File, name: &CStr) -> io::Result<libc::stat> {
    let mut info = std::mem::MaybeUninit::uninit();
    if unsafe { libc::fstatat(parent.as_raw_fd(), name.as_ptr(), info.as_mut_ptr(), libc::AT_SYMLINK_NOFOLLOW) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { info.assume_init() })
}

fn sync_node(file: &File, tree: bool) -> io::Result<()> {
    let info = file.metadata()?;
    if info.is_dir() && tree {
        let duplicate = open_child(file, OsStr::new("."), true)?.into_raw_fd();
        let stream = unsafe { libc::fdopendir(duplicate) };
        if stream.is_null() {
            let error = io::Error::last_os_error();
            unsafe { libc::close(duplicate); }
            return Err(error);
        }
        let entries = Entries(stream);
        loop {
            #[cfg(target_os = "android")]
            unsafe { *libc::__errno() = 0; }
            #[cfg(target_os = "linux")]
            unsafe { *libc::__errno_location() = 0; }
            let entry = unsafe { libc::readdir(entries.0) };
            if entry.is_null() {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(0) { return Err(error); }
                break;
            }
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
            if name.to_bytes() == b"." || name.to_bytes() == b".." { continue; }
            let before = child_identity(file, name)?;
            let kind = before.st_mode & libc::S_IFMT;
            if kind != libc::S_IFREG && kind != libc::S_IFDIR { continue; }
            let child = open_child(file, OsStr::from_bytes(name.to_bytes()), kind == libc::S_IFDIR)?;
            let opened = child.metadata()?;
            if opened.dev() != before.st_dev as u64 || opened.ino() != before.st_ino as u64 {
                return Err(io::Error::other("module tree changed during synchronization"));
            }
            sync_node(&child, true)?;
            let linked = child_identity(file, name)?;
            if opened.dev() != linked.st_dev as u64 || opened.ino() != linked.st_ino as u64 {
                return Err(io::Error::other("module tree changed during synchronization"));
            }
        }
    } else if !info.is_dir() && !info.is_file() {
        return Err(invalid("module synchronization requires a regular file or directory"));
    }
    file.sync_all()
}

fn open_relative(root: &File, parts: &[&OsStr]) -> io::Result<File> {
    let mut parent = root.try_clone()?;
    let Some((name, parents)) = parts.split_last() else { return Ok(parent); };
    for component in parents { parent = open_child(&parent, component, true)?; }
    let name_c = CString::new(name.as_bytes()).map_err(|_| invalid("invalid path component"))?;
    let before = child_identity(&parent, &name_c)?;
    let kind = before.st_mode & libc::S_IFMT;
    if kind != libc::S_IFREG && kind != libc::S_IFDIR {
        return Err(invalid("module synchronization requires a regular file or directory"));
    }
    let file = open_child(&parent, name, kind == libc::S_IFDIR)?;
    let opened = file.metadata()?;
    if opened.dev() != before.st_dev as u64 || opened.ino() != before.st_ino as u64 {
        return Err(io::Error::other("module synchronization target changed"));
    }
    Ok(file)
}

fn sync_relative(root: &File, path: &Path, tree: bool) -> io::Result<()> {
    let mut parts = Vec::new();
    for part in path.components() {
        match part {
            Component::Normal(name) => parts.push(name),
            _ => return Err(invalid("path is outside module storage")),
        }
    }
    let file = open_relative(root, &parts)?;
    let opened = file.metadata()?;
    sync_node(&file, tree)?;
    let linked = open_relative(root, &parts)?.metadata()?;
    if opened.dev() != linked.dev() || opened.ino() != linked.ino() {
        return Err(io::Error::other("module synchronization target changed"));
    }
    Ok(())
}

pub fn run(args: &[OsString]) -> i32 {
    let (tree, paths) = if args.first().is_some_and(|arg| arg == "--tree") {
        (true, &args[1..])
    } else { (false, args) };
    if paths.is_empty() {
        eprintln!("maplesu-tools: usage: module-sync [--tree] PATH...");
        return 64;
    }
    let result = (|| -> io::Result<()> {
        if unsafe { libc::getuid() != 0 || libc::geteuid() != 0 } {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "Root required"));
        }
        let root = anchor()?;
        for path in paths {
            let relative = Path::new(path).strip_prefix("/data/adb")
                .map_err(|_| invalid("path is outside module storage"))?;
            sync_relative(&root, relative, tree)?;
        }
        let opened = root.metadata()?;
        let current = anchor()?.metadata()?;
        if opened.dev() != current.dev() || opened.ino() != current.ino() {
            return Err(io::Error::other("module storage root changed"));
        }
        Ok(())
    })();
    match result {
        Ok(()) => 0,
        Err(error) => { eprintln!("maplesu-tools: module-sync: {error}"); 74 }
    }
}
