#![no_main]
#[path = "../init.rs"]
#[allow(dead_code)]
mod init;
use rustix::{cstr, runtime::execve};

/// # Safety
/// Android's kernel supplies the original PID 1 argv/envp vectors.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn main(_argc: i32, argv: *const *const u8, envp: *const *const u8) -> i32 {
    if let Err(error) = init::vr_init() {
        log::error!("MapleSU vr: init handoff failed: {error:#}");
        return 1;
    }
    unsafe { execve(cstr!("/init"), argv, envp); }
    1
}
