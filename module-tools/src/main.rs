//! MapleSU module tool multicall host.
//!
//! Shape is taken from the pinned KSU userspace contract rather than invented:
//!
//! * `cli.rs:521-524` dispatches on the **complete** argv[0] with a suffix test
//!   (`arg0.ends_with("resetprop")`), not on a basename and not on a subcommand.
//! * `assets.rs:26-28` publishes `BINARY_DIR/resetprop` as a **symlink** to the
//!   host binary; the host is the only real executable.
//! * `cli.rs:814-819` additionally accepts `ksud resetprop <args>` and rebuilds
//!   `["resetprop", ...args]` before dispatching, so a subcommand path exists
//!   alongside the symlink path.
//!
//! The resetprop CLI implementation itself is **not** reimplemented here. It is
//! the upstream `resetprop_main` from the pinned `ksu_props` checkout, included
//! by path, so flags, exit codes and stream usage stay upstream-identical.

// Included from the pinned checkout instead of copied: `include!`/`#[path]` keeps
// the bytes authoritative in ksu_props, so a source update there is a deliberate
// build input change rather than a silently diverging fork.
#[path = "../../third_party/ksu_props/src/tools/resetprop/src/resetprop_main.rs"]
mod resetprop_main;
mod module_sync;
mod module_initrc;
mod module_preinit;

use std::ffi::OsString;

/// Name the host reports for itself. Only used when no tool name is derivable,
/// which happens when argv[0] is missing or is not one of the tool names.
const HOST_NAME: &str = "maplesu-tools";

fn main() {
    let mut args: Vec<OsString> = std::env::args_os().collect();
    let arg0 = args
        .first()
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_default();

    // KSU: `if arg0.ends_with("resetprop") { resetprop_main(&all_args) }`.
    // The suffix test deliberately matches `/data/adb/.../bin/resetprop` and a
    // bare `resetprop`, exactly like upstream.
    if arg0.ends_with("resetprop") {
        resetprop_main::resetprop_main(&to_string_args(&args))
    }

    // KSU also exposes the tool as a subcommand (`cli.rs:814-819`). Accept the
    // same spelling so a caller that already prefixes the host name keeps
    // working; rebuild argv[0] as `resetprop` so the reused CLI sees the name it
    // declares in its clap attributes.
    if let Some(first) = args.get(1) {
        if first == "module-preinit" {
            if unsafe { libc::getuid() != 0 || libc::geteuid() != 0 } {
                eprintln!("maplesu-tools: module-preinit: Root required"); std::process::exit(74);
            }
            let code = match args.get(2).and_then(|v| v.to_str()) {
                Some("boot-completed") if args.len() == 3 => module_preinit::on_boot_completed(),
                Some("reset") if args.len() == 3 => module_preinit::reset_bootcount(),
                Some("status") if args.len() == 3 => { module_preinit::print_status(); Ok(()) },
                _ => { eprintln!("maplesu-tools: usage: module-preinit status|reset|boot-completed"); std::process::exit(64); }
            };
            if let Err(error) = code { eprintln!("maplesu-tools: module-preinit: {error:#}"); std::process::exit(74); }
            std::process::exit(0);
        }
        if first == "module-initrc" {
            std::process::exit(module_initrc::run(&args[2..]));
        }
        if first == "module-sync" {
            std::process::exit(module_sync::run(&args[2..]));
        }
        if first.to_string_lossy() == "resetprop" {
            args.remove(1);
            args[0] = OsString::from("resetprop");
            resetprop_main::resetprop_main(&to_string_args(&args))
        }
    }

    // No recognized tool name. This must stay a hard failure: silently doing
    // nothing would let a caller believe a module tool ran when it did not.
    eprintln!(
        "{HOST_NAME}: unrecognized invocation name '{arg0}'; \
         invoke through the published tool symlink or as `{HOST_NAME} resetprop ...`"
    );
    std::process::exit(64);
}

/// The reused CLI takes `Vec<String>`; module argument paths are UTF-8 by
/// contract on this platform, and a non-UTF-8 argument is a caller error rather
/// than something to silently mangle.
fn to_string_args(args: &[OsString]) -> Vec<String> {
    args.iter()
        .map(|value| {
            value.to_str().map(ToOwned::to_owned).unwrap_or_else(|| {
                eprintln!("{HOST_NAME}: argument is not valid UTF-8");
                std::process::exit(64);
            })
        })
        .collect()
}
