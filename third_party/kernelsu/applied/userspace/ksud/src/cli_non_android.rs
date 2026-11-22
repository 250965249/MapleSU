use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;

use crate::boot_patch::{BootPatchArgs, BootRestoreArgs};
use crate::lkm_image::BootPatchV2Args;
use crate::{apk_sign, defs};

/// KernelSU cli for non-android
#[derive(Parser, Debug)]
#[command(author, version = defs::VERSION_NAME, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand, Debug)]
enum Commands {
    /// Patch boot or init_boot images to apply KernelSU
    BootPatch(BootPatchArgs),

    /// Remove vr/vklp from a vendor_boot candidate without flashing.
    BootPatchRmvr(crate::vendor_boot::VendorBootRmvrArgs),

    /// Install the Ultra early vr-only companion into a boot/init_boot ramdisk.
    BootPatchVrBootstrap(crate::vr_bootstrap::VrBootstrapArgs),

    /// Restore boot or init_boot images patched by KernelSU
    BootRestore(BootRestoreArgs),

    /// Patch KernelSU into a boot image
    ///
    /// Always operates on a boot image; never selects init_boot or vendor_boot.
    BootPatchV2(BootPatchV2Args),

    /// Get apk size and hash
    GetSign {
        /// apk path
        apk: String,
    },

    /// show supported kmi versions
    SupportedKmis,

    /// print the ramdisk state of a boot image:
    /// `ours` | `compatible` | `foreign` | `stock` (or `unknown` when it cannot be read).
    RamdiskState {
        /// boot image path
        #[arg(short, long)]
        boot: PathBuf,
    },
}

pub fn run() -> Result<()> {
    env_logger::init();

    let cli = Args::parse();

    log::info!("command: {:?}", cli.command);

    let result = match cli.command {
        Commands::GetSign { apk } => {
            let sign = apk_sign::get_apk_signature(&apk)?;
            println!("size: {:#x}, hash: {}", sign.0, sign.1);
            Ok(())
        }

        Commands::BootPatch(boot_patch) => crate::boot_patch::patch(boot_patch),

        Commands::BootPatchRmvr(args) => crate::vendor_boot::patch_rmvr(args),

        Commands::BootPatchVrBootstrap(args) => crate::vr_bootstrap::patch(args),

        Commands::BootRestore(boot_restore) => crate::boot_patch::restore(boot_restore),

        Commands::BootPatchV2(patch) => crate::lkm_image::patch_boot(&patch),

        Commands::SupportedKmis => {
            let kmi = crate::assets::list_supported_kmi();
            for kmi in &kmi {
                println!("{kmi}");
            }
            Ok(())
        }

        Commands::RamdiskState { boot } => {
            println!("{}", crate::boot_patch::query_ramdisk_state(Some(&boot)));
            Ok(())
        }
    };

    if let Err(e) = &result {
        log::error!("Error: {e:?}");
    }
    result
}
