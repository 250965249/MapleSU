use anyhow::{Context, Ok, Result};
use clap::Parser;
use std::path::PathBuf;

use android_logger::Config;
use log::{LevelFilter, error, info};

use crate::boot_patch::{BootPatchArgs, BootRestoreArgs};
use crate::lkm_image::BootPatchV2Args;
use crate::module::regenerate_preinit;
use crate::{
    apk_sign, assets, debug, defs, init_event, ksu_uapi, ksucalls, module, module_config, sulog,
    utils,
};

/// KernelSU userspace cli
#[derive(Parser, Debug)]
#[command(author, version = defs::FULL_VERSION, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

/// 网页管理器的子命令
#[derive(clap::Subcommand, Debug)]
enum Webadmin {
    /// 打开（下次开机或 restart 后生效）
    On,
    /// 关闭
    Off,
    /// 看状态（enabled / token / url）
    Status,
    /// 只打印访问地址（**含专属密钥**，直接复制到浏览器就能用）
    Url,
    /// 换一把访问密钥（用户忘了/怕泄露时用；老链接立刻失效）
    ResetToken,
    /// 在后台起一个（当前进程内，用于调试；正常由开机流程启动）
    Serve {
        /// 指定监听端口（优先于配置文件；换端口靠它）
        #[arg(long)]
        port: Option<u16>,
    },
    /// 重启常驻进程（服务"救活"用：先停再起）
    Restart,
    /// 确保在跑、且跑的是当前这份 ksud；**已经是同一个就不动**
    /// （App 每次打开都调它，避免无谓地断一下服务）
    Sync,
}

#[derive(clap::Subcommand, Debug)]
enum Commands {
    /// Manage KernelSU modules
    Module {
        #[command(subcommand)]
        command: Module,
    },

    /// 内置网页管理器（跑在 ksud 里，不依赖 App）
    Webadmin {
        #[command(subcommand)]
        command: Webadmin,
    },

    /// Fixed root-only Normal mode recovery operations
    #[command(hide = true)]
    NormalRecovery {
        #[arg(value_enum)]
        operation: crate::normal_recovery::Operation,
    },

    /// Fixed root-only Normal authorization operations
    #[command(hide = true)]
    NormalSuperuser {
        #[command(subcommand)]
        operation: crate::normal_superuser::Operation,
    },

    /// Trigger `post-fs-data` event
    PostFsData,

    /// Trigger `service` event
    Services,

    /// Run sulog reader daemon. Not for user. Use `ksud debug sulogd` to launch daemon.
    #[command(hide = true)]
    Sulogd,

    /// Trigger `boot-complete` event
    BootCompleted,

    /// Load kernelsu.ko and execute late-load stage scripts
    LateLoad {
        /// Use adb root to execute late-load for jailbreaking by Magica
        #[arg(long, default_missing_value = "5555", num_args = 0..=1)]
        magica: Option<u16>,

        /// Pass allow_shell=1 when loading kernelsu.ko
        #[arg(long)]
        allow_shell: bool,

        /// Restore adb properties after magica late-load
        #[arg(long)]
        post_magica: bool,

        /// Specify kernel KMI version instead of auto-detection
        #[arg(long)]
        kmi: Option<String>,

        /// manager package name
        #[arg(long, default_value_t = String::from(defs::DEFAULT_PACKAGE_NAME))]
        package_name: String,
    },

    /// Emulate system reboot
    SoftReboot,

    /// Load a kernel module with kallsyms access
    Insmod {
        /// kernel module path
        module: PathBuf,
        /// module load parameters (e.g. key=val key2=val2)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
        params: Vec<String>,
    },

    /// Install KernelSU userspace component to system
    Install {
        #[arg(long, default_value = None)]
        libadbroot: Option<PathBuf>,

        #[arg(long, default_value = None)]
        data_path: Option<PathBuf>,

        /// MapleSU W12b: 切换事务内使用；标签失败时写 .pending_label 而不是失败
        #[arg(long, default_value_t = false)]
        stage_for_switch: bool,
    },

    /// Unload KernelSU kernel module (LKM Only)
    Unload,

    /// Uninstall KernelSU modules and itself(LKM Only)
    Uninstall {
        #[arg(long, default_value_t = String::from(defs::DEFAULT_PACKAGE_NAME))]
        package_name: String,
    },

    /// 从卸载备份恢复用户数据（.allowlist / stealth / stealth_code /
    /// module_configs/ / profile/ / .feature_config）；默认取最新一份，
    /// 逐字节校验后覆盖回 /data/adb/ksu，先把当前数据快照到 <备份>/pre_restore_<ts>/。
    RestoreUserData {
        /// 指定备份目录（绝对路径，或相对 /data/adb 的目录名）；默认最新一份
        #[arg(long)]
        from: Option<PathBuf>,
    },

    /// SELinux policy Patch tool
    Sepolicy {
        #[command(subcommand)]
        command: Sepolicy,
    },

    /// Manage App Profiles
    Profile {
        #[command(subcommand)]
        command: Profile,
    },

    /// Manage kernel features
    Feature {
        #[command(subcommand)]
        command: Feature,
    },

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

    /// Show boot information
    BootInfo {
        #[command(subcommand)]
        command: BootInfo,
    },
    /// For developers
    Debug {
        #[command(subcommand)]
        command: Debug,
    },
    /// Kernel interface
    Kernel {
        #[command(subcommand)]
        command: Kernel,
    },

    /// Resetprop - Magisk-compatible system property tool
    #[command(disable_help_flag = true)]
    Resetprop {
        /// Arguments passed to resetprop
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
        args: Vec<String>,
    },

    /// Manage initrc injection
    Initrc {
        #[command(subcommand)]
        command: Initrc,
    },
}

#[derive(clap::Subcommand, Debug)]
enum BootInfo {
    /// show current kmi version
    CurrentKmi,

    /// show supported kmi versions
    SupportedKmis,

    /// check if device is A/B capable
    IsAbDevice,

    /// show auto-selected boot partition name
    DefaultPartition,

    /// list available partitions for current or OTA toggled slot
    AvailablePartitions,

    /// show slot suffix for current or OTA toggled slot
    SlotSuffix {
        /// toggle to another slot
        #[arg(short = 'u', long, default_value = "false")]
        ota: bool,
    },

    /// print the ramdisk state of a boot image:
    /// `ours` | `compatible` | `foreign` | `stock` (or `unknown` when it cannot be read).
    /// READ-ONLY: never writes anything.
    RamdiskState {
        /// boot image path
        #[arg(short, long, default_value = None)]
        boot: Option<PathBuf>,
    },
}

#[derive(clap::Subcommand, Debug)]
enum Debug {
    /// Set the manager app, kernel CONFIG_KSU_DEBUG should be enabled.
    SetManager {
        /// manager package name
        #[arg(default_value_t = String::from(defs::DEFAULT_PACKAGE_NAME))]
        apk: String,
    },

    /// Get apk size and hash
    GetSign {
        /// apk path
        apk: String,
    },

    /// Root Shell
    Su {
        /// switch to gloabl mount namespace
        #[arg(short, long, default_value = "false")]
        global_mnt: bool,
    },

    /// Get kernel version
    Version,

    /// For testing
    Test,

    /// Extract an embedded binary to a specified path
    ExtractBinary {
        /// binary name (e.g. busybox, resetprop, bootctl)
        name: String,
        /// destination file path
        path: PathBuf,
    },

    /// Process mark management
    Mark {
        #[command(subcommand)]
        command: MarkCommand,
    },

    /// Launch sulogd daemon manually
    Sulogd,

    /// Get kernel info
    Info,
    /// Print compile-time identity without querying the kernel.
    BuildInfo,

    /// Print default package name
    Package,
}

#[derive(clap::Subcommand, Debug)]
enum MarkCommand {
    /// Get mark status for a process (or all)
    Get {
        /// target pid (0 for total count)
        #[arg(default_value = "0")]
        pid: i32,
    },

    /// Mark a process
    Mark {
        /// target pid (0 for all processes)
        #[arg(default_value = "0")]
        pid: i32,
    },

    /// Unmark a process
    Unmark {
        /// target pid (0 for all processes)
        #[arg(default_value = "0")]
        pid: i32,
    },

    /// Refresh mark for all running processes
    Refresh,
}

#[derive(clap::Subcommand, Debug)]
enum Sepolicy {
    /// Patch sepolicy
    Patch {
        /// sepolicy statements
        sepolicy: String,
    },

    /// Apply sepolicy from file
    Apply {
        /// sepolicy file path
        file: String,
    },

    /// Check if sepolicy statement is supported/valid
    Check {
        /// sepolicy statements
        sepolicy: String,
    },
}

#[derive(clap::Subcommand, Debug)]
enum Module {
    /// Install module <ZIP>
    Install {
        /// module zip file path
        zip: String,
    },

    /// Undo module uninstall mark <id>
    UndoUninstall {
        /// module id
        id: String,
    },

    /// Uninstall module <id>
    Uninstall {
        /// module id
        id: String,
    },

    /// enable module <id>
    Enable {
        /// module id
        id: String,
    },

    /// disable module <id>
    Disable {
        // module id
        id: String,
    },

    /// run action for module <id>
    Action {
        // module id
        id: String,
    },

    /// list all modules
    List,

    /// preinit actions run before SELinux policy is loaded
    Preinit {
        #[command(subcommand)]
        command: PreinitCmd,
    },

    /// manage module configuration
    Config {
        /// target internal module name (resolved as internal.<name>)
        #[arg(long)]
        internal: Option<String>,
        #[command(subcommand)]
        command: ModuleConfigCmd,
    },
}

#[derive(clap::Subcommand, Debug)]
enum PreinitCmd {
    /// show per-module preinit state for the next boot
    Status,
    /// re-enable preinit after it was disabled by repeated failed boots
    Reset,
}

#[derive(clap::Subcommand, Debug)]
enum ModuleConfigCmd {
    /// Get a config value
    Get {
        /// config key
        key: String,
    },

    /// Set a config value
    Set {
        /// config key
        key: String,
        /// config value (omit to read from stdin)
        value: Option<String>,
        /// read value from stdin (default if value not provided)
        #[arg(long)]
        stdin: bool,
        /// use temporary config (cleared on reboot)
        #[arg(short, long)]
        temp: bool,
    },

    /// List all config entries
    List,

    /// Delete a config entry
    Delete {
        /// config key
        key: String,
        /// delete from temporary config
        #[arg(short, long)]
        temp: bool,
    },

    /// Clear all config entries
    Clear {
        /// clear temporary config
        #[arg(short, long)]
        temp: bool,
    },
}

#[derive(clap::Subcommand, Debug)]
enum Profile {
    /// get root profile's selinux policy of <package-name>
    GetSepolicy {
        /// package name
        package: String,
    },

    /// set root profile's selinux policy of <package-name> to <profile>
    SetSepolicy {
        /// package name
        package: String,
        /// policy statements
        policy: String,
    },

    /// get template of <id>
    GetTemplate {
        /// template id
        id: String,
    },

    /// set template of <id> to <template string>
    SetTemplate {
        /// template id
        id: String,
        /// template string
        template: String,
    },

    /// delete template of <id>
    DeleteTemplate {
        /// template id
        id: String,
    },

    /// list all templates
    ListTemplates,
}

#[derive(clap::Subcommand, Debug)]
enum Feature {
    /// Get feature value and support status
    Get {
        /// Feature ID or name (su_compat, kernel_umount, sulog, adb_root, selinux_hide, shell_su_adb_only)
        id: String,
        /// Read from config file
        #[arg(long, default_value_t = false)]
        config: bool,
    },

    /// Set feature value
    Set {
        /// Feature ID or name
        id: String,
        /// Feature value (0=disable, 1=enable)
        value: u64,
    },

    /// List all available features
    List,

    /// Check feature status (supported/unsupported/managed/forced)
    Check {
        /// Feature ID or name (su_compat, kernel_umount, sulog, adb_root, selinux_hide, shell_su_adb_only)
        id: String,
    },

    /// Load configuration from file and apply to kernel
    Load,

    /// Save current kernel feature states to file
    Save,
}

#[derive(clap::Subcommand, Debug)]
enum Kernel {
    /// Nuke ext4 sysfs
    NukeExt4Sysfs {
        /// mount point
        mnt: String,
    },
    /// Manage umount list
    Umount {
        #[command(subcommand)]
        command: UmountOp,
    },
    /// Notify that module is mounted
    NotifyModuleMounted,
}

#[derive(clap::Subcommand, Debug)]
enum UmountOp {
    /// Add mount point to umount list
    Add {
        /// mount point path
        mnt: String,
        /// umount flags (default: 0, MNT_DETACH: 2)
        #[arg(short, long, default_value = "0")]
        flags: u32,
    },
    /// Delete mount point from umount list
    Del {
        /// mount point path
        mnt: String,
    },
    /// Wipe all entries from umount list
    Wipe,
}

#[derive(clap::Subcommand, Debug)]
enum Initrc {
    /// Regenerate preinit rc file and preinit dirs
    Refresh,
}

pub fn run() -> Result<()> {
    android_logger::init_once(
        Config::default()
            .with_max_level(crate::debug_select!(LevelFilter::Trace, LevelFilter::Info))
            .with_tag("KernelSU"),
    );

    ksucalls::setup_sigsys_handler();

    // the kernel executes su with argv[0] = "su" and replace it with us
    let arg0 = std::env::args().next().unwrap_or_default();
    if arg0 == "su" || arg0.ends_with("/su") {
        return crate::su::root_shell();
    }

    if arg0.ends_with("resetprop") {
        let all_args: Vec<String> = std::env::args().collect();
        crate::resetprop::resetprop_main(&all_args)
    }

    let cli = Args::parse();

    log::info!("command: {:?}", cli.command);

    let result = match cli.command {
        Commands::Webadmin { command } => match command {
            Webadmin::On => {
                crate::webadmin_ksud::set_enabled(true)?;
                crate::webadmin_ksud::ensure_running()?;
                println!("网页管理器：已开启（ksud 常驻，不依赖 App）");
                // 顺手把**带密钥的完整地址**打出来：用户/App 都需要它
                println!("{}", crate::webadmin::url());
                Ok(())
            }
            Webadmin::Off => {
                crate::webadmin_ksud::set_enabled(false)?;
                crate::webadmin_ksud::stop_running()?;
                println!("网页管理器：已关闭");
                Ok(())
            }
            Webadmin::Status => {
                println!("{}", crate::webadmin_ksud::status_text());
                Ok(())
            }
            Webadmin::Url => {
                // ⚠️ 这条命令的 stdout **含访问密钥** —— 只有调用方（App / 用户）看得到，
                //    绝不要把它重定向进日志文件。
                println!("{}", crate::webadmin::url());
                Ok(())
            }
            Webadmin::ResetToken => {
                let url = crate::webadmin_ksud::reset_token_url()?;
                println!("网页管理器：访问密钥已重置（旧链接立即失效）");
                println!("{url}");
                Ok(())
            }
            Webadmin::Sync => {
                let restarted = crate::webadmin_ksud::sync_if_needed()?;
                println!(
                    "网页管理器：{}",
                    if restarted {
                        "ksud 换过版本（或本来没在跑），已确保新版在跑"
                    } else {
                        "已在运行且就是当前版本，没动它"
                    }
                );
                Ok(())
            }
            Webadmin::Restart => {
                crate::webadmin_ksud::set_enabled(true)?;
                let ok = crate::webadmin_ksud::restart()?;
                println!(
                    "网页管理器：已重启（{}）",
                    if ok { "在跑" } else { "拉起失败" }
                );
                Ok(())
            }
            Webadmin::Serve { port } => {
                // 常驻进程本体：前台跑到底（由 ensure_running() 以脱离会话的方式拉起）
                crate::webadmin_ksud::serve_forever(port);
            }
        },
        Commands::NormalRecovery { operation } => crate::normal_recovery::run(operation),
        Commands::NormalSuperuser { operation } => crate::normal_superuser::run(operation),
        Commands::PostFsData => init_event::on_post_fs_data(),
        Commands::BootCompleted => {
            init_event::on_boot_completed();
            Ok(())
        }

        Commands::SoftReboot => crate::soft_reboot::soft_reboot(),

        Commands::Insmod { module, params } => debug::insmod(&module, &params),

        Commands::Module { command } => {
            utils::switch_mnt_ns(1)?;
            match command {
                Module::Install { zip } => module::install_module(&zip),
                Module::UndoUninstall { id } => module::undo_uninstall_module(&id),
                Module::Uninstall { id } => module::uninstall_module(&id),
                Module::Enable { id } => module::enable_module(&id),
                Module::Disable { id } => module::disable_module(&id),
                Module::Action { id } => module::run_action(&id),
                Module::List => module::list_modules(),
                Module::Preinit { command } => match command {
                    PreinitCmd::Status => {
                        crate::preinit::print_status();
                        Ok(())
                    }
                    PreinitCmd::Reset => crate::preinit::reset_bootcount(),
                },
                Module::Config { internal, command } => {
                    let module_id = match internal {
                        Some(internal_name) => format!("internal.{internal_name}"),
                        None => std::env::var("KSU_MODULE").map_err(|_| {
                            anyhow::anyhow!(
                                "This command must be run in the context of a module or passed --internal <name>"
                            )
                        })?,
                    };
                    crate::module::validate_module_id(&module_id)?;

                    match command {
                        ModuleConfigCmd::Get { key } => {
                            // Use merge_configs to respect priority (temp overrides persist)
                            let config = module_config::merge_configs(&module_id)?;
                            match config.get(&key) {
                                Some(value) => {
                                    println!("{value}");
                                    Ok(())
                                }
                                None => anyhow::bail!("Key '{key}' not found"),
                            }
                        }
                        ModuleConfigCmd::Set {
                            key,
                            value,
                            stdin,
                            temp,
                        } => {
                            // Validate key at CLI layer for better user experience
                            module_config::validate_config_key(&key)?;

                            // Read value from stdin or argument
                            let value_str = match value {
                                Some(v) if !stdin => v,
                                _ => {
                                    // Read from stdin
                                    use std::io::Read;
                                    let mut buffer = String::new();
                                    std::io::stdin()
                                        .read_to_string(&mut buffer)
                                        .context("Failed to read from stdin")?;
                                    buffer
                                }
                            };

                            // Validate value
                            module_config::validate_config_value(&value_str)?;

                            let config_type = if temp {
                                module_config::ConfigType::Temp
                            } else {
                                module_config::ConfigType::Persist
                            };
                            module_config::set_config_value(
                                &module_id,
                                &key,
                                &value_str,
                                config_type,
                            )
                        }
                        ModuleConfigCmd::List => {
                            let config = module_config::merge_configs(&module_id)?;
                            if config.is_empty() {
                                println!("No config entries found");
                            } else {
                                for (key, value) in config {
                                    println!("{key}={value}");
                                }
                            }
                            Ok(())
                        }
                        ModuleConfigCmd::Delete { key, temp } => {
                            let config_type = if temp {
                                module_config::ConfigType::Temp
                            } else {
                                module_config::ConfigType::Persist
                            };
                            module_config::delete_config_value(&module_id, &key, config_type)
                        }
                        ModuleConfigCmd::Clear { temp } => {
                            let config_type = if temp {
                                module_config::ConfigType::Temp
                            } else {
                                module_config::ConfigType::Persist
                            };
                            module_config::clear_config(&module_id, config_type)
                        }
                    }
                }
            }
        }
        Commands::Install {
            libadbroot,
            data_path,
            stage_for_switch,
        } => utils::install(libadbroot, data_path, stage_for_switch),
        Commands::Unload => crate::unload::unload(),
        Commands::Uninstall { package_name } => utils::uninstall(&package_name),
        Commands::RestoreUserData { from } => utils::restore_user_data(from.as_deref()),
        Commands::Sepolicy { command } => match command {
            Sepolicy::Patch { sepolicy } => crate::sepolicy::live_patch(&sepolicy),
            Sepolicy::Apply { file } => crate::sepolicy::apply_file(file),
            Sepolicy::Check { sepolicy } => crate::sepolicy::check_rule(&sepolicy),
        },
        Commands::LateLoad {
            magica,
            allow_shell,
            post_magica,
            kmi,
            package_name,
        } => {
            if let Some(port) = magica {
                return crate::magica::run(port, &package_name, allow_shell).map_err(|e| {
                    error!("Error running magica: {e}");
                    e
                });
            }
            let result = crate::late_load::run(&package_name, kmi, allow_shell);
            if post_magica {
                info!("Restoring adb properties (post-magica cleanup)...");
                if let Err(e) = crate::magica::disable_adb_root() {
                    error!("disable adb root failed: {e}");
                }
            }
            result
        }
        Commands::Services => {
            if ksucalls::get_version() <= 0 {
                info!("KernelSU not available, exiting services");
                std::process::exit(0);
            }
            init_event::on_services();
            Ok(())
        }
        Commands::Sulogd => sulog::run_sulogd(),
        Commands::Profile { command } => match command {
            Profile::GetSepolicy { package } => crate::profile::get_sepolicy(&package),
            Profile::SetSepolicy { package, policy } => {
                crate::profile::set_sepolicy(&package, policy)
            }
            Profile::GetTemplate { id } => crate::profile::get_template(&id),
            Profile::SetTemplate { id, template } => crate::profile::set_template(&id, template),
            Profile::DeleteTemplate { id } => crate::profile::delete_template(&id),
            Profile::ListTemplates => crate::profile::list_templates(),
        },

        Commands::Feature { command } => match command {
            Feature::Get { id, config } => {
                if config {
                    crate::feature::get_feature_config(&id)
                } else {
                    crate::feature::get_feature(&id)
                }
            }
            Feature::Set { id, value } => crate::feature::set_feature(&id, value),
            Feature::List => {
                crate::feature::list_features();
                Ok(())
            }
            Feature::Check { id } => crate::feature::check_feature(&id),
            Feature::Load => crate::feature::load_config_and_apply(),
            Feature::Save => crate::feature::save_config(),
        },

        Commands::Debug { command } => match command {
            Debug::SetManager { apk } => debug::set_manager(&apk),
            Debug::GetSign { apk } => {
                let sign = apk_sign::get_apk_signature(&apk)?;
                println!("size: {:#x}, hash: {}", sign.0, sign.1);
                Ok(())
            }
            Debug::Version => {
                println!("Kernel Version: {}", ksucalls::get_version());
                Ok(())
            }
            Debug::Su { global_mnt } => crate::su::grant_root(global_mnt),
            Debug::Test => assets::ensure_binaries(false),
            Debug::ExtractBinary { name, path } => {
                let data = assets::get_asset_data(&name)?;
                utils::ensure_binary(&path, &data, false)
            }
            Debug::Mark { command } => match command {
                MarkCommand::Get { pid } => debug::mark_get(pid),
                MarkCommand::Mark { pid } => debug::mark_set(pid),
                MarkCommand::Unmark { pid } => debug::mark_unset(pid),
                MarkCommand::Refresh => debug::mark_refresh(),
            },
            Debug::Sulogd => sulog::ensure_sulogd_running(),
            Debug::Info => {
                println!("userspace_version: {}", defs::VERSION_CODE);
                println!("userspace_uapi_version: {}", ksucalls::uapi_version());
                let info = ksucalls::get_info();
                println!("version: {}", info.version);
                println!("flags: 0x{:x}", info.flags);
                println!("uapi_version: {}", info.uapi_version);
                println!("features: 0x{:x}", info.features);
                println!("lkm: {}", ksucalls::is_lkm());
                println!(
                    "bundled: {}",
                    (info.flags & ksu_uapi::KSU_GET_INFO_FLAG_BUNDLED) != 0
                );
                println!("late_load: {}", ksucalls::is_late_load());
                println!("runtime_mode: {}", ksucalls::runtime_mode());
                println!(
                    "pr_build: {}",
                    (info.flags & ksu_uapi::KSU_GET_INFO_FLAG_PR_BUILD) != 0
                );
                Ok(())
            }
            Debug::BuildInfo => {
                println!(
                    "{}",
                    const_format::formatcp!(
                        "MAPLESU_KSUD_BUILD_V1 version={} uapi={}",
                        defs::VERSION_CODE,
                        ksu_uapi::KERNEL_SU_UAPI_VERSION
                    )
                );
                Ok(())
            }
            Debug::Package => {
                println!("{}", defs::DEFAULT_PACKAGE_NAME);
                Ok(())
            }
        },

        Commands::BootPatch(boot_patch) => crate::boot_patch::patch(boot_patch),

        Commands::BootPatchRmvr(args) => crate::vendor_boot::patch_rmvr(args),

        Commands::BootPatchVrBootstrap(args) => crate::vr_bootstrap::patch(args),

        Commands::BootInfo { command } => match command {
            BootInfo::CurrentKmi => {
                let kmi = crate::boot_patch::get_current_kmi()?;
                println!("{kmi}");
                // return here to avoid printing the error message
                return Ok(());
            }
            BootInfo::SupportedKmis => {
                let kmi = crate::assets::list_supported_kmi();
                for kmi in &kmi {
                    println!("{kmi}");
                }
                return Ok(());
            }
            BootInfo::IsAbDevice => {
                let val = crate::utils::getprop("ro.build.ab_update")
                    .unwrap_or_else(|| String::from("false"));
                let is_ab = val.trim().to_lowercase() == "true";
                println!("{}", if is_ab { "true" } else { "false" });
                return Ok(());
            }
            BootInfo::DefaultPartition => {
                let kmi = crate::boot_patch::get_current_kmi().unwrap_or_else(|_| String::new());
                let name = crate::boot_patch::choose_boot_partition(&kmi, false, &None);
                println!("{name}");
                return Ok(());
            }
            BootInfo::SlotSuffix { ota } => {
                let suffix = crate::boot_patch::get_slot_suffix(ota);
                println!("{suffix}");
                return Ok(());
            }
            BootInfo::AvailablePartitions => {
                let parts = crate::boot_patch::list_available_partitions();
                for p in &parts {
                    println!("{p}");
                }
                return Ok(());
            }
            BootInfo::RamdiskState { boot } => {
                // 与 host CLI 同源同判据（query_ramdisk_state）；输出恰好一个词
                println!("{}", crate::boot_patch::query_ramdisk_state(boot.as_deref()));
                return Ok(());
            }
        },
        Commands::BootRestore(boot_restore) => crate::boot_patch::restore(boot_restore),
        Commands::BootPatchV2(patch) => crate::lkm_image::patch_boot(&patch),
        Commands::Resetprop { args } => {
            let mut full_args = vec!["resetprop".to_string()];
            full_args.extend(args);
            crate::resetprop::resetprop_main(&full_args)
        }

        Commands::Kernel { command } => match command {
            Kernel::NukeExt4Sysfs { mnt } => ksucalls::nuke_ext4_sysfs(&mnt),
            Kernel::Umount { command } => match command {
                UmountOp::Add { mnt, flags } => ksucalls::umount_list_add(&mnt, flags),
                UmountOp::Del { mnt } => ksucalls::umount_list_del(&mnt),
                UmountOp::Wipe => ksucalls::umount_list_wipe(),
            },
            Kernel::NotifyModuleMounted => {
                ksucalls::report_module_mounted();
                Ok(())
            }
        },
        Commands::Initrc { command } => match command {
            Initrc::Refresh => regenerate_preinit(),
        },
    };

    if let Err(e) = &result {
        log::error!("Error: {e:?}");
    }
    result
}
