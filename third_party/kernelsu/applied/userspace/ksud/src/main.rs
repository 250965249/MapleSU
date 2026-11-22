#![deny(clippy::all, clippy::pedantic)]
#![warn(clippy::nursery)]
#![allow(
    clippy::module_name_repetitions,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    clippy::doc_markdown,
    clippy::too_many_lines,
    clippy::cast_possible_wrap,
    clippy::redundant_field_names
)]

mod apk_sign;
mod assets;
mod boot_patch;
mod vendor_boot;
mod vr_bootstrap;
#[cfg(target_os = "android")]
mod cli;
#[cfg(not(target_os = "android"))]
mod cli_non_android;
#[cfg(target_os = "android")]
mod debug;
mod defs;
#[cfg(target_os = "android")]
mod feature;
mod feature_id;
#[cfg(any(target_os = "android", test))]
mod normal_recovery;
#[cfg(target_os = "android")]
mod normal_superuser;
#[cfg(target_os = "android")]
mod hot_install;
#[cfg(target_os = "android")]
mod init_event;
#[cfg(target_os = "android")]
mod ksucalls;
#[cfg(target_os = "android")]
mod late_load;
mod lkm_image;
mod lkm_image_btf;
#[cfg(target_os = "android")]
mod magica;
#[cfg(target_os = "android")]
mod metamodule;
#[cfg(target_os = "android")]
mod module;
#[cfg(target_os = "android")]
mod module_config;
#[cfg(target_os = "android")]
mod preinit;
#[cfg(target_os = "android")]
mod profile;
#[cfg(target_os = "android")]
mod resetprop;
#[cfg(target_os = "android")]
mod restorecon;
#[cfg(target_os = "android")]
mod sepolicy;
#[cfg(target_os = "android")]
mod soft_reboot;
#[cfg(target_os = "android")]
mod su;
#[cfg(target_os = "android")]
mod sulog;
#[cfg(target_os = "android")]
mod unload;
#[cfg(target_os = "android")]
mod utils;
// MapleSU 0006：webadmin 纯 HTTP 层（7K 注释：故意不加 cfg，宿主也能编/测）
mod webadmin;
#[cfg(target_os = "android")]
mod webadmin_ksud;
// MapleSU 0007：7K 抽出的跨平台小工具（7K 注明故意不加 cfg，宿主可编/测）
mod atomic;
mod script_path;
// MapleSU W18b：资源标签解析（module::packages_info 用；flate2 rust_backend，
// 7K 注明宿主也能编，因此不限定 android）—— 文件由 0007 入库，本补丁接线
// MapleSU W18b（0008b）：卸载备份恢复（纯 std 实现 + CLI，7K main.rs:50）
mod restore_user_data;
mod res_label;

#[cfg(target_os = "android")]
#[allow(nonstandard_style, unused, unsafe_op_in_unsafe_fn)]
mod ksu_uapi;

fn main() -> anyhow::Result<()> {
    #[cfg(target_os = "android")]
    {
        cli::run()
    }
    #[cfg(not(target_os = "android"))]
    {
        cli_non_android::run()
    }
}
