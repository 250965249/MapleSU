# SPDX-License-Identifier: GPL-3.0-or-later
"""Compile-time daemon identity, separate from the running kernel's identity."""

def patch_identity(tree, _source):
    path = "userspace/ksud/src/cli.rs"
    tree.insert_after(path, "    Info,\n", "    /// Print compile-time identity without querying the kernel.\n    BuildInfo,\n")
    tree.insert_after(path, "            Debug::Info => {\n", '                println!("userspace_version: {}", defs::VERSION_CODE);\n                println!("userspace_uapi_version: {}", ksucalls::uapi_version());\n')
    tree.insert_before(path, "            Debug::Package => {\n", '''            Debug::BuildInfo => {
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
''')
    return [path]

PATCHES_KSUD_IDENTITY = [{
    "name": "0016-ksud-build-identity.patch",
    "apply": patch_identity,
    "status": "implemented",
    "summary": "Report compiled ksud version/UAPI independently of the running kernel",
}]
