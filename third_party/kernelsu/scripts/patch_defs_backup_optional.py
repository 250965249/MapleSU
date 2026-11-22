#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Keep boot-patch backups best-effort, matching the pinned KSU upstream."""

BOOT_PATCH = "userspace/ksud/src/boot_patch.rs"
BACKUP_FLASH_ABORT = '''\
                            if flash {
                                return Err(e).context(
                                    "backup before flash failed; refusing to write the partition",
                                );
                            }
'''


def patch_boot_backup_optional(tree, _source) -> list[str]:
    tree.replace_once(BOOT_PATCH, BACKUP_FLASH_ABORT, "")
    return [BOOT_PATCH]


PATCHES_BACKUP_OPTIONAL = [{
    "name": "0023-boot-backup-optional.patch",
    "summary": "Keep boot-patch backup failures non-blocking and retain successful backups for verified rollback",
    "apply": patch_boot_backup_optional,
    "status": "implemented",
    "checks": [[BOOT_PATCH, ['println!("- Backup stock image failed: {e:?}");']]],
}]
