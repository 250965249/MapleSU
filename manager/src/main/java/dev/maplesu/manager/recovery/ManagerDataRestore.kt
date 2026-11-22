package dev.maplesu.manager.recovery

/** Historical UIDs establish which files may be migrated, not the identity of a new install. */
internal fun managerDataVerificationScript(packageName: String, retainedUid: Int?, backupGeneration: Long): String {
    require(packageName.matches(Regex("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+")))
    require(retainedUid == null || retainedUid in 10000..99999)
    require(backupGeneration >= 0)
    return """
        fail() { printf 'MAPLESU_RESTORE_DATA_FAILED=%s\n' "${'$'}1"; exit 1; }
        DATA='/data/user/0/$packageName'
        DE='/data/user_de/0/$packageName'
        OLD='${retainedUid ?: ""}'
        package_uid() {
          PACKAGES=${'$'}(pm list packages -U --user 0 '$packageName' 2>/dev/null) || return 1
          LINE=${'$'}(printf '%s\n' "${'$'}PACKAGES" | tr -d '\r' | sed 's/[[:space:]]*${'$'}//' | grep -F 'package:$packageName uid:')
          CURRENT=${'$'}{LINE#package:$packageName uid:}
          case "${'$'}CURRENT" in ''|*[!0-9]*) return 1 ;; esac
          [ "${'$'}LINE" = "package:$packageName uid:${'$'}CURRENT" ] &&
            [ "${'$'}CURRENT" -ge 10000 ] && [ "${'$'}CURRENT" -lt 100000 ]
        }
        package_uid || fail DATA_PACKAGE_QUERY_FAILED
        NEW=${'$'}CURRENT
        [ -d "${'$'}DATA" ] || fail DATA_DIRECTORY_MISSING
        REPAIR=0
        for D in "${'$'}DATA" "${'$'}DE"; do
          [ ! -L "${'$'}D" ] || fail DATA_DIRECTORY_UNSAFE
          [ -e "${'$'}D" ] || continue
          [ -d "${'$'}D" ] || fail DATA_DIRECTORY_UNSAFE
          OWNER=${'$'}(stat -L -c '%u' "${'$'}D" 2>/dev/null) || fail DATA_OWNER_UNREADABLE
          case "${'$'}OWNER" in ''|*[!0-9]*) fail DATA_OWNER_UNREADABLE ;; esac
          if [ "${'$'}OWNER" != "${'$'}NEW" ]; then
            [ -n "${'$'}OLD" ] && [ "${'$'}OWNER" = "${'$'}OLD" ] || fail DATA_PACKAGE_UID_MISMATCH
            REPAIR=1
          fi
          if [ -n "${'$'}OLD" ] && [ "${'$'}OLD" != "${'$'}NEW" ]; then
            LEFT=${'$'}(find "${'$'}D" -xdev \( -user "${'$'}OLD" -o -group "${'$'}OLD" -o -group "${'$'}((OLD + 10000))" \) -print -quit) || fail DATA_OWNER_UNREADABLE
            [ -z "${'$'}LEFT" ] || REPAIR=1
          fi
        done
        if [ "${'$'}REPAIR" = 1 ]; then
          # Stop writes before the rollback snapshot; never chown an unrelated package tree.
          am force-stop --user 0 '$packageName' >/dev/null 2>&1 || fail DATA_MIGRATION_FAILED
          package_uid && [ "${'$'}CURRENT" = "${'$'}NEW" ] || fail DATA_PACKAGE_QUERY_FAILED
          ROOT='${RecoveryPaths.DIR}'
          [ ! -L "${'$'}ROOT" ] && [ "${'$'}(stat -c '%a %u' "${'$'}ROOT" 2>/dev/null)" = '700 0' ] || fail DATA_BACKUP_FAILED
          BACKUP="${'$'}ROOT/manager-data-uid-$backupGeneration-${'$'}OLD-${'$'}NEW"
          if [ ! -e "${'$'}BACKUP" ] && [ ! -L "${'$'}BACKUP" ]; then
            STAGE="${'$'}BACKUP.tmp.${'$'}${'$'}"
            umask 077
            mkdir "${'$'}STAGE" || fail DATA_BACKUP_FAILED
            trap 'rm -f "${'$'}STAGE/data.tar" "${'$'}STAGE/data.sha256"; rmdir "${'$'}STAGE" 2>/dev/null' EXIT
            trap 'exit 1' HUP INT TERM
            set -- 'user/0/$packageName'
            [ ! -d "${'$'}DE" ] || set -- "${'$'}@" 'user_de/0/$packageName'
            tar -cpf "${'$'}STAGE/data.tar" -C /data "${'$'}@" && chmod 600 "${'$'}STAGE/data.tar" &&
              (cd "${'$'}STAGE" && sha256sum data.tar > data.sha256 && tar -tf data.tar >/dev/null) &&
              sync && mv "${'$'}STAGE" "${'$'}BACKUP" || fail DATA_BACKUP_FAILED
            trap - EXIT HUP INT TERM
          fi
          [ ! -L "${'$'}BACKUP" ] && [ "${'$'}(stat -c '%a %u' "${'$'}BACKUP")" = '700 0' ] &&
            [ ! -L "${'$'}BACKUP/data.tar" ] && [ ! -L "${'$'}BACKUP/data.sha256" ] &&
            [ "${'$'}(stat -c '%a %u' "${'$'}BACKUP/data.tar")" = '600 0' ] &&
            [ "${'$'}(stat -c '%a %u' "${'$'}BACKUP/data.sha256")" = '600 0' ] &&
            (cd "${'$'}BACKUP" && sha256sum -c data.sha256 >/dev/null 2>&1) || fail DATA_BACKUP_FAILED
          echo MAPLESU_RESTORE_DATA_BACKUP_OK
          for D in "${'$'}DATA" "${'$'}DE"; do
            [ -d "${'$'}D" ] || continue
            find "${'$'}D" -xdev -user "${'$'}OLD" -exec chown -h "${'$'}NEW" {} + &&
              find "${'$'}D" -xdev -group "${'$'}OLD" -exec chgrp -h "${'$'}NEW" {} + &&
              find "${'$'}D" -xdev -group "${'$'}((OLD + 10000))" -exec chgrp -h "${'$'}((NEW + 10000))" {} + || fail DATA_MIGRATION_FAILED
            LEFT=${'$'}(find "${'$'}D" -xdev \( -user "${'$'}OLD" -o -group "${'$'}OLD" -o -group "${'$'}((OLD + 10000))" \) -print -quit) || fail DATA_MIGRATION_FAILED
            [ -z "${'$'}LEFT" ] || fail DATA_MIGRATION_FAILED
          done
        fi
        if [ -n "${'$'}OLD" ] && [ "${'$'}OLD" != "${'$'}NEW" ]; then
          for D in "${'$'}DATA" "${'$'}DE"; do
            [ -d "${'$'}D" ] || continue
            restorecon -RF -D "${'$'}D" >/dev/null 2>&1 || fail DATA_LABEL_RESTORE_FAILED
          done
          echo MAPLESU_RESTORE_UID_CHANGED
        fi
        package_uid && [ "${'$'}CURRENT" = "${'$'}NEW" ] || fail DATA_PACKAGE_QUERY_FAILED
        for D in "${'$'}DATA" "${'$'}DE"; do
          [ -d "${'$'}D" ] || continue
          [ "${'$'}(stat -L -c '%u' "${'$'}D" 2>/dev/null)" = "${'$'}NEW" ] || fail DATA_PACKAGE_UID_MISMATCH
        done
        echo MAPLESU_RESTORE_DATA_OK
    """.trimIndent()
}
