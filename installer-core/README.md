# installer-core/

Install transactions in plain Java: file and block-device writes, multi-partition plans, switch plans, journals and recovery. It imports only the JDK, so it runs on a bare JDK without Android or Gradle.

| Path | Content |
| --- | --- |
| `src/main/java/dev/maplesu/installer/` | `FileInstallTransaction`, `BlockDeviceTransaction`, `InstallerMultiPartitionTransaction`, the switch model (`SwitchPlan`, `SwitchStep`, `SwitchFacts`, `SwitchFailure`, `WorkMode`) and the journal (`FileSwitchJournal`, `SwitchJournalSink`) |
| `src/test/` | Synthetic suites: transactions, block-device emulation, multi-partition plans, switch verification, write-path guards and recovery |

```shell
python tools/check_host.py
```

The command compiles the sources and runs every suite in an isolated work directory; it needs no device. The same sources are the `:installer-core` Gradle module, which the Manager depends on.

## Rules

- Import only the JDK and `dev.maplesu.installer.*` (`pure-java-modules` in `python tools/check_architecture.py`).
- A write is an explicit step with a preflight, a backup, a journal entry, a synchronous write and a read-back check. `WritePathGuardTest` reads the production sources to keep writes inside these transactions.
- Image preparation stays in [`image-core`](../image-core/README.md); this module only decides when and where bytes are written, and how an interrupted run is recovered.
