# Development

Start with [Architecture](ARCHITECTURE.md) for component boundaries and
[Build](BUILD.md) for the toolchains and native inputs. [Actions](ACTIONS.md)
describes cloud builds. The client SDK and consumer example can be built
independently of the Manager's native backends.

## Build and check a change

Install the Python dependencies from `requirements-native.txt`, configure the
Android SDK and JDK, then run the checks relevant to your change:

```shell
python tools/check_architecture.py
python tools/check_host.py
./gradlew :maplesu-client:assembleRelease :maplesu-consumer:assembleDebug
```

Use `gradlew.bat` on Windows. Manager builds and tests require the complete
native inputs listed in [Build](BUILD.md) and [Native dependencies](NATIVE_DEPENDENCIES.md).
Run the matching debug build when changing Manager code. See [Testing](TESTING.md)
for Android, host and device checks.

## Component ownership

Keep UI and orchestration in `manager/`, image transformations in `image-core/`,
and write transactions and recovery in `installer-core/`. Integrating apps use
the Binder client in `client/`. Changes to its shared AIDL must update both
copies together.

Use [SDK](SDK.md) for application integration, [Ultra modules](ULTRA_MODULES.md)
for native extensions, and the [module](MODULE_REPOSITORY.md) and
[theme](THEME_REPOSITORY.md) repository guides for catalog contributions.
Catalogs have their own maintainers and release process.

## Native inputs

Keep upstream versions, input hashes, kernel contracts and paired SDK identity
records consistent. Update fixed inputs through the procedures in
[Native dependencies](NATIVE_DEPENDENCIES.md), including the corresponding source
and build identity records. Preserve upstream notices and review generated
inputs with the implementation that consumes them.

## Submit and prepare a release

Keep each commit focused. Review `git status --short`, `git diff` and
`git diff --cached` before pushing. Include the checks you ran and any required
native-input updates in the pull request. Source checks run on Windows and Linux
for pushes and pull requests.

After committing, run `python tools/check_source_export.py` to check that the
committed archive respects the public-source exclusions. Uncommitted changes
are outside that check. Source export, its full audit and the independent build
are described in [Releasing](RELEASING.md). Keep local notes, device captures,
credentials and generated builds outside the submitted source.
