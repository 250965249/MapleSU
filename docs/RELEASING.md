# Releasing MapleSU

The Manager, module catalog and theme catalog have separate release processes.
Pin the source revision and build inputs, review component attribution and input
records, and verify the actual artifacts before publication.

## Prepare the public source

The public candidate is a fresh source tree exported from a reviewed commit.
Keep the development repository private while this review is pending. Create a
new public repository from the approved export so private commit history and
development records stay with the private repository.

`release/source-policy.json` defines excluded paths and required files.
`.gitattributes` applies the same exclusions to `git archive`.
`tools/check_source_export.py` checks the actual archive from the selected commit;
CI runs this check on Windows and Linux. Update both exclusion lists together.

From a committed checkout, prepare an empty directory outside the repository:

```shell
python tools/check_source_export.py --ref HEAD
git archive --format=tar --output=../MapleSU-public-source.tar HEAD
mkdir ../MapleSU-public-source
tar -xf ../MapleSU-public-source.tar -C ../MapleSU-public-source
python ../MapleSU-public-source/tools/release_audit.py --root ../MapleSU-public-source --all --strict --output ../MapleSU-public-audit.json
```

The archive excludes private maintenance records, research trees, local
attachments. It includes the complete native inputs indexed in
`release/native-inputs.json`, and checks their sizes and hashes in the archive. The export check verifies
file selection. The strict audit additionally checks document links, credentials,
binary allowlists and unresolved release conditions. Preserve credits, notices
and source provenance in the exported tree.

Open the audit report and resolve every error before publishing. Build the
complete Manager and SDK from the exported tree and compare their native SDK,
helper and backend identities with the development baseline. Keep credits,
component notices and source manifests with the release.

## Validate the candidate

Run checks inside the exported directory with its declared public inputs:

```shell
python -m pip install -r requirements-native.txt
python tools/check_architecture.py
python tools/check_host.py
python -m unittest discover -s tools/tests -p "test_release_audit.py"
python -m unittest discover -s tools/tests -p "test_source_export.py"
./gradlew :maplesu-client:assembleRelease :maplesu-consumer:assembleDebug :manager:assembleRelease --no-build-cache --no-configuration-cache
```

Use [Build](BUILD.md) for the complete Manager build and platform-specific
commands. Record the source commit, tool versions, commands and results. Verify
installation, authorization, modules, upgrades and recovery on the release's
supported devices. Review the final directory and executable bits, including
`gradlew`, before importing the approved tree into the public repository.

## APK and SDK

Build the SDK with the tasks in [SDK integration](SDK.md). Build and sign the APK
using [Build](BUILD.md) or [Actions](ACTIONS.md). Keep the signing key and passwords
in maintainer-controlled storage and Actions Secrets. Include the source commit,
version, artifact hashes, signing certificate digest and compatibility record
with a release. SDK consumers trust the signing certificate.

## Community repositories

Follow the [theme guide](THEME_REPOSITORY.md) and [module guide](MODULE_REPOSITORY.md)
for submissions, maintainer records, package origins and resource licenses.
Contribution pull requests run static checks without release credentials or
executing uploaded package code. Review existing entries before enabling their
release checks.

ReZygisk and other independently distributed modules are reviewed in their own
repositories. Their license checks apply to those module releases. The main
repository excludes their implementation and does not package the adapter.
