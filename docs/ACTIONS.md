# GitHub Actions builds

The **Build Manager** workflow follows KernelSU's separation of project source and
release signing material. It builds the SDK, consumer example and complete Manager
on a Windows runner with the project's pinned Java, Android, Python and Rust inputs.
See [KernelSU's Manager workflow](https://github.com/tiann/KernelSU/blob/main/.github/workflows/build-manager.yml)
for the upstream reference. MapleSU uses its own build tasks and signing variables.

## Run a build

Open **Actions → Build Manager → Run workflow**. Select `debug` for development or
`release` for a signed APK. Signed builds run from the repository's default branch.
The workflow uploads APKs, the SDK AAR and release mappings as build artifacts; it
does not create a public release or send channel announcements.

Pull requests use the debug build and receive no release signing material. The
complete Manager uses the retained native SDKs, provider inputs and source
snapshots documented in [Native dependencies](NATIVE_DEPENDENCIES.md). The workflow
verifies the source export and paired SDK identity before building.

## Configure release signing

Add these repository secrets under **Settings → Secrets and variables → Actions**:

| Secret | Value |
| --- | --- |
| `KEYSTORE` | Base64 of the existing release keystore |
| `KEYSTORE_PASSWORD` | Keystore password |
| `KEY_ALIAS` | Existing signing-key alias |
| `KEY_PASSWORD` | Signing-key password |

The workflow maps the passwords and alias to `MAPLE_RELEASE_*`, restores the
keystore into the runner's temporary directory for the signing step, and removes
that file after Gradle exits. Keystores and passwords belong in Secrets and a
separate maintainer backup, outside Git, release attachments and build artifacts.
Keep the existing signing identity when updating installed release APKs.

Grant Write access only to trusted maintainers: workflow changes can access
repository secrets. Review signed-build workflow changes accordingly. For a
larger maintainer team, move the same four secrets to a protected release
environment and apply its approval policy to the signing job.

**Source checks** runs host and SDK checks for development. The complete source
export includes the pinned native build inputs and excludes local development
records. Repository visibility and release publication remain maintainer decisions.
