"""Guard the environment-owned identity entry, independently of module packaging."""
from pathlib import Path

root = Path(__file__).resolve().parents[2]
recovery = (root / 'manager/src/main/java/dev/maplesu/manager/runtime/ultra/UltraIdentityRecovery.kt').read_text(encoding='utf-8-sig')
build = (root / 'manager/build.gradle.kts').read_text(encoding='utf-8-sig')
cmake = (root / 'runtime/CMakeLists.txt').read_text(encoding='utf-8-sig')
assert 'libmodule_maplesu_identity.so' not in build, 'Identity is still bundled as a user module'
assert 'add_library(module_maplesu_identity' not in cmake
assert 'client.installModule(' not in recovery, 'Identity deployment still installs a user module'
assert 'UltraInstalledIdentityProbe.readAndVerify(' in recovery, 'Boot entry must be read back before retiring the old module'
hook = (root / 'manager/src/main/java/dev/maplesu/manager/runtime/ultra/UltraIdentityBootHook.kt').read_text()
assert 'IDENTITY_UPGRADE_PREPARED' in hook, 'Old environments need a pre-upgrade deployment path'
print('PASS identity packaging, environment readback and upgrade preparation wiring')
