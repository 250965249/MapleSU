"""Source-bound regressions; deliberately does not compile Android or Kotlin."""
from pathlib import Path
import re
import subprocess
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[2]
JAVA = ROOT / 'manager/src/main/java'

def source(path):
    return (JAVA / path).read_text(encoding='utf-8-sig')

def function(text, name):
    start = re.search(r'^    (?:private )?(?:suspend )?fun ' + name + r'\(', text, re.M)
    assert start is not None, name
    end = re.search(r'^    (?:private )?(?:suspend )?fun ', text[start.end():], re.M)
    return text[start.start():start.end() + end.start() if end else len(text)]

class HiddenReadContract(unittest.TestCase):
    def test_production_state_reads_use_bounded_busy_retry(self):
        text = source('com/maplesu/core/ui/security/LiteHiddenController.kt')
        self.assertIn('LiteHiddenStateReader.read(', function(text, 'readState'))
        reader = source('dev/maplesu/manager/litehidden/LiteHiddenStateReader.kt')
        self.assertIn('ROOT_EXECUTION_BUSY', reader)
        self.assertIn('PRO_ROOT_FAILED:MAPLESU_SDK_BUSY', reader)
        self.assertIn('repeat(MAX_ATTEMPTS)', reader)
        self.assertIn('Thread.currentThread().interrupt()', reader)

    def test_status_queries_do_not_start_in_parallel(self):
        text = source('dev/maplesu/manager/workmode/ui/LiteHiddenViewModel.kt')
        init = text.split('    init {',1)[1].split('\n    }',1)[0]
        self.assertNotIn('refreshWebUiStatus()', init)
        refresh = function(text, 'refresh')
        self.assertIn('refreshWebUiStatus()', refresh)
        self.assertIn('checkingState = false', refresh)
        self.assertIn('webUiStatusJob?.join()', refresh)
        self.assertIn('if (isActive && revision == webUiStatusRevision)', refresh)
        self.assertIn('awaitActivated(', refresh)
        self.assertNotIn('} ?: return@launch', refresh)

    def test_unknown_can_be_retried_without_enabling(self):
        text = source('dev/maplesu/manager/workmode/ui/LiteHiddenScreen.kt')
        self.assertIn('lite_hidden_retry_state', text)
        self.assertIn('viewModel::refresh', text)
        self.assertIn('!checkingState', text)
        viewmodel = source('dev/maplesu/manager/workmode/ui/LiteHiddenViewModel.kt')
        refresh = function(viewmodel, 'refresh')
        self.assertNotIn('card.webUiLinkAvailable) return', refresh)
        self.assertNotIn('ui.webUiLinkAvailable) return@launch', refresh)
        self.assertIn('if (it.webUiLinkAvailable) it.webUiLink', refresh)
        self.assertIn('if (it.webUiLinkAvailable) it.portText', refresh)
        self.assertIn('if (it.webUiLinkAvailable) it.portValid', refresh)
        settings = source('com/maplesu/core/ui/viewmodel/SettingsViewModel.kt')
        self.assertNotIn('val hidden = status.masks', settings)
        self.assertIn('status == LiteHiddenStatus.ON || LiteHiddenRuntimeProxy.isMaskingLite()', settings)

    def test_parasite_checks_live_root_not_environment_cache(self):
        bridge = source('dev/maplesu/manager/workmode/ui/LiteHiddenBridge.kt')
        can_enable = function(bridge, 'canEnable')
        self.assertIn('val state = readState()', can_enable)
        self.assertNotIn('rootAvailableForLite()', can_enable)
        activate = function(bridge, 'activate')
        self.assertNotIn('if (!rootAvailableForLite())', activate)
        self.assertIn('val state = readState()', activate)
        unknown = activate.split('if (state == LiteHiddenState.UNKNOWN)', 1)[1].split('if (state == LiteHiddenState.ON)', 1)[0]
        hidden = activate.split('if (state == LiteHiddenState.ON)', 1)[1].split('HiddenModePolicy.validatePort', 1)[0]
        self.assertIn('return HiddenActivateResult(false, HiddenFailure.ROOT_UNAVAILABLE', unknown)
        self.assertIn('return HiddenActivateResult(false, HiddenFailure.VERIFY_FAILED', hidden)
        self.assertLess(activate.index('if (state == LiteHiddenState.UNKNOWN)'), activate.index('HiddenModeBackends.activate('))
        self.assertLess(activate.index('if (state == LiteHiddenState.ON)'), activate.index('HiddenModeBackends.activate('))
        environment = source('dev/maplesu/manager/litehidden/ProductionHiddenEnv.kt')
        root_available = environment.split('val ultraDeps = HiddenModeDeps(', 1)[1].split('identity = identity', 1)[0]
        self.assertIn('val result = ultraRoot.run("id -u")', root_available)
        self.assertIn('result.code == 0 && result.output.trim() == "0"', root_available)
        self.assertNotIn('UltraEnvironmentProbe.isRunning()', environment)

    def test_state_file_read_has_no_environment_preparation_side_effects(self):
        paths = source('dev/maplesu/manager/litehidden/LiteHiddenPaths.kt')
        self.assertIn('if (write != true) return stateReadScript()', paths)
        read = function(paths, 'stateReadScript')
        self.assertNotRegex(read, r'\b(mkdir|chmod|chown|touch|rm)\b')
        self.assertIn('LITE_MISSING', read)
        self.assertIn('id -u', read)
        backend = source('dev/maplesu/manager/litehidden/ProductionHiddenEnv.kt')
        self.assertIn('LiteHiddenStateReader.parse(result.output)', backend)

class HiddenStateShell(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        paths = source('dev/maplesu/manager/litehidden/LiteHiddenPaths.kt')
        raw = re.search(r'fun stateReadScript\(\): String = """(.*?)"""\.trimIndent\(\)', paths, re.S)
        assert raw is not None
        cls.directory = '/tmp/maplesu-hidden-state/data/adb/maplesu'
        cls.script = textwrap.dedent(raw.group(1)).strip().replace("${'$'}", '$')
        cls.script = cls.script.replace('$STATE_PATH', cls.directory + '/lite_hidden').replace('$DATA_DIR', cls.directory)
        cls.script = cls.script.replace(' /data /data/adb ', ' /tmp/maplesu-hidden-state/data /tmp/maplesu-hidden-state/data/adb ')

    def check_shell(self, setup, assertion):
        script = 'set -eu\n' + setup + '\nread_state() (\n' + self.script + '\n)\n' + assertion + '\n'
        run = subprocess.run(['docker', 'run', '--rm', '-i', 'alpine:3.20', 'sh', '-s'],
                             input=script.encode('utf-8'), capture_output=True, timeout=25)
        self.assertEqual(0, run.returncode, (run.stdout + run.stderr).decode('utf-8', errors='replace'))

    def test_missing_parent_is_off_without_creating_any_directory(self):
        self.check_shell('', "[ \"$(read_state)\" = LITE_MISSING ]; [ ! -e /tmp/maplesu-hidden-state ]")

    def test_missing_state_is_off_without_creating_a_file(self):
        self.check_shell('mkdir -p ' + self.directory,
                         '[ "$(read_state)" = LITE_MISSING ]; [ ! -e ' + self.directory + '/lite_hidden ]')

    def test_reads_real_on_and_off(self):
        for state in ('0', '1'):
            with self.subTest(state=state):
                self.check_shell('mkdir -p ' + self.directory + '; echo ' + state + ' > ' + self.directory + '/lite_hidden',
                                 '[ "$(read_state)" = ' + state + ' ]')

    def test_nonroot_read_fails_instead_of_claiming_missing(self):
        self.check_shell('id() { echo 2000; }', 'if read_state; then exit 1; fi')

    def test_a_directory_at_the_state_path_fails(self):
        self.check_shell('mkdir -p ' + self.directory + '/lite_hidden',
                         'if read_state; then exit 1; fi')

    def test_a_dangling_symlink_does_not_claim_missing(self):
        self.check_shell('mkdir -p ' + self.directory + '; ln -s /absent-state ' + self.directory + '/lite_hidden',
                         'if read_state; then exit 1; fi')

    def test_parent_is_a_file_and_not_a_valid_missing_directory(self):
        self.check_shell('mkdir -p ' + self.directory.rsplit('/', 1)[0] + '; touch ' + self.directory,
                         'if read_state; then exit 1; fi')

    def test_read_preserves_state_and_directory_permissions(self):
        self.check_shell('mkdir -p ' + self.directory + '; chmod 700 ' + self.directory +
                         '; echo 0 > ' + self.directory + '/lite_hidden; chmod 600 ' + self.directory + '/lite_hidden',
                         'before=$(stat -c "%a:%u:%s:%Y:%Z" ' + self.directory + ' ' + self.directory + '/lite_hidden); '
                         '[ "$(read_state)" = 0 ]; after=$(stat -c "%a:%u:%s:%Y:%Z" ' + self.directory + ' ' +
                         self.directory + '/lite_hidden); [ "$before" = "$after" ]')

if __name__ == '__main__':
    unittest.main(verbosity=2)
