"""Current compose selection and bootstrap archive pairing with ordinary files."""
import contextlib
import copy
import json
from pathlib import Path
import tempfile
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import build_tools_under_test as B
import delivery_tools_under_test as D

CURRENT_COMMANDS = []

class CurrentComposeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="current-compose-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.sources = [self.root / "current" / name for name in ("one.cpp", "two.cpp")]
        for path in self.sources:
            path.parent.mkdir(exist_ok=True)
            path.write_text("int ordinary_fixture;\n", encoding="utf-8")
        self.entry = B.ManifestEntry(81, "same_name.o", self.sources, list(map(str, self.sources)),
                                     "core-oz-elf", "complete", "elf")
        self.entry.compose = [dict(tool="clang++", input=str(path), argv=[]) for path in self.sources]
        self.tc = SimpleNamespace(tool=lambda name: Path(name), has=lambda name: True)

    def rejected_without_tools(self, recipe):
        self.entry.compose = recipe
        problems = []
        with patch.object(B.S, "run", return_value=SimpleNamespace(returncode=1, stdout="", stderr="fixture")) as run:
            self.assertIsNone(B._run_compose_steps(self.entry, self.tc, problems))
        self.assertTrue(problems)
        run.assert_not_called()

    def test_missing_compile_step_rejected_before_tools(self):
        self.rejected_without_tools(self.entry.compose[:1])

    def test_extra_compile_step_rejected_before_tools(self):
        self.rejected_without_tools(self.entry.compose + [copy.deepcopy(self.entry.compose[0])])

    def test_wrong_existing_same_basename_source_rejected_before_tools(self):
        wrong = self.root / "historical" / self.sources[1].name
        wrong.parent.mkdir()
        wrong.write_text("int historical_fixture;", encoding="utf-8")
        self.entry.compose[1]["input"] = str(wrong)
        self.rejected_without_tools(self.entry.compose)

    def test_reordered_sources_rejected_before_tools(self):
        self.rejected_without_tools(list(reversed(self.entry.compose)))

    def test_explicit_escaping_source_rejected_before_tools(self):
        self.entry.compose[1]["input"] = "../../outside.cpp"
        with patch.object(B.gen_manifest, "resolve_source", side_effect=[self.sources[0], None]):
            self.rejected_without_tools(self.entry.compose)

    def test_stale_argv_source_rejected_before_tools(self):
        wrong = self.root / "r9" / self.sources[1].name
        wrong.parent.mkdir()
        wrong.write_text("int historical_argv_fixture;", encoding="utf-8")
        self.entry.compose[1]['argv'] = ['-c', str(wrong), '-o', 'old.o']
        self.rejected_without_tools(self.entry.compose)

    def test_step_flags_drop_validated_c_operand_without_losing_other_values(self):
        flags = B._step_flags(['-I','selected headers','-std=c++20','-c','./src/one.cpp',
                               '-o','old.o','-DVALUE=7'],set())
        self.assertEqual(flags,['-I','selected headers','-std=c++20','-DVALUE=7'])

    def test_current_four_recipes_keep_one_real_source_and_published_flags(self):
        original_root = B.S.REPO_ROOT
        for idx in (48, 81, 84, 85):
            path = next((original_root / 'runtime/maplesu-sdk/sdk/manifest').glob(f'{idx:04d}_*.json'))
            row = json.loads(path.read_text(encoding='utf-8'))
            sources = [B.resolve_source(raw) for raw in row['sources']]
            entry = B.ManifestEntry(idx, row['name'], sources, row['sources'], row['flagsProfile'],
                                    row['status'], row['layout'], compose=row['compose'])
            commands = []
            def fake_run(command, **kwargs):
                command = list(map(str, command))
                target = Path(command[command.index('-o') + 1])
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(b'ordinary mock output; not a native object')
                commands.append(dict(argv=command,cwd=str(kwargs['cwd'])))
                return SimpleNamespace(returncode=0,stdout='',stderr='')
            with patch.object(B,'OBJ_DIR',self.root/'obj'), patch.object(B,'TU_DIR',self.root/'tu'), \
                    patch.object(B,'LOG_DIR',self.root/'logs'), patch.object(B.P,'precompile_snapshot',return_value={}), \
                    patch.object(B.S,'run',side_effect=fake_run):
                problems = []
                self.assertIsNotNone(B._run_compose_steps(entry,self.tc,problems))
                self.assertEqual(problems,[])
            for source,command,step in zip(sources,commands,row['compose']):
                argv = command['argv']
                self.assertEqual([arg for arg in argv if not arg.startswith('-') and Path(arg).suffix == '.cpp'], [str(source)])
                self.assertEqual(command['cwd'],str(original_root))
                self.assertTrue(Path(argv[argv.index('-o')+1]).is_relative_to(self.root))
                for flag in step['argv']:
                    if flag.startswith(('-std=', '-D', '-f', '--target=', '-O', '-W')):
                        self.assertIn(flag,argv)
            CURRENT_COMMANDS.append(dict(idx=idx,name=row['name'],manifest=D.record(path,original_root),
                                         sources=[D.record(p,original_root) for p in sources],
                                         commands=commands,simulated=True,actualCompilation=False))


class CurrentBootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="current-bootstrap-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(D, "describe_backend", return_value={"fixture": "backend"}))
        self.old_targets = [(r[4].replace("maplesu_", "skroot_"), r[3], str(i), str(i))
                            for i,r in enumerate(B.PH.TABLE)]
        self.stack.enter_context(patch.object(D, "extractor", return_value=SimpleNamespace(TARGETS=self.old_targets)))
        table = self.root / "runtime/maplesu-sdk/sdk/tools/gen_payload_headers.py"
        table.parent.mkdir(parents=True)
        table.write_text("TABLE = " + repr(B.PH.TABLE) + "\n", encoding="utf-8")
        backend_tool = table.with_name('source_backend.py')
        backend_tool.write_bytes(Path(B.SB.__file__).read_bytes())

    def write(self, name, data):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def fixture(self, current=True):
        names = ["same_name.o"] * 3 + ["core%d.o" % i for i in range(253)]
        data = b"!<arch>\n"
        members = []
        for i,name in enumerate(names):
            body = ("ordinary core %d" % i).encode()
            header = f"{name+'/':<16}{0:<12}{0:<6}{0:<6}{'100644':<8}{len(body):<10}`\n".encode()
            data += header + body + (b"\n" if len(body) % 2 else b"")
            members.append(dict(name=name, object_sha256=__import__('hashlib').sha256(body).hexdigest()))
        core = self.write("bootstrap/libkernel_module_kit_static.a", data)
        archive = self.write("final/libkernel_module_kit_static.a", b"ordinary final archive")
        helper = self.write("helper.bin", b"ordinary helper")
        backend = self.write("backend.bin", b"ordinary backend")
        trace = self.write("extract.tsv", b"libkernel_module_kit_static.a(same_name.o)\n")
        record = lambda p: D.record(p, self.root)
        installers = [r[4] for r in B.PH.TABLE] if current else [r[0] for r in self.old_targets]
        build = dict(provenance=dict(schema="maplesu-sdk-source-provenance/2" if current else "maplesu-sdk-source-provenance/1"),
                     bootstrap=dict(pack=dict(archive=record(core)["path"], bytes=core.stat().st_size,
                                              sha256=D.sha(core), members=256)),
                     pack=dict(member_inputs=members + [dict(name=n,object_sha256="0"*64) for n in installers]),
                     source_helper=dict(sdkArchive=dict(source=record(core)["path"], bytes=core.stat().st_size, sha256=D.sha(core))),
                     source_backend=dict(file=record(backend), identity={"fixture":"backend"},
                                         provenance=dict(inputs=[dict(**record(core),roles=["sdk_archive"])])),
                     final_archive_stability=dict(passed=True,archive=record(archive)))
        for name,path in (("helper",helper),("backend",backend)):
            build['final_archive_stability'][name] = dict(identical=True,file=record(path),trace=record(trace),
                                                         selected_sdk_members=["same_name.o"],installers_selected=[])
        return build, archive, helper, backend, core

    def verify(self, values):
        build,archive,helper,backend,_ = values
        return D.verify_source_bootstrap(build,archive,helper,backend,self.root,self.root)

    def test_current_installer_names_accept_exact_256_core(self):
        self.verify(self.fixture())

    def test_historical_v1_installer_names_keep_original_contract(self):
        self.verify(self.fixture(False))

    def test_helper_old_archive_path_with_same_bytes_rejected(self):
        values = self.fixture(False)
        old = self.write("r9/libkernel_module_kit_static.a", values[-1].read_bytes())
        values[0]['source_helper']['sdkArchive']['source'] = D.record(old,self.root)['path']
        with self.assertRaisesRegex(AssertionError,"SOURCE_SDK_HELPER_CORE_ARCHIVE"):
            self.verify(values)

    def test_helper_core_digest_mismatch_rejected(self):
        values = self.fixture(False)
        values[0]['source_helper']['sdkArchive']['sha256'] = "0" * 64
        with self.assertRaises(AssertionError):
            self.verify(values)

    def test_backend_old_archive_with_same_bytes_rejected(self):
        values = self.fixture(False)
        old = self.write("r9/libkernel_module_kit_static.a", values[-1].read_bytes())
        values[0]['source_backend']['provenance']['inputs'] = [dict(**D.record(old,self.root),roles=["sdk_archive"])]
        with self.assertRaisesRegex(AssertionError,"SOURCE_SDK_BACKEND_CORE_ARCHIVE"):
            self.verify(values)

    def test_backend_missing_or_duplicate_core_archive_rejected(self):
        for duplicate in (False, True):
            with self.subTest(duplicate=duplicate):
                values = self.fixture(False)
                rows = values[0]['source_backend']['provenance']['inputs']
                rows[:] = rows * 2 if duplicate else []
                with self.assertRaisesRegex(AssertionError,"SOURCE_SDK_BACKEND_CORE_ARCHIVE"):
                    self.verify(values)

    def with_commands(self, commands):
        values = self.fixture(False)
        path = self.write('compile_commands.json',json.dumps(commands).encode())
        generated = values[0]['source_backend']
        generated['compileCommands'] = D.record(path,self.root)
        generated['compile_commands'] = commands
        generated['provenance']['toolchain'] = dict(target='aarch64-none-linux-android31')
        return values

    def test_backend_arguments_with_spaced_argv_preserves_raw_commands(self):
        commands = [dict(directory=str(self.root),file='source with spaces.cpp',arguments=[
            'C:/Program Files/NDK/clang++.exe','--target=aarch64-none-linux-android31',
            '-I','C:/selected headers','-DNAME=two words','-c','source with spaces.cpp',
            '-o','CMakeFiles/'+target+'/source with spaces.cpp.o'])
            for target in ('maplesu_policy_boot.dir','maplesu_kernel_layout.dir')]
        values = self.with_commands(commands)
        before = copy.deepcopy(values[0])
        self.verify(values)
        self.assertEqual(values[0],before)

    def test_backend_command_string_uses_same_producer_parser(self):
        commands = [dict(command='"C:/Program Files/NDK/clang++.exe" --target=aarch64-none-linux-android31 '
                         '-I"C:/selected headers" -c "source with spaces.cpp" '
                         '-o "CMakeFiles/maplesu_policy_boot.dir/source with spaces.cpp.o"')]
        self.verify(self.with_commands(commands))

    def test_backend_command_parser_imports_in_fresh_staging_context(self):
        tools = self.root / 'runtime/maplesu-sdk/sdk/tools'
        for module in (B.S,B.P):
            (tools / Path(module.__file__).name).write_bytes(Path(module.__file__).read_bytes())
        values = self.with_commands([dict(arguments=['clang++','--target=aarch64-none-linux-android31',
                    '-c','ordinary.cpp','-o','CMakeFiles/maplesu_policy_boot.dir/ordinary.o'])])
        paths = [value for value in sys.path if not value.endswith(('sdk/tools','sdk\\tools'))]
        with patch.dict(sys.modules), patch.object(sys,'path',paths):
            for name in ('sdk_common','source_provenance'):
                sys.modules.pop(name,None)
            before = list(sys.path)
            self.verify(values)
            self.assertEqual(sys.path,before)

    def test_backend_arguments_inconsistent_missing_or_duplicate_target_rejected(self):
        for targets in ([['--target=aarch64-none-linux-android31'],['--target=aarch64-none-linux-android21']],
                        [['--target=aarch64-none-linux-android31'],[]],
                        [['--target=aarch64-none-linux-android31'],['--target=aarch64-none-linux-android31']*2]):
            with self.subTest(targets=targets):
                commands = [dict(arguments=['clang++',*flags,'-c','ordinary.cpp','-o',
                                           f'CMakeFiles/maplesu_policy_boot.dir/{i}.o'])
                            for i,flags in enumerate(targets)]
                with self.assertRaisesRegex(AssertionError,'SOURCE_SDK_BACKEND_COMPILER_TARGET'):
                    self.verify(self.with_commands(commands))

    def test_backend_arguments_toolchain_target_mismatch_rejected(self):
        values = self.with_commands([dict(arguments=['clang++','--target=aarch64-none-linux-android21',
                    '-c','ordinary.cpp','-o','CMakeFiles/maplesu_policy_boot.dir/ordinary.o'])])
        with self.assertRaisesRegex(AssertionError,'SOURCE_SDK_BACKEND_COMPILER_TARGET'):
            self.verify(values)

    def test_backend_raw_command_receipt_drift_rejected(self):
        values = self.with_commands([dict(arguments=['clang++','--target=aarch64-none-linux-android31',
                    '-c','ordinary.cpp','-o','CMakeFiles/maplesu_policy_boot.dir/ordinary.o'])])
        values[0]['source_backend']['compile_commands'][0]['arguments'].append('-DCHANGED=1')
        with self.assertRaisesRegex(AssertionError,'SOURCE_SDK_BACKEND_COMPILER_COMMANDS'):
            self.verify(values)
