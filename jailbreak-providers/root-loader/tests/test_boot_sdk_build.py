"""Host fixtures for measured SDK gates; no kernel image build is started."""
import importlib.util
from pathlib import Path
import struct
from types import SimpleNamespace
import unittest

HERE = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("boot_sdk_builder_fixture", HERE / "boot_sdk_build.py")
SDK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SDK)
PRODUCER_SPEC = importlib.util.spec_from_file_location("boot_sdk_layout_producer", HERE / "build_root_module.py")
PRODUCER = importlib.util.module_from_spec(PRODUCER_SPEC)
PRODUCER_SPEC.loader.exec_module(PRODUCER)


class Symbols:
    def __init__(self, missing=(), overrides=None):
        self.missing = missing
        self.overrides = overrides or {}

    def address(self, name):
        return None if name in self.missing else self.overrides.get(name, 0 if name == "_text" else 4096)


class Btf:
    field_layout = PRODUCER.Btf.field_layout

    def __init__(self):
        self.types = [dict(kind=0, size=0)]
        self.integers = {size: self.add(kind=1, size=size, int_encoding=size * 8) for size in (1, 2, 4, 8)}
        pointer = self.add(kind=2, size=self.integers[1])
        filename = self.add(kind=4, size=16, name="filename",
            members=[dict(name="name", byte=0, type=pointer)])
        filename_ptr = self.add(kind=2, size=filename)
        user_arg = self.add(kind=4, size=16)
        seccomp = self.add(kind=4, size=16, name="seccomp",
            members=[dict(name="mode", byte=0, type=self.integers[4])])
        self.seccomp = self.types[seccomp]
        self.task = dict(kind=4, size=4096, name="task_struct",
            members=[dict(name="seccomp", byte=2048, type=seccomp)])
        self.types.append(self.task)
        self.prototypes = {}
        signatures = {
            "do_execveat_common": [self.integers[4], filename_ptr, user_arg, user_arg, self.integers[4]],
            "avc_denied": [self.integers[n] if n else pointer for n in (4, 4, 2, 4, 1, 1, 4, 0)],
            "filldir64": [pointer, pointer] + [self.integers[n] for n in (4, 8, 8, 4)],
            "slow_avc_audit": [self.integers[n] if n else pointer for n in (4, 4, 2, 4, 4, 4, 4, 0)],
            "module_memfree": [pointer],
        }
        for name, params in signatures.items():
            proto = self.add(kind=13, size=0 if name == "module_memfree" else self.integers[4],
                vlen=len(params), params=[dict(type=t) for t in params])
            self.add(kind=12, name=name, size=proto)
            self.prototypes[name] = self.types[proto]
        self.filename = self.types[filename]
        self.user_arg = self.types[user_arg]

    def add(self, **fields):
        self.types.append(fields)
        return len(self.types) - 1

    def struct(self, name):
        if name == "task_struct":
            return self.task
        raise KeyError(name)

    def structs(self, name):
        return [(i, value) for i, value in enumerate(self.types)
                if i and value.get("kind") == 4 and value.get("name") == name]

    @staticmethod
    def member(st, name):
        return next(member for member in st["members"] if member["name"] == name)


class BootSdkBuildTest(unittest.TestCase):
    def test_actual_btf_parser_retains_member_bits(self):
        spec = importlib.util.spec_from_file_location("boot_sdk_btf_fixture", HERE / "build_root_module.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        strings = b"\0seccomp\0mode\0"
        integer = struct.pack("<IIII", 0, 1 << 24, 4, 32)
        owner = struct.pack("<III", 1, (1 << 31) | (4 << 24) | 1, 16)
        for bit, width in ((0, 0), (32, 0), (1, 0), (32, 7), (32, 32)):
            types = integer + owner + struct.pack("<III", 9, 1, (width << 24) | bit)
            raw = struct.pack("<HBBIIIII", 0xeb9f, 1, 0, 24, 0, len(types), len(types), len(strings)) + types + strings
            btf = module.Btf(raw)
            with self.subTest(bit=bit, width=width):
                field = btf.member(btf.struct("seccomp"), "mode")
                self.assertEqual(bit // 8, field["byte"])
                self.assertEqual(bit, field["bit"])
                self.assertEqual(width, field["bitfield_bits"])
                self.assertTrue(btf.struct("seccomp")["bits"])
                self.assertEqual(32, btf.types[1]["int_encoding"])

    def test_image_notes_require_a_complete_gnu_build_id(self):
        notes = struct.pack("<III", 4, 20, 3) + b"GNU\0" + bytes(range(20))
        symbols = Symbols(overrides={"__start_notes": 16, "__stop_notes": 16 + len(notes)})
        self.assertEqual(notes.hex(), SDK.kernel_notes(bytes(16) + notes, symbols))
        self.assertIsNone(SDK.kernel_notes(bytes(16) + notes[:-1], symbols))
        self.assertIsNone(SDK.kernel_notes(bytes(16) + bytes(len(notes)), symbols))
        self.assertIsNone(SDK.kernel_notes(bytes(16) + notes, Symbols(missing=("__start_notes",))))
        header = SDK.header(dict(defines={}, kernelNotesHex=notes.hex()))
        self.assertIn("MSU_BS_KERNEL_NOTES_BYTES 36", header)
        self.assertIn("MSU_BS_KERNEL_NOTES {4,0,0,0,20,0,0,0,3,0,0,0,71,78,85,0,", header)

    def test_environment_uses_filename_register_not_seven_register_call_arity(self):
        facts = SDK.environment_facts(Btf(), Symbols())
        self.assertEqual(1, facts["MSU_BS_ENVIRONMENT"])
        self.assertEqual(1, facts["MSU_BS_EXECVE_REG"])
        self.assertEqual(0, facts["MSU_BS_EXECVE_CHAR"])
        self.assertEqual(2048, facts["MSU_BS_SECCOMP_OFFSET"])

    def test_each_environment_helper_is_required(self):
        for name in SDK.ENV_SYMBOLS:
            with self.subTest(symbol=name):
                self.assertEqual({}, SDK.environment_facts(Btf(), Symbols(missing=(name,))))

    def test_seccomp_offset_names_mode_not_the_outer_object(self):
        for offset in (0, 1, 2, 3, 4, 8, 12):
            with self.subTest(mode_offset=offset):
                btf = Btf(); btf.seccomp["members"][0]["byte"] = offset
                facts = SDK.environment_facts(btf, Symbols())
                self.assertEqual(2048 + offset, facts["MSU_BS_SECCOMP_OFFSET"])
        btf = Btf(); btf.task["members"][0]["byte"] = 32764; btf.task["size"] = 65536
        btf.seccomp["members"][0]["byte"] = 4
        self.assertEqual({}, SDK.environment_facts(btf, Symbols()))

    def test_seccomp_mode_requires_four_bytes_within_both_owners(self):
        fixtures = []
        btf = Btf(); btf.seccomp["members"][0]["type"] = btf.integers[8]; fixtures.append(btf)
        btf = Btf(); btf.seccomp["members"][0]["byte"] = 16; fixtures.append(btf)
        btf = Btf(); btf.seccomp["members"][0]["bit"] = 1; fixtures.append(btf)
        btf = Btf(); btf.seccomp["bits"] = True; btf.seccomp["members"][0]["bitfield_bits"] = 7; fixtures.append(btf)
        btf = Btf(); btf.task["members"][0]["byte"] = 4092; fixtures.append(btf)
        btf = Btf(); btf.task["members"][0]["bit"] = 2048 * 8 + 1; fixtures.append(btf)
        btf = Btf(); btf.task["members"][0]["bitfield_bits"] = 1; fixtures.append(btf)
        btf = Btf(); btf.task["members"][0]["type"] = btf.integers[8]; fixtures.append(btf)
        btf = Btf(); btf.seccomp["members"] = []; fixtures.append(btf)
        for number, btf in enumerate(fixtures):
            with self.subTest(case=number):
                self.assertEqual({}, SDK.environment_facts(btf, Symbols()))

    def test_seccomp_mode_accepts_anonymous_nested_owners(self):
        btf = Btf()
        inner = btf.add(kind=4, size=16, members=[dict(name="mode", byte=1, type=btf.integers[4])])
        btf.seccomp["members"] = [dict(name="", byte=0, type=inner)]
        self.assertEqual(2049, SDK.environment_facts(btf, Symbols())["MSU_BS_SECCOMP_OFFSET"])
        btf = Btf()
        original = btf.task["members"][0]
        wrapper = btf.add(kind=4, size=16,
            members=[dict(name="seccomp", byte=0, type=original["type"])])
        btf.task["members"] = [dict(name="", byte=2048, type=wrapper)]
        self.assertEqual(2048, SDK.environment_facts(btf, Symbols())["MSU_BS_SECCOMP_OFFSET"])

    def test_seccomp_anonymous_owner_bounds_and_cycles_are_rejected(self):
        btf = Btf()
        inner = btf.add(kind=4, size=16, members=[dict(name="mode", byte=0, type=btf.integers[4])])
        btf.seccomp["members"] = [dict(name="", byte=1, type=inner)]
        self.assertEqual({}, SDK.environment_facts(btf, Symbols()))
        btf.seccomp["members"] = [dict(name="", byte=0, type=btf.task["members"][0]["type"])]
        self.assertEqual({}, SDK.environment_facts(btf, Symbols()))

    def test_seccomp_ambiguous_members_and_task_layouts_are_rejected(self):
        btf = Btf()
        inner = btf.add(kind=4, size=16, members=[dict(name="mode", byte=0, type=btf.integers[4])])
        btf.seccomp["members"].append(dict(name="", byte=0, type=inner))
        self.assertEqual({}, SDK.environment_facts(btf, Symbols()))
        btf = Btf()
        btf.add(kind=4, size=4096, name="task_struct", members=[dict(name="seccomp", byte=2049,
            type=btf.task["members"][0]["type"])])
        self.assertEqual({}, SDK.environment_facts(btf, Symbols()))

    def test_seccomp_mode_uses_effective_bits_and_legacy_integer_offset(self):
        cases = [
            # storage bytes, INT bits, internal offset, modern, field width, accepted offset
            (4, 32, 0, False, 0, 2051),
            (4, 16, 0, False, 0, None),
            (8, 32, 8, False, 0, 2052),
            (4, 32, 1, False, 0, None),
            (8, 16, 8, False, 0, None),
            (4, 32, 0, True, 32, 2051),
            (4, 32, 0, True, 16, None),
            (4, 16, 0, True, 32, None),
            (8, 32, 8, True, 32, None),
            (8, 64, 0, True, 32, 2051),
            (8, 64, 0, True, 0, None),
        ]
        for size, bits, internal, modern, width, expected in cases:
            btf = Btf(); btf.seccomp["bits"] = modern
            btf.task["members"][0]["byte"] = 2049
            mode = btf.seccomp["members"][0]; mode["byte"] = 2; mode["bitfield_bits"] = width
            mode["type"] = btf.add(kind=1, size=size, int_encoding=(internal << 16) | bits)
            facts = SDK.environment_facts(btf, Symbols())
            with self.subTest(size=size, bits=bits, internal=internal, modern=modern, width=width):
                self.assertEqual(expected, facts.get("MSU_BS_SECCOMP_OFFSET"))

    def test_seccomp_mode_accepts_enum_and_other_full_width_value_types(self):
        for kind in (4, 5, 6, 16, 19):
            btf = Btf(); mode = btf.seccomp["members"][0]
            mode["type"] = btf.add(kind=kind, name="vendor_value", size=4)
            btf.seccomp["name"] = "vendor_seccomp"
            with self.subTest(kind=kind):
                self.assertEqual(2048, SDK.environment_facts(btf, Symbols())["MSU_BS_SECCOMP_OFFSET"])
        for kind in (6, 19):
            btf = Btf(); btf.seccomp["bits"] = True; mode = btf.seccomp["members"][0]
            mode["type"] = btf.add(kind=kind, size=8); mode["bitfield_bits"] = 32
            self.assertEqual(2048, SDK.environment_facts(btf, Symbols())["MSU_BS_SECCOMP_OFFSET"])
            mode["bitfield_bits"] = 16
            self.assertEqual({}, SDK.environment_facts(btf, Symbols()))

    def test_seccomp_mode_uses_array_value_size_from_actual_parser(self):
        spec = importlib.util.spec_from_file_location("boot_sdk_array_fixture", HERE / "build_root_module.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        types = struct.pack("<IIII", 0, 1 << 24, 1, 8)
        types += struct.pack("<IIIIII", 0, 3 << 24, 0, 1, 1, 4)
        strings = b"\0"
        raw = struct.pack("<HBBIIIII", 0xeb9f, 1, 0, 24, 0, len(types), len(types), len(strings)) + types + strings
        array = module.Btf(raw).types[2]
        self.assertEqual((1, 4), (array["array_type"], array["array_count"]))
        btf = Btf()
        array["array_type"] = btf.integers[1]
        btf.seccomp["members"][0]["type"] = btf.add(**array)
        self.assertEqual(2048, SDK.environment_facts(btf, Symbols())["MSU_BS_SECCOMP_OFFSET"])
        array_type = btf.types[btf.seccomp["members"][0]["type"]]
        array_type["array_count"] = 3
        self.assertEqual({}, SDK.environment_facts(btf, Symbols()))

    def test_unknown_by_value_filename_and_release_abis_disable_environment(self):
        fixtures = []
        btf = Btf(); btf.user_arg["size"] = 8; fixtures.append(btf)
        btf = Btf(); btf.filename["members"][0]["byte"] = 8; fixtures.append(btf)
        btf = Btf(); btf.prototypes["module_memfree"]["size"] = btf.integers[4]; fixtures.append(btf)
        btf = Btf(); btf.prototypes["module_memfree"]["params"][0]["type"] = btf.integers[8]; fixtures.append(btf)
        for btf in fixtures:
            self.assertEqual({}, SDK.environment_facts(btf, Symbols()))
        for offset in (0, 32768):
            btf = Btf(); btf.task["members"][0]["byte"] = offset
            self.assertEqual({}, SDK.environment_facts(btf, Symbols()))

    def test_missing_nofault_write_helper_stops_before_btf_derivation(self):
        def unexpected(_image):
            self.fail("Missing required helpers must stop before ABI derivation")
        self.assertIn("copy_to_kernel_nofault", SDK.SYMBOLS)
        self.assertEqual({}, SDK.derive(SimpleNamespace(Btf=unexpected), b"",
            Symbols(missing=("copy_to_kernel_nofault",)), 128, {"defines": {}}))

    def test_profiled_allocator_uses_measured_612_wrapper(self):
        wrapper = bytes.fromhex("3f2303d5ff0301d1fd7b03a9fdc30091084138d5088943f9a8831ff8ff2003d5bf031ff81f2003d5082101b069e080d2e2675ab208317e39090de0f2e37b5fb22a0175b2210080520200b0f21f01007103f0b7f2049881524511899ae6031faa07008012fe0300f935020094084138d5088943f9a9835ff81f0109ebe1010054fd7b43a9ff030191bf2303d5c0035fd6")
        image = bytearray(8192)
        struct.pack_into("<Q", image, 16, 0x10000000)
        image[56:60] = b"ARM\x64"; image[4096:4096 + len(wrapper)] = wrapper
        symbols = Symbols(missing=("vmalloc", "__vmalloc_node_range"), overrides={
            "vmalloc_noprof": 4096,
            "__vmalloc_node_range_noprof": 4096 + 104 + (0x235 * 4)})
        facts = SDK.vmalloc_facts(image, symbols)
        self.assertIsNotNone(facts)
        self.assertEqual(1, facts["MSU_BS_ALLOCATOR_NOPROF"])
        self.assertEqual(0x4000000000 - 0x80000000, facts["MSU_BS_VM_START_MAG"])
        self.assertEqual(0x140800000, facts["MSU_BS_VM_END_MAG"])
        self.assertEqual(0x0068000000000703, facts["MSU_BS_VM_PROT"])
        for at in (48, 64, 88, 104):
            corrupt = bytearray(image); corrupt[4096 + at] ^= 4
            self.assertIsNone(SDK.vmalloc_facts(corrupt, symbols))

    def test_measured_61_wrapper_with_canonical_return_address(self):
        # Saved 6.1 image bytes; relocate only BL for the small host fixture.
        wrapper = bytes.fromhex("3f2303d5ff8300d1fd7b01a9fd430091e8f600d0ff2003d56be080d2c96359b2cabf4992df0349f2082159390b0de0f24901899a6a0175b2e2675ab2e38f64b21f0100712100805265018a9a0200a1f2a3ffdff204988152e6031faa07008012e90300f9c0b6f997fd7b41a9ff830091bf2303d5c0035fd6")
        image = bytearray(8192)
        struct.pack_into("<Q", image, 16, 0x10000000)
        image[56:60] = b"ARM\x64"; image[4096:4096 + len(wrapper)] = wrapper
        struct.pack_into("<I", image, 4096 + 100, 0x94000000 | ((6144 - 4196) // 4))
        symbols = Symbols(overrides={"vmalloc": 4096, "__vmalloc_node_range": 6144})
        facts = SDK.vmalloc_facts(image, symbols)
        self.assertIsNotNone(facts)
        self.assertEqual(0, facts["MSU_BS_ALLOCATOR_NOPROF"])
        self.assertEqual(0x3ff8000000, facts["MSU_BS_VM_START_MAG"])
        self.assertEqual(0x210000000, facts["MSU_BS_VM_END_MAG"])
        self.assertEqual(1, facts["MSU_BS_VM_ALIGN"])
        self.assertEqual(0xcc0, facts["MSU_BS_VM_GFP"])
        self.assertEqual(0x0068000000000703, facts["MSU_BS_VM_PROT"])
        self.assertEqual(0x0068000000000f03, facts["MSU_BS_VM_PROT_SET"])
        for at in (24, 52, 72, 96, 100):
            corrupt = bytearray(image); corrupt[4096 + at] ^= 4
            self.assertIsNone(SDK.vmalloc_facts(corrupt, symbols))

    def test_new_execmem_release_abi_can_back_the_legacy_sdk_name(self):
        btf = Btf()
        btf.types.append(dict(kind=12, name="execmem_free",
            size=next(t["size"] for t in btf.types if t.get("name") == "module_memfree")))
        facts = SDK.environment_facts(btf, Symbols(missing=("module_memfree",)))
        self.assertEqual(1, facts["MSU_BS_ENVIRONMENT"])
        self.assertEqual(1, facts["MSU_BS_EXECMEM_FREE"])

    def test_measured_vmalloc_instruction_shape_and_callee_are_required(self):
        # The measured wrapper relocated into a small host fixture, not host kernel constants.
        wrapper = bytes.fromhex(
            "3f2303d5ff8300d1fd7b01a9fd430091ff2003d528fd00b069e080d208c15939"
            "090de0f2e2675ab22a0175b2e38f64b2210080521f0100710200b0f2a3ffdff2"
            "25018a9a04988152e6031faa07008012fe0300f9c4fdff97fd7b41a9ff830091"
            "bf2303d5c0035fd6")
        image = bytearray(8192)
        struct.pack_into("<Q", image, 16, 0x10000000)
        image[56:60] = b"ARM\x64"; image[4096:4096 + len(wrapper)] = wrapper
        symbols = Symbols(overrides={"__vmalloc_node_range": 4096 + 84 - 572 * 4})
        facts = SDK.vmalloc_facts(image, symbols)
        self.assertIsNotNone(facts)
        self.assertEqual(1, facts["MSU_BS_VM_ALIGN"])
        self.assertGreater(facts["MSU_BS_VM_START_MAG"], facts["MSU_BS_VM_END_MAG"])
        self.assertIsNone(SDK.vmalloc_facts(image, Symbols()))
        image[4096] ^= 1
        self.assertIsNone(SDK.vmalloc_facts(image, symbols))


if __name__ == "__main__":
    unittest.main()
