"""Resident-symbol checks against ELF fixtures, without building an LKM."""
import importlib.util
from pathlib import Path
import struct
from types import SimpleNamespace
import unittest

HERE = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("boot_sdk_resident_gate_fixture", HERE / "build_root_module.py")
BUILDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILDER)


class Elf:
    def __init__(self, missing=(), transient=(), kcfi=0x12345678):
        self.missing, self.transient = missing, transient
        self.raw = struct.pack("<II", kcfi, 0)

    def symbol(self, name):
        return None if name in self.missing else dict(name=name, shndx=1, value=4096)

    def symbol_section(self, symbol):
        return dict(name=".init.text" if symbol["name"] in self.transient else ".text",
            addr=4096, size=8192, flags=BUILDER.SHF_ALLOC | BUILDER.SHF_EXECINSTR)

    @staticmethod
    def symbol_file_offset(_symbol):
        return 4


class BootSdkResidentGateTest(unittest.TestCase):
    def gate(self, elf, environment=True):
        context = SimpleNamespace(elf=elf, l3_facts={"bootSdk": {"environmentAbi": environment},
            "callbackDispatch": {"preHandler": {"typeId": "0x12345678"}}})
        gate = BUILDER.Gate("sdk-resident", "SDK resident callbacks")
        BUILDER.gate_l3_handler_text(context, gate)
        return gate

    def test_all_sdk_entrypoints_are_resident(self):
        self.assertTrue(self.gate(Elf()).ok)

    def test_environment_callbacks_are_not_optional_after_claiming_the_capability(self):
        for name in ("sdk_lookup", "sdk_module_free", "msu_boot_sdk_avc_redirect",
                     "msu_sdk_lookup_template", "msu_sdk_avc_template", "msu_sdk_avc_bridge"):
            with self.subTest(symbol=name):
                with self.assertRaisesRegex(BUILDER._CheckFailed, name + " is defined"):
                    self.gate(Elf(missing=(name,)))
                with self.assertRaisesRegex(BUILDER._CheckFailed, name + " is resident"):
                    self.gate(Elf(transient=(name,)))

    def test_basic_channel_does_not_claim_or_require_the_environment_bridge(self):
        self.assertTrue(self.gate(Elf(missing=("msu_sdk_avc_bridge", "sdk_module_free")), environment=False).ok)

    def test_allocator_observer_is_resident_and_carries_the_native_callback_prefix(self):
        name = "msu_boot_sdk_allocator_pre"
        with self.assertRaisesRegex(BUILDER._CheckFailed, name + " is defined"):
            self.gate(Elf(missing=(name,)))
        with self.assertRaisesRegex(BUILDER._CheckFailed, name + " is resident"):
            self.gate(Elf(transient=(name,)))
        class WrongObserverPrefix(Elf):
            def symbol_file_offset(self, symbol):
                return 8 if symbol["name"] == name else 4
        with self.assertRaisesRegex(BUILDER._CheckFailed, name + " carries the measured native KCFI prefix"):
            self.gate(WrongObserverPrefix())

    def test_process_context_adapter_and_measured_kcfi_prefix_are_required(self):
        with self.assertRaisesRegex(BUILDER._CheckFailed, "sdk_execve is resident"):
            self.gate(Elf(transient=("sdk_execve",)))
        with self.assertRaisesRegex(BUILDER._CheckFailed, "measured native KCFI prefix"):
            self.gate(Elf(kcfi=0))


if __name__ == "__main__":
    unittest.main()
