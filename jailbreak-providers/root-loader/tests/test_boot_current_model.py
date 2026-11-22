"""Host regression for actual L3 current-model qualification; no image mutation.

Synthetic getuid bodies are appended in memory to the real 6.6 image. BTF,
seccomp, AVC and group helpers remain real target input. Only the symbol entry
and its real fixture boundary move. No current qualifier is mocked or decoded
again here. Receipts distinguish this proof from full module/device acceptance.
"""
from __future__ import annotations

import argparse
import copy
import datetime
import hashlib
import inspect
import json
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[3]
LOADER = ROOT / "jailbreak-providers/root-loader"
sys.path.insert(0, str(LOADER))
import build_root_module as builder

CONTRACT = LOADER / "contracts/6.6.89-android15-8-g7e1f3c083cc6-abogki467167594-4k.json"
RECEIPT = None
OBSERVATIONS = []
SOURCES = []
MRS_SP_EL0_X8 = 0xd5384108
RET = 0xd65f03c0
NOP = 0xd503201f


def pack(*words):
    return struct.pack("<" + "I" * len(words), *words)


def load64(rd, rn, offset):
    assert offset >= 0 and offset % 8 == 0 and offset < 32768
    return 0xf9400000 | ((offset // 8) << 10) | (rn << 5) | rd


def load32(rd, rn, offset):
    assert offset >= 0 and offset % 4 == 0 and offset < 16384
    return 0xb9400000 | ((offset // 4) << 10) | (rn << 5) | rd


def branch(pc, destination, call=False):
    delta = destination - pc
    assert delta % 4 == 0 and -(1 << 27) <= delta < (1 << 27)
    return (0x94000000 if call else 0x14000000) | ((delta // 4) & 0x3ffffff)


def cbz(pc, destination, register=5):
    delta = destination - pc
    assert delta % 4 == 0 and -(1 << 20) <= delta < (1 << 20)
    return 0x34000000 | (((delta // 4) & 0x7ffff) << 5) | register


def adr(rd, pc, destination):
    delta = destination - pc
    assert -(1 << 20) <= delta < (1 << 20)
    return 0x10000000 | ((delta & 3) << 29) | (((delta >> 2) & 0x7ffff) << 5) | rd


def target_btf_defines(image):
    """Independent legacy BTF projection, retained only as this test's oracle."""
    btf = builder.Btf(image)
    fields = {"MAPLESU_TASK_CRED_OFF": ("task_struct", "cred"),
              "MAPLESU_CRED_UID_OFF": ("cred", "uid"),
              "MAPLESU_CRED_EUID_OFF": ("cred", "euid"),
              "MAPLESU_CRED_GROUPS_OFF": ("cred", "group_info"),
              "MAPLESU_GROUP_USAGE_OFF": ("group_info", "usage"),
              "MAPLESU_CRED_USAGE_OFF": ("cred", "usage")}
    result = {macro: btf.member(btf.struct(owner), member)["byte"]
              for macro, (owner, member) in fields.items()}
    usage = btf.types[btf.member(btf.struct("cred"), "usage")["type"]]
    while usage["kind"] in (8, 9, 10, 11):
        usage = btf.types[usage["size"]]
    result["MAPLESU_CRED_USAGE_SIZE"] = usage["size"]
    return result


class GetterSymbols:
    """Real symbol table except the getuid body and its exact fixture extent."""
    def __init__(self, original, start, end, added=None):
        self.original, self.start, self.end = original, start, end
        self.added = {"__arm64_sys_getuid": start, "fixture_getuid_end": end}
        self.added.update({name: None if offset is None else start + offset
                           for name, offset in (added or {}).items()})

    def address(self, name):
        return self.added[name] if name in self.added else self.original.address(name)

    def next_address(self, address, limit=0x1000):
        return min([self.original.next_address(address, limit), *[
            value for value in self.added.values() if value is not None and address < value <= address + limit]])


class SubjectLayoutProjectionTest(unittest.TestCase):
    def description(self):
        values = {"task_struct.cred": (1920, 8, 4736), "cred.uid": (4, 4, 168),
                  "cred.euid": (20, 4, 168), "cred.group_info": (144, 8, 168),
                  "group_info.usage": (0, 4, None), "cred.usage": (0, 4, 168)}
        return {"schemaVersion": 1, "operation": "PRO_LAYOUT_SUBJECT_DESCRIBE",
                "fields": {name: dict(offsetBytes=offset, widthBytes=width, ownerSizeBytes=owner)
                           for name, (offset, width, owner) in values.items()}}

    def test_measured_four_and_eight_byte_credential_counters(self):
        for width in (4, 8):
            description = self.description()
            description["fields"]["cred.usage"]["widthBytes"] = width
            result = builder.l3_subject_defines(description)
            self.assertEqual(width, result["MAPLESU_CRED_USAGE_SIZE"])
            self.assertEqual(144, result["MAPLESU_CRED_GROUPS_OFF"])
            self.assertEqual(7, len(result))

    def test_incompatible_field_width_and_alignment_are_rejected(self):
        for name, changes in (("task_struct.cred", {"widthBytes": 4}),
                              ("cred.uid", {"offsetBytes": 5}),
                              ("group_info.usage", {"widthBytes": 8}),
                              ("cred.usage", {"offsetBytes": -4}),
                              ("cred.euid", {"offsetBytes": True})):
            with self.subTest(name=name, changes=changes):
                description = self.description()
                description["fields"][name].update(changes)
                with self.assertRaises(builder.GateFailure):
                    builder.l3_subject_defines(description)

    def test_owner_exact_boundary_is_accepted_and_crossing_rejected(self):
        description = self.description()
        description["fields"]["cred.group_info"]["offsetBytes"] = 160
        self.assertEqual(160, builder.l3_subject_defines(description)["MAPLESU_CRED_GROUPS_OFF"])
        description["fields"]["cred.group_info"]["ownerSizeBytes"] = 167
        with self.assertRaisesRegex(builder.GateFailure, "exceeds its owner"):
            builder.l3_subject_defines(description)

    def test_missing_field_and_transport_schema_are_rejected(self):
        original = self.description()
        cases = [None, {**original, "schemaVersion": 2}, {**original, "fields": []}]
        missing = copy.deepcopy(original)
        del missing["fields"]["cred.usage"]
        cases.append(missing)
        for description in cases:
            with self.subTest(description=description):
                with self.assertRaises(builder.GateFailure):
                    builder.l3_subject_defines(description)


class BootCurrentModelTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        image_path = ROOT / cls.contract["imagePath"]
        symbols_path = ROOT / cls.contract["symbolsPath"]
        cls.image = image_path.read_bytes()
        if hashlib.sha256(cls.image).hexdigest() != cls.contract["imageSha256"]:
            raise AssertionError("real baseline image differs from existing contract")
        cls.symbols = builder.SymbolTable(symbols_path)
        # Resolve unchanged target BTF once. The production current qualifier,
        # seccomp parser and entry checks still execute on every fixture.
        cls.defines = target_btf_defines(cls.image)
        cls.cred = cls.defines["MAPLESU_TASK_CRED_OFF"]
        cls.uid = cls.defines["MAPLESU_CRED_UID_OFF"]
        for path in (Path(__file__), LOADER / "build_root_module.py", CONTRACT,
                     symbols_path, LOADER / "module/maplesu_l3.c",
                     LOADER / "module/maplesu_boot_sdk.c"):
            raw = path.read_bytes()
            SOURCES.append({"path": str(path.relative_to(ROOT)), "bytes": len(raw),
                            "sha256": hashlib.sha256(raw).hexdigest()})
        SOURCES.append({"path": cls.contract["imagePath"], "bytes": len(cls.image),
                        "sha256": cls.contract["imageSha256"]})

    @classmethod
    def tearDownClass(cls):
        if RECEIPT is not None:
            RECEIPT.parent.mkdir(parents=True, exist_ok=True)
            RECEIPT.write_text(json.dumps({
                "schema": 1, "date": datetime.datetime.now(datetime.timezone.utc).date().isoformat(), "host_only": True,
                "production_mutation_in_test": False, "qualifier_mocked": False,
                "entry": "build_root_module.derive_l3_subject_facts",
                "entry_sha256": hashlib.sha256(inspect.getsource(builder.derive_l3_subject_facts).encode()).hexdigest(),
                "current_qualifier_sha256": hashlib.sha256(inspect.getsource(builder.derive_l3_current_model).encode()).hexdigest(),
                "btf_seccomp_avc_dependencies": "actual unchanged real target inputs",
                "synthetic_model_evidence": "fixture specification, not an instruction decoder",
                "sources": SOURCES, "observations": OBSERVATIONS,
                "matched_expectation": sum(row["actual"] == row["expected"] for row in OBSERVATIONS),
                "mismatched_expectation": sum(row["actual"] != row["expected"] for row in OBSERVATIONS),
                "device_operations": "none", "artifact_build": "none",
            }, indent=2) + "\n", encoding="utf-8")

    def observe(self, name, expected, body=None, model=None, following=b"", pad=True, real=False,
                added=None, entry_size=None, defines=None):
        if real:
            image, symbols = self.image, self.symbols
            start = symbols.address("__arm64_sys_getuid")
            end = symbols.next_address(start)
            body = image[start:end]
        else:
            start = len(self.image)
            end = start + (len(body) if entry_size is None else entry_size)
            image = self.image + body + following + (pack(*([NOP] * 8)) if pad else b"")
            symbols = GetterSymbols(self.symbols, start, end, added)
        row = {"name": name, "fixture_kind": "real" if real else "synthetic",
               "model": model, "expected": expected,
               "getuid_start": start, "getuid_end": end, "body_hex": body.hex(),
               "body_sha256": hashlib.sha256(body).hexdigest(), "following_hex": following.hex()}
        try:
            # No mock: derive_l3_facts calls this exact producer for rootSubject.
            facts = builder.derive_l3_subject_facts(image, symbols, None if real else (defines or self.defines))
            row.update(actual="accepted", actual_defines=facts["defines"], current_model=facts.get("currentModel"))
        except builder.GateFailure as error:
            row.update(actual="rejected", error_type=type(error).__name__, detail=str(error))
        except Exception as error:
            row.update(actual="error", error_type=type(error).__name__, detail=str(error))
        OBSERVATIONS.append(row)
        self.assertEqual(expected, row["actual"], json.dumps(row, sort_keys=True))
        if expected == "accepted":
            self.assertEqual("sp_el0-task", row["current_model"]["currentModel"])
            self.assertEqual("target-accessor", row["current_model"]["source"])
            self.assertEqual(row["actual_defines"]["MAPLESU_TASK_CRED_OFF"], row["current_model"]["taskCred"])
            self.assertEqual(row["actual_defines"]["MAPLESU_CRED_UID_OFF"], row["current_model"]["credUid"])
        return row

    def direct(self):
        return pack(MRS_SP_EL0_X8, load64(8, 8, self.cred), load32(0, 8, self.uid), RET)

    def test_real_6_6_getuid_keeps_existing_subject_path(self):
        row = self.observe("real-6.6-direct-task", "accepted", real=True, model="target BTF + original target getter")
        self.assertEqual(self.defines, {key: row["actual_defines"][key] for key in self.defines})

    def test_real_other_btf_subject_descriptions_match_independent_oracle(self):
        contracts = ["family-5.15.json", "family-6.1.json", "family-6.12.json", "family-6.18.json",
                     "6.6.66-android15-8-g29d86c5fc9dd-abogki428889875-4k.json"]
        for name in contracts:
            with self.subTest(contract=name):
                contract_path = LOADER / "contracts" / name
                contract = builder.load_contract(contract_path)
                image_path, symbols_path = ROOT / contract["imagePath"], ROOT / contract["symbolsPath"]
                image = image_path.read_bytes()
                self.assertEqual(contract["imageSha256"], hashlib.sha256(image).hexdigest())
                facts = builder.derive_l3_subject_facts(image, builder.SymbolTable(symbols_path))
                expected = target_btf_defines(image)
                self.assertEqual(expected, {key: facts["defines"][key] for key in expected})
                self.assertEqual("PRO_LAYOUT_SUBJECT_DESCRIBE", facts["layout"]["operation"])
                OBSERVATIONS.append({"name": "real-BTF-subject-" + name, "fixture_kind": "real",
                                     "expected": "accepted", "actual": "accepted", "facts": facts,
                                     "scope": "default subject and independent BTF oracle; not module/device"})
                for path in (contract_path, image_path, symbols_path):
                    raw = path.read_bytes()
                    SOURCES.append({"path": str(path.relative_to(ROOT)), "bytes": len(raw),
                                    "sha256": hashlib.sha256(raw).hexdigest()})

    def test_synthetic_direct_task_matches_target_cred_uid(self):
        self.observe("synthetic-direct-task", "accepted", self.direct(), model="SP_EL0 -> task.cred -> cred.uid -> W0")

    def test_old_thread_info_model_is_not_direct_task(self):
        body = pack(MRS_SP_EL0_X8, load64(8, 8, 16), load64(8, 8, self.cred), load32(0, 8, self.uid), RET)
        self.observe("old-thread-info-task", "rejected", body,
                     model="SP_EL0 -> thread_info.task@16 -> task.cred -> cred.uid -> W0")

    def test_unrelated_mrs_does_not_prove_task(self):
        self.observe("unrelated-mrs", "rejected", pack(MRS_SP_EL0_X8, 0x52807d00, RET),
                     model="MRS result unused; MOV W0,#1000; RET")

    def test_overwritten_mrs_register_does_not_prove_task(self):
        self.observe("overwritten-register", "rejected", pack(MRS_SP_EL0_X8, 0xd2800008,
                     load64(8, 8, self.cred), load32(0, 8, self.uid), RET),
                     model="MRS X8; MOV X8,#0 destroys origin before pointer load")

    def test_unreachable_mrs_does_not_prove_task(self):
        self.observe("unreachable-mrs", "rejected", pack(RET, MRS_SP_EL0_X8),
                     model="RET before MRS; no reachable task origin")

    def test_mrs_in_next_function_does_not_prove_this_getter(self):
        self.observe("next-function-mrs", "rejected", pack(RET), following=self.direct(),
                     model="getuid extent is RET only; following symbol owns MRS")

    def test_truncated_getter_mrs_alone_has_no_return_proof(self):
        self.observe("truncated-mrs-only", "rejected", pack(MRS_SP_EL0_X8), pad=False,
                     model="only MRS, no cred read/UID/RET; exactly image end")

    def test_truncated_instruction_is_a_controlled_rejection(self):
        self.observe("truncated-instruction", "rejected", pack(MRS_SP_EL0_X8)[:3], pad=False,
                     model="three bytes of first instruction at image end")

    def test_absent_mrs_is_rejected(self):
        self.observe("no-mrs", "rejected", pack(0x52807d00, RET), model="constant return, padded readable scan")

    def test_other_system_register_is_rejected(self):
        self.observe("other-system-register", "rejected", pack(0xd538d088,
                     load64(8, 8, self.cred), load32(0, 8, self.uid), RET),
                     model="MRS TPIDR_EL1 is not SP_EL0")

    def test_real_5_10_current_getter_without_claiming_full_subject(self):
        fixture_path = ROOT / "runtime/maplesu-sdk/sdk/tools/tests/kernel_layout/fixtures/android12-5.10.json"
        fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
        image_path, symbols_path = ROOT / fixture["imagePath"], ROOT / fixture["symbolPath"]
        image = image_path.read_bytes()
        self.assertEqual(fixture["imageSha256"], hashlib.sha256(image).hexdigest())
        self.assertEqual(fixture["symbolSha256"], hashlib.sha256(symbols_path.read_bytes()).hexdigest())
        symbols = builder.SymbolTable(symbols_path)
        defines = {"MAPLESU_TASK_CRED_OFF": fixture["expected"]["task_struct.cred"],
                   "MAPLESU_CRED_UID_OFF": fixture["expected"]["cred.uid"]}
        facts = builder.derive_l3_current_model(image, symbols, defines)
        self.assertEqual("sp_el0-task", facts["currentModel"])
        self.assertEqual("target-accessor", facts["source"])
        self.assertEqual((1920, 4), (facts["taskCred"], facts["credUid"]))
        for path in (fixture_path, image_path, symbols_path):
            raw = path.read_bytes()
            SOURCES.append({"path": str(path.relative_to(ROOT)), "bytes": len(raw),
                            "sha256": hashlib.sha256(raw).hexdigest()})
        OBSERVATIONS.append({"name": "real-5.10-current-only", "fixture_kind": "real",
                             "expected": "accepted", "actual": "accepted", "current_model": facts,
                             "scope": "current qualifier only; does not prove no-BTF full subject/CONFIGURE"})

    def test_real_5_10_default_subject_consumes_complete_target_layout(self):
        fixture_path = ROOT / "runtime/maplesu-sdk/sdk/tools/tests/kernel_layout/fixtures/android12-5.10.json"
        evidence_path = ROOT / "docs/dual-mode/impl/_work/2026-11-15-p2/evidence/ngki-subject-refcount-r1/TARGET-FACTS.json"
        fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
        target = next(t for t in json.loads(evidence_path.read_text())["targets"]
                      if t["name"] == "android12-5.10-9465fbb7")
        image_path, symbols_path = ROOT / fixture["imagePath"], ROOT / fixture["symbolPath"]
        image = image_path.read_bytes()
        self.assertEqual(fixture["imageSha256"], hashlib.sha256(image).hexdigest())
        self.assertEqual(fixture["symbolSha256"], hashlib.sha256(symbols_path.read_bytes()).hexdigest())
        self.assertNotIn(builder.BTF_MAGIC, image)
        row = {"name": "real-5.10-default-subject", "fixture_kind": "real",
               "expected": "accepted", "defines_injected": False,
               "scope": "actual default subject producer; not complete L3/CONFIGURE/device"}
        try:
            facts = builder.derive_l3_subject_facts(image, builder.SymbolTable(symbols_path))
            row.update(actual="accepted", facts=facts)
        except builder.GateFailure as error:
            row.update(actual="rejected", detail=str(error))
        OBSERVATIONS.append(row)
        for path in (fixture_path, evidence_path, image_path, symbols_path):
            raw = path.read_bytes()
            SOURCES.append({"path": str(path.relative_to(ROOT)), "bytes": len(raw),
                            "sha256": hashlib.sha256(raw).hexdigest()})
        self.assertEqual("accepted", row["actual"], json.dumps(row, sort_keys=True))
        expected = {"MAPLESU_TASK_CRED_OFF": fixture["expected"]["task_struct.cred"],
                    "MAPLESU_CRED_UID_OFF": fixture["expected"]["cred.uid"],
                    "MAPLESU_CRED_EUID_OFF": fixture["expected"]["cred.euid"],
                    "MAPLESU_CRED_GROUPS_OFF": target["credGroupInfo"]["offset"],
                    "MAPLESU_GROUP_USAGE_OFF": target["groupUsage"]["offset"],
                    "MAPLESU_CRED_USAGE_OFF": target["credUsage"]["offset"],
                    "MAPLESU_CRED_USAGE_SIZE": target["credUsage"]["width"]}
        self.assertEqual(expected, {key: facts["defines"][key] for key in expected})
        self.assertEqual("sp_el0-task", facts["currentModel"]["currentModel"])

    def test_real_5_10_legacy_l3_uses_default_subject_description(self):
        contract_path = LOADER / "contracts/family-5.10.json"
        contract = builder.load_contract(contract_path)
        image_path, symbols_path = ROOT / contract["imagePath"], ROOT / contract["symbolsPath"]
        image = image_path.read_bytes()
        symbols = builder.SymbolTable(symbols_path)
        layouts = builder.legacy_cfi.legacy_510.image_layouts(builder, contract, image, symbols)
        cfi = builder.legacy_cfi.image_facts(builder, contract)
        facts = builder.legacy_cfi.l3_facts(builder, contract, image, symbols, cfi, layouts)
        subject = facts["rootSubject"]
        row = {"name": "real-5.10-legacy-subject", "fixture_kind": "real",
               "expected": "accepted", "actual": "accepted" if subject.get("layout") else "bypassed",
               "facts": subject, "scope": "actual legacy L3 facts entry; no module build or device"}
        OBSERVATIONS.append(row)
        for path in (contract_path, image_path, symbols_path,
                     ROOT / contract["abiEvidence"]["referenceModulePath"]):
            raw = path.read_bytes()
            SOURCES.append({"path": str(path.relative_to(ROOT)), "bytes": len(raw),
                            "sha256": hashlib.sha256(raw).hexdigest()})
        self.assertEqual("accepted", row["actual"], json.dumps(row, sort_keys=True))
        self.assertEqual("PRO_LAYOUT_SUBJECT_DESCRIBE", subject["layout"]["operation"])

    def test_forward_paths_merge_at_one_return(self):
        self.observe("forward-path-merge", "accepted", pack(MRS_SP_EL0_X8, load64(8, 8, self.cred),
                     load32(0, 8, self.uid), cbz(12, 20), NOP, RET),
                     model="both forward paths merge with identical proven UID state")

    def test_register_move_and_split_pointer_offsets_keep_the_origin(self):
        self.observe("move-split-pointer", "accepted", pack(MRS_SP_EL0_X8, 0xaa0803e9,
                     0x91000000 | (2048 << 10) | (9 << 5) | 9,
                     load64(9, 9, self.cred - 2048),
                     0x91000000 | (4 << 10) | (9 << 5) | 9,
                     load32(8, 9, self.uid - 4), 0x2a0803e0, RET))

    def test_pointer_truncation_and_missing_overflow_flags_are_rejected(self):
        self.observe("truncated-pointer-move", "rejected", pack(MRS_SP_EL0_X8, 0x2a0803e8,
                     load64(8, 8, self.cred), load32(0, 8, self.uid), RET))
        self.observe("overflow-flags-clobbered", "rejected", pack(MRS_SP_EL0_X8,
                     load64(8, 8, self.cred), load32(8, 8, self.uid), adr(9, 12, 128),
                     load32(9, 9, 0), 0x3100051f, 0x3100053f, 0x1a880120, RET),
                     following=b"\0" * 92 + pack(65534), added={"overflowuid": 128})

    def test_non_flag_instructions_preserve_cmn_source(self):
        self.observe("cmn-through-address-load-move", "accepted", pack(MRS_SP_EL0_X8,
                     load64(8, 8, self.cred), load32(8, 8, self.uid), 0x3100051f,
                     adr(9, 16, 128), load32(9, 9, 0), 0x2a0803ea, NOP, 0x1a8a0120, RET),
                     following=b"\0" * 88 + pack(65534), added={"overflowuid": 128})

    def test_conditional_paths_preserve_cmn_source(self):
        self.observe("cmn-through-conditional-merge", "accepted", pack(MRS_SP_EL0_X8,
                     load64(8, 8, self.cred), load32(8, 8, self.uid), adr(9, 12, 128),
                     load32(9, 9, 0), 0x3100051f, cbz(24, 32), NOP, 0x1a880120, RET),
                     following=b"\0" * 88 + pack(65534), added={"overflowuid": 128})

    def test_known_call_invalidates_cmn_source(self):
        self.observe("cmn-invalidated-by-call", "rejected", pack(MRS_SP_EL0_X8,
                     load64(8, 8, self.cred), load32(19, 8, self.uid), adr(9, 12, 128),
                     load32(20, 9, 0), 0x2a1303e1, 0x3100067f, branch(28, 96, True),
                     0x1a930280, RET), following=b"\0" * 56 + pack(RET) + b"\0" * 28 + pack(65534),
                     added={"from_kuid_munged": 96, "overflowuid": 128})

    def test_legacy_sys_getuid_uses_identical_bounded_semantics(self):
        row = self.observe("legacy-sys-getuid", "accepted", self.direct(),
                           added={"__arm64_sys_getuid": None, "sys_getuid": 0})
        self.assertEqual("sys_getuid", row["current_model"]["getter"])

    def test_both_getter_anchors_must_agree(self):
        self.observe("both-getters-consistent", "accepted", self.direct(), added={"sys_getuid": 0})
        self.observe("both-getters-conflicting", "rejected", self.direct() + pack(RET),
                     entry_size=16, added={"sys_getuid": 16, "fixture_legacy_end": 20})

    def test_forward_paths_have_separate_valid_returns(self):
        self.observe("forward-separate-returns", "accepted", pack(MRS_SP_EL0_X8,
                     load64(8, 8, self.cred), load32(0, 8, self.uid), cbz(12, 20), RET, RET))

    def test_forward_path_with_clobbered_uid_is_rejected(self):
        self.observe("forward-bad-path", "rejected", pack(MRS_SP_EL0_X8,
                     load64(8, 8, self.cred), load32(0, 8, self.uid), cbz(12, 24),
                     0x52800000, RET, RET))

    def test_branch_bounds_are_enforced(self):
        for name, destination in (("backward", 8), ("outside", 24)):
            with self.subTest(name=name):
                self.observe("conditional-" + name, "rejected", pack(MRS_SP_EL0_X8,
                             load64(8, 8, self.cred), load32(0, 8, self.uid), cbz(12, destination), RET))

    def test_exact_entry_stub_reaches_valid_body(self):
        row = self.observe("exact-entry-stub", "accepted", pack(branch(0, 16), NOP, NOP, NOP) + self.direct(),
                           entry_size=4, added={"fixture_body": 16, "fixture_body_end": 32})
        self.assertEqual([row["getuid_start"]], row["current_model"]["thunks"])

    def test_stub_requires_exact_symbol_target(self):
        for name, destination, added in (("missing", 16, {}),
                                        ("middle", 20, {"fixture_body": 16, "fixture_body_end": 32})):
            with self.subTest(name=name):
                self.observe("entry-stub-" + name, "rejected", pack(branch(0, destination), NOP, NOP, NOP) + self.direct(),
                             entry_size=4, added=added)

    def test_entry_stub_loop_is_rejected(self):
        self.observe("entry-stub-loop", "rejected", pack(branch(0, 16), NOP, NOP, NOP, branch(16, 0)),
                     entry_size=4, added={"fixture_loop": 16, "fixture_loop_end": 20})

    def test_uid_converter_call_and_tail(self):
        for call in (False, True):
            with self.subTest(call=call):
                prefix = [0xa9bf7bfd] if call else []
                words = prefix + [MRS_SP_EL0_X8, load64(8, 8, self.cred), load32(1, 8, self.uid)]
                words += [branch(len(words) * 4, 64, call)]
                if call:
                    words += [0xa8c17bfd, RET]
                self.observe("uid-converter-" + ("call" if call else "tail"), "accepted", pack(*words),
                             following=b"\0" * (64 - len(words) * 4) + pack(RET),
                             added={"from_kuid_munged": 64})

    def test_named_converter_outside_target_image_is_rejected(self):
        self.observe("converter-outside-image", "rejected", pack(MRS_SP_EL0_X8,
                     load64(8, 8, self.cred), load32(1, 8, self.uid), branch(12, 128)),
                     added={"from_kuid_munged": 128})

    def test_converter_requires_exact_uid_symbol_and_argument(self):
        for name, register, added in (("wrong-symbol", 1, {"from_kgid_munged": 64, "from_kuid_munged": None}),
                                      ("wrong-argument", 0, {"from_kuid_munged": 64})):
            with self.subTest(name=name):
                self.observe("converter-" + name, "rejected", pack(MRS_SP_EL0_X8,
                             load64(8, 8, self.cred), load32(register, 8, self.uid), branch(12, 64)), added=added)

    def test_overflow_projection_requires_address_flags_and_direction(self):
        for name, address, comparison, selection in (
                ("valid-eq", 128, 0x3100051f, 0x1a880120),
                ("valid-ne", 128, 0x3100051f, 0x1a891100),
                ("wrong-address", 132, 0x3100051f, 0x1a880120),
                ("wrong-flags", 128, 0x3100053f, 0x1a880120),
                ("wrong-direction", 128, 0x3100051f, 0x1a890100)):
            with self.subTest(name=name):
                self.observe("overflow-" + name, "accepted" if name.startswith("valid") else "rejected",
                             pack(MRS_SP_EL0_X8, load64(8, 8, self.cred), load32(8, 8, self.uid),
                                  adr(9, 12, address), load32(9, 9, 0), comparison, selection, RET),
                             following=b"\0" * 96 + pack(65534, 0), added={"overflowuid": 128})

    def test_named_overflow_outside_target_image_is_rejected(self):
        self.observe("overflow-outside-image", "rejected", pack(MRS_SP_EL0_X8,
                     load64(8, 8, self.cred), load32(8, 8, self.uid), adr(9, 12, 128),
                     load32(9, 9, 0), 0x3100051f, 0x1a880120, RET), added={"overflowuid": 128})

    def test_wrong_layout_and_load_width_are_rejected(self):
        for name, pointer, field in (("wrong-cred", self.cred + 8, self.uid),
                                     ("wrong-uid", self.cred, self.uid + 4)):
            with self.subTest(name=name):
                self.observe(name, "rejected", pack(MRS_SP_EL0_X8, load64(8, 8, pointer), load32(0, 8, field), RET))
        self.observe("32-bit-cred-pointer", "rejected", pack(MRS_SP_EL0_X8,
                     load32(8, 8, self.cred), load32(0, 8, self.uid), RET))

    def test_unknown_write_and_missing_return_are_rejected(self):
        self.observe("unknown-clobber", "rejected", pack(MRS_SP_EL0_X8,
                     load64(8, 8, self.cred), load32(0, 8, self.uid), 0x4a000000, RET))
        self.observe("missing-return", "rejected", self.direct()[:-4])

    def test_target_layout_alignment_is_rejected(self):
        for key in ("MAPLESU_TASK_CRED_OFF", "MAPLESU_CRED_UID_OFF"):
            with self.subTest(key=key):
                self.observe("unaligned-" + key, "rejected", self.direct(),
                             defines={**self.defines, key: self.defines[key] + 1})

    def test_invalid_getter_extent_is_controlled(self):
        for name, size in (("unaligned", 15), ("past-image", 256), ("empty", 0)):
            with self.subTest(name=name):
                self.observe("getter-extent-" + name, "rejected", self.direct(), entry_size=size)
        self.observe("getter-symbol-missing", "rejected", self.direct(), added={"__arm64_sys_getuid": None})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--receipt", type=Path)
    args, remaining = parser.parse_known_args()
    RECEIPT = args.receipt
    unittest.main(argv=[sys.argv[0], *remaining])
