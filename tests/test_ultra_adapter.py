"""Host tests for the GhostSam provider adapter V2 (wire/command/state, no device)."""

from __future__ import annotations

import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "jailbreak-providers" / "ghostsam" / "adapter"))
sys.path.insert(0, str(ROOT / "jailbreak-providers" / "lease" / "tests"))

import lease_wire as W  # noqa: E402
import lease_contract_ref as C  # noqa: E402

BOOT = "5334f916-9a56-4267-8d79-cb67a4782ece"
NONCE = bytes(range(32))
NONCE_HEX = NONCE.hex()
GOLDEN_HEX = (
    "4d4a424c00000002000000010000109200000000000000010000000200000001"
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    "00000024" "35333334663931362d396135362d343236372d386437392d636236376134373832656365"
    "0000000c" "753a723a7368656c6c3a7330"
    "00000001" "00000002"
)


def pending(**over):
    base = dict(endpoint="maplesu-jb-a", nonce=NONCE, nonce_hex=NONCE_HEX,
                manager_uid=10000, boot_id=BOOT, provider=1)
    base.update(over)
    return W.PendingLease(**base)


class ACommandBuilderTests(unittest.TestCase):
    def test_endpoint_nonce_boot_uid_rules_shared_with_contract(self):
        self.assertTrue(C.endpoint(b"maplesu-jb-a"))
        self.assertTrue(C.endpoint(b"maplesu-jb-" + b"a" * 88))
        for bad in (b"", b"maplesu-jb-", b"other-1", b"maplesu-jb-A", b"maplesu-jb-../x", b"maplesu-jb-" + b"a" * 90):
            self.assertFalse(C.endpoint(bad), bad)
        self.assertTrue(C.boot_id(BOOT.encode()))
        self.assertFalse(C.boot_id((BOOT + "\n").encode()))

    def test_build_argv_valid_and_invalid(self):
        argv = W.build_argv("/data/app/x/consumer", "maplesu-jb-a", NONCE_HEX, 10000, BOOT, "ghostlock", "u")
        self.assertEqual(argv[1:6], ["maplesu-jb-a", NONCE_HEX, "10000", BOOT, "ghostlock"])
        self.assertEqual(argv[6], "u")
        for kwargs in (
            dict(endpoint=""), dict(endpoint="maplesu-jb-"), dict(nonce_hex="0" * 63),
            dict(nonce_hex="G" + "0" * 63), dict(uid=9999), dict(boot_id="0" * 36),
            dict(provider_key="other"), dict(endpoint="maplesu-jb-a\nb"),
            dict(endpoint="maplesu-jb-a'b"),
        ):
            args = dict(consumer_path="/c", endpoint="maplesu-jb-a", nonce_hex=NONCE_HEX,
                        uid=10000, boot_id=BOOT, provider_key="ghostlock")
            args.update(kwargs)
            with self.subTest(kwargs=kwargs), self.assertRaises(W.WireError):
                W.build_argv(args["consumer_path"], args["endpoint"], args["nonce_hex"],
                             args["uid"], args["boot_id"], args["provider_key"])

    def test_command_quotes_all_args_in_order(self):
        cmd = W.build_command("/c", "maplesu-jb-a", NONCE_HEX, 10000, BOOT, "ghostlock")
        argv = W.build_argv("/c", "maplesu-jb-a", NONCE_HEX, 10000, BOOT, "ghostlock")
        self.assertTrue(cmd.startswith("exec "))
        for a in argv:
            self.assertIn("'" + a + "'", cmd)


class BPrimitiveFrameTests(unittest.TestCase):
    def test_c_frame_le_u32(self):
        cmd = "exec '/c' 'maplesu-jb-a'"
        frame = W.encode_c_frame(cmd)
        self.assertEqual(frame[0], 0x43)
        self.assertEqual(struct.unpack_from("<I", frame, 1)[0], len(cmd.encode()))
        self.assertEqual(W.decode_c_frame(frame), cmd)

    def test_c_frame_rejects_nul(self):
        with self.assertRaises(W.WireError):
            W.encode_c_frame("a\x00b")
        with self.assertRaises(W.WireError):
            W.decode_c_frame(b"C" + struct.pack("<I", 3) + b"ab")  # length mismatch


class CMjblGoldenTests(unittest.TestCase):
    def test_golden_bytes(self):
        frame = W.encode_mjbl_v2(1, 4242, 0, 0x0000000100000002, NONCE, BOOT, "u:r:shell:s0", 1, 2)
        self.assertEqual(frame.hex(), GOLDEN_HEX)
        self.assertEqual(len(frame), 128)
        self.assertEqual(W.decode_mjbl_v2(frame, expected_nonce=NONCE, expected_boot_id=BOOT,
                                          peer_pid=4242, peer_uid=0)["starttime"], 0x0000000100000002)

    def test_starttime_zero_rejected(self):
        zero = W.encode_mjbl_v2(1, 4242, 0, 0, NONCE, BOOT, "u:r:shell:s0", 1, 2)
        with self.assertRaises(W.WireError) as ctx:
            W.decode_mjbl_v2(zero, expected_nonce=NONCE, expected_boot_id=BOOT, peer_pid=4242, peer_uid=0)
        self.assertEqual(ctx.exception.token, "LEASE_WORKER_STARTTIME_INVALID")
        with self.assertRaises(W.WireError) as ctx2:
            W.decode_mjbl_v2(bytes.fromhex(GOLDEN_HEX), expected_nonce=NONCE, expected_boot_id=BOOT,
                             peer_pid=4242, peer_uid=0, expected_starttime=123)
        self.assertEqual(ctx2.exception.token, "LEASE_WORKER_STARTTIME_INVALID")

    def _mut(self, mutate):
        b = bytearray(bytes.fromhex(GOLDEN_HEX))
        mutate(b)
        return bytes(b)

    def test_field_corruption_tokens(self):
        cases = [
            ("magic", lambda b: b.__setitem__(slice(0, 4), struct.pack(">I", 0xDEADBEEF)), "LEASE_MAGIC_INVALID"),
            ("version", lambda b: b.__setitem__(slice(4, 8), struct.pack(">I", 1)), "LEASE_VERSION_INVALID"),
            ("provider", lambda b: b.__setitem__(slice(8, 12), struct.pack(">I", 3)), "LEASE_PROVIDER_INVALID"),
            ("pid", lambda b: b.__setitem__(slice(12, 16), struct.pack(">I", 1)), "LEASE_SHELL_PID_INVALID"),
            ("uid", lambda b: b.__setitem__(slice(16, 20), struct.pack(">I", 10000)), "LEASE_UID_MISMATCH"),
            ("cap", lambda b: b.__setitem__(slice(28, 32), struct.pack(">I", 0)), "LEASE_CAPABILITY_MISSING"),
            ("nonce", lambda b: b.__setitem__(32, b[32] ^ 0xFF), "LEASE_NONCE_MISMATCH"),
            ("boot", lambda b: b.__setitem__(68, ord("0") if b[68] != ord("0") else ord("1")), "LEASE_BOOT_ID_MISMATCH"),
            ("enforcing", lambda b: b.__setitem__(slice(120, 124), struct.pack(">I", 2)), "LEASE_ENFORCING_INVALID"),
            ("seccomp", lambda b: b.__setitem__(slice(124, 128), struct.pack(">I", 3)), "LEASE_SECCOMP_UNAVAILABLE"),
        ]
        for name, mutate, token in cases:
            with self.subTest(field=name):
                with self.assertRaises(W.WireError) as ctx:
                    W.decode_mjbl_v2(self._mut(mutate), expected_nonce=NONCE, expected_boot_id=BOOT,
                                     peer_pid=4242, peer_uid=0)
                self.assertEqual(ctx.exception.token, token)


class DMalformedFrameTests(unittest.TestCase):
    def test_await_twice(self):
        b = W.LeaseBinder()
        b.await_once()
        with self.assertRaises(W.WireError) as ctx:
            b.await_once()
        self.assertEqual(ctx.exception.token, "LEASE_AWAIT_ALREADY_USED")

    def test_failure_and_restore_frames(self):
        self.assertEqual(W.failure_frame("STDIO"), bytes([ord("F"), 6, 0, 0, 0]))
        with self.assertRaises(W.WireError):
            W.failure_frame("NOPE")
        r = W.restore_frame(1, 1, 1, 0, 0, 0)
        self.assertEqual(len(r), 10)
        self.assertEqual(W.parse_restore_frame(r)["applied"], 1)
        for bad_len in (r[:9], r + b"\x00"):  # 9-byte truncation and 11-byte overlong must be rejected
            with self.subTest(bad_len=len(bad_len)):
                with self.assertRaises(W.WireError):
                    W.parse_restore_frame(bad_len)
        with self.assertRaises(W.WireError):
            W.restore_frame(9, 1, 1, 0, 0, 0)

    def test_ready_frame(self):
        self.assertEqual(W.ready_frame(4242)[0], ord("R"))
        with self.assertRaises(W.WireError):
            W.ready_frame(1)


class EAdapterStateTests(unittest.TestCase):
    def test_success_and_capability(self):
        binder = W.LeaseBinder()
        res = W.AdapterProvider(binder).run(
            consumer_present=True, consumer_digest_ok=True, primitive_available=True,
            pending=pending(), peer_uid=0, peer_pid=4242, starttime=0x0000000100000002,
            domain="u:r:shell:s0", enforcing=1, seccomp=2)
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["token"], "DAEMON_READY")
        self.assertEqual(res["capability"], ["RAW_ROOT_LEASE"])
        self.assertFalse(binder.transport_open)
        self.assertTrue(binder.nonce_zeroed)

    def test_failure_recovery_tokens(self):
        for kwargs, token in (
            (dict(consumer_present=False), "CONSUMER_MISSING"),
            (dict(consumer_digest_ok=False), "DIGEST_MISMATCH"),
            (dict(primitive_available=False), "GHOSTSAM_PRIMITIVE_DENIED"),
            (dict(pending=None), "LEASE_PENDING_MISSING"),
        ):
            base = dict(consumer_present=True, consumer_digest_ok=True, primitive_available=True,
                        pending=pending(), peer_uid=0, peer_pid=4242, starttime=1,
                        domain="u:r:shell:s0", enforcing=1, seccomp=2)
            base.update(kwargs)
            binder = W.LeaseBinder()
            res = W.AdapterProvider(binder).run(**base)
            self.assertFalse(res["ok"], kwargs)
            self.assertEqual(res["token"], token)
            self.assertFalse(binder.transport_open)


class FFailClosedTests(unittest.TestCase):
    def test_no_nonce_no_authorization(self):
        p = pending(nonce=b"\x00" * 32, nonce_hex="00" * 32)  # consumer/stdin nonce differs from expected below
        frame = W.encode_mjbl_v2(1, 4242, 0, 1, bytes(range(32)), BOOT, "u:r:shell:s0", 1, 2)
        with self.assertRaises(W.WireError) as ctx:
            W.decode_mjbl_v2(frame, expected_nonce=p.nonce, expected_boot_id=BOOT, peer_pid=4242, peer_uid=0)
        self.assertEqual(ctx.exception.token, "LEASE_NONCE_MISMATCH")

    def test_boot_mismatch_and_peer_uid(self):
        frame = W.encode_mjbl_v2(1, 4242, 0, 1, NONCE, BOOT, "u:r:shell:s0", 1, 2)
        with self.assertRaises(W.WireError) as c1:
            W.decode_mjbl_v2(frame, expected_nonce=NONCE, expected_boot_id="00000000-0000-0000-0000-000000000000",
                             peer_pid=4242, peer_uid=0)
        self.assertEqual(c1.exception.token, "LEASE_BOOT_ID_MISMATCH")
        with self.assertRaises(W.WireError) as c2:
            W.decode_mjbl_v2(frame, expected_nonce=NONCE, expected_boot_id=BOOT, peer_pid=4242, peer_uid=2000)
        self.assertEqual(c2.exception.token, "LEASE_ROOT_PEER_REQUIRED")

    def test_capability_gate_rejects_ultra(self):
        W.CapabilityGate.assert_no_ultra({})
        with self.assertRaises(W.WireError):
            W.CapabilityGate.assert_no_ultra({"ultraState": "ACTIVE"})
        res = W.AdapterProvider().run(consumer_present=True, consumer_digest_ok=True,
                                      primitive_available=True, pending=pending(), peer_uid=0,
                                      peer_pid=4242, starttime=1, domain="u:r:shell:s0",
                                      enforcing=1, seccomp=2, facts={"ultraKeyPresent": True})
        self.assertEqual(res["token"], "CAPABILITY_OUT_OF_SCOPE:ultraKeyPresent")


class GV2LeaseOwnershipTests(unittest.TestCase):
    def test_ghostsamleasefactory_generates_without_rootshelllease(self):
        p = W.GhostsamLeaseFactory.create(manager_uid=10000, boot_id=BOOT, endpoint="maplesu-jb-a", nonce=NONCE)
        self.assertTrue(p.endpoint.startswith("maplesu-jb-"))
        self.assertEqual(len(p.nonce), 32)
        self.assertEqual(p.nonce_hex, NONCE_HEX)
        with self.assertRaises(W.WireError):
            W.GhostsamLeaseFactory.create(manager_uid=9999, boot_id=BOOT)
        with self.assertRaises(W.WireError):
            W.GhostsamLeaseFactory.create(manager_uid=10000, boot_id="0" * 36)

    def test_v2_command_line_has_no_nonce(self):
        # V2: nonce via stdin TLV, argv must NOT contain the 64-hex nonce.
        cmd = W.build_command("/c", "maplesu-jb-a", NONCE_HEX, 10000, BOOT, "ghostlock", include_nonce=False)
        self.assertNotIn(NONCE_HEX, cmd)
        self.assertNotIn(NONCE_HEX, "/c maplesu-jb-a 10000 " + BOOT + " ghostlock")
        tlv = W.encode_stdin_tlv(NONCE, "maplesu-jb-a", 10000, BOOT)
        self.assertIn(NONCE, tlv)  # nonce travels on stdin, not argv
        # V1 (canonical argv) still carries nonce -> R2 residual risk applies (documented).
        cmd_v1 = W.build_command("/c", "maplesu-jb-a", NONCE_HEX, 10000, BOOT, "ghostlock")
        self.assertIn(NONCE_HEX, cmd_v1)

    def test_stdin_tlv_roundtrip_and_tamper(self):
        tlv = W.encode_stdin_tlv(NONCE, "maplesu-jb-a", 10000, BOOT)
        got = W.decode_stdin_tlv(tlv)
        self.assertEqual(got["nonce"], NONCE)
        self.assertEqual(got["endpoint"], "maplesu-jb-a")
        self.assertEqual(got["uid"], 10000)
        self.assertEqual(got["boot_id"], BOOT)
        # consumer builds identity from the stdin TLV (endpoint/uid/boot/nonce cross-checked)
        p = pending()
        frame = W.ConsumerV2.identity_frame(p, 4242, 1, "u:r:shell:s0", 1, 2)
        self.assertEqual(W.decode_mjbl_v2(frame, expected_nonce=NONCE, expected_boot_id=BOOT,
                                          peer_pid=4242, peer_uid=0)["uid"], 0)
        for bad in (tlv[:-1], tlv + b"\x00", b"", tlv[:3]):
            with self.subTest(bad=bad[:4]):
                with self.assertRaises(W.WireError):
                    W.decode_stdin_tlv(bad)


class HResultFrameTests(unittest.TestCase):
    def test_p_restore_exact_10(self):
        r = W.restore_frame(1, 1, 1, 0, 0, 0)
        self.assertEqual(W.parse_result_frame(r)["tag"], "P")
        for bad in (r[:9], r + b"\x00"):
            with self.assertRaises(W.WireError):
                W.parse_result_frame(bad)
        with self.assertRaises(W.WireError) as c:
            W.parse_result_frame(bytes([ord("P"), 1, 9, 1, 0, 0, 0, 0, 0, 0]))
        self.assertEqual(c.exception.token, "LEASE_RESTORE_ORIGIN_INVALID")

    def test_x_d_tags_single_byte(self):
        self.assertEqual(W.parse_result_frame(b"X")["tag"], "X")
        self.assertEqual(W.parse_result_frame(b"D")["tag"], "D")
        with self.assertRaises(W.WireError) as cx:
            W.parse_result_frame(b"X\x00\x00\x00\x00")  # trailing payload must be rejected
        self.assertEqual(cx.exception.token, "LEASE_RESULT_TRAILING")
        with self.assertRaises(W.WireError) as cd:
            W.parse_result_frame(b"D\x00")  # non-empty D payload must be rejected
        self.assertEqual(cd.exception.token, "LEASE_D_PAYLOAD_NONEMPTY")
        with self.assertRaises(W.WireError) as cz:
            W.parse_result_frame(b"Z")
        self.assertEqual(cz.exception.token, "LEASE_RESULT_TAG_INVALID")
        self.assertEqual(W.parse_result_frame(W.ready_frame(4242))["pid"], 4242)
        self.assertEqual(W.parse_result_frame(W.failure_frame("STDIO"))["stage"], 6)

    def test_v2_fd_args_form_and_reference_transport(self):
        cmd = W.build_command("/c", "maplesu-jb-a", NONCE_HEX, 10000, BOOT, "ghostlock", fd_args=True)
        self.assertEqual(cmd, "exec '/c' '--fd-args'")
        self.assertNotIn(NONCE_HEX, cmd)
        t = W.ReferenceLeaseTransport()
        ident = t.run(pending(), pid=4242, starttime=0x0000000100000002,
                      domain="u:r:shell:s0", enforcing=1, seccomp=2)
        self.assertEqual(ident["starttime"], 0x0000000100000002)
        # same 'C' stream: 'C'+LE len+command, then stdin TLV packet on the same connection
        self.assertEqual(t.stream[0], 0x43)
        self.assertIn(b"\x02", bytes(t.stream))
        self.assertIn(NONCE, bytes(t.stream))


class IAdmissionWiringTests(unittest.TestCase):
    """Static registration checks against the real MapleSU jailbreak sources + mirror logic."""

    def _src(self, rel):
        return (ROOT / "manager/src/main/java/dev/maplesu/manager/jailbreak" / rel).read_text(encoding="utf-8")

    def test_registration_exists_in_sources(self):
        admission = self._src("JailbreakAdmission.kt")
        self.assertIn('GHOSTSAM("ghostsam")', admission)
        self.assertIn("JailbreakMethod.GHOSTSAM -> listOf(\"libmaplesu_ghostsam_consumer.so\")", admission)
        request = self._src("JailbreakRequest.kt")
        self.assertIn('const val BACKEND_GHOSTSAM = "ghostsam"', request)
        self.assertIn("BACKEND_KSU, BACKEND_GHOSTSAM", request)  # ROUTABLE_BACKENDS membership
        executor = self._src("JailbreakExecutor.kt")
        self.assertIn("JailbreakMethod.GHOSTSAM.wireName -> escalateGhostsam", executor)
        self.assertIn("GhostsamAttempt.run(", executor)
        attempt = self._src("ghostsam/GhostsamAttempt.kt")
        self.assertIn("LeaseBinder(", attempt)
        self.assertIn("DefaultLeaseTransport(lease.server)", attempt)

    def test_missing_primitive_and_artifact_fail_closed(self):
        self.assertEqual(W.GhostsamAdmission.blockers(), [])
        self.assertEqual(W.GhostsamAdmission.blockers(primitive_available=False), ["GHOSTSAM_PRIMITIVE_DENIED"])
        self.assertEqual(W.GhostsamAdmission.blockers(artifact_present=False), ["ARTIFACT_UNVERIFIED"])
        self.assertEqual(W.GhostsamAdmission.blockers(owner_only=False), ["PROVIDER_OWNER_ONLY"])
        self.assertEqual(W.GhostsamAdmission.blockers(arm64=False), ["PROVIDER_ABI_UNSUPPORTED"])
        self.assertEqual(W.GhostsamAdmission.CAPABILITIES, frozenset({"RAW_ROOT_LEASE"}))

    def test_capability_superset_rejected(self):
        bad = W.GhostsamAdmission.blockers(capability="ULTRA_KERNEL_SU")
        self.assertEqual(bad, ["CAPABILITY_OUT_OF_SCOPE:ULTRA_KERNEL_SU"])
        with self.assertRaises(W.WireError):
            W.CapabilityGate.assert_no_ultra({"ultraState": "ACTIVE"})


class JN1N2Tests(unittest.TestCase):
    def test_self_starttime_field22_last_paren(self):
        # comm contains ')' -> must anchor on the LAST ')'; field 3 is state, not a number.
        line = "4242 (a)b) R " + " ".join(str(i) for i in range(4, 22)) + " 987654"
        self.assertEqual(W.self_starttime(line), 987654)
        self.assertEqual(C.self_starttime(line), 987654)
        for bad in ("", "no-paren", "1 (x) R 1 2"):
            self.assertEqual(W.self_starttime(bad), 0)
        # state 'S' followed by exactly fields 4..22
        self.assertEqual(W.self_starttime("9 (sh) S 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22"), 22)

    def test_factory_listener_lifecycle(self):
        lease = W.GhostsamLeaseFactory.create(manager_uid=10000, boot_id=BOOT,
                                              endpoint="maplesu-jb-a", nonce=NONCE)
        self.assertIsNotNone(lease.server)
        self.assertTrue(lease.server.open)
        self.assertEqual(lease.server.endpoint, "maplesu-jb-a")
        t = W.ReferenceLeaseTransport()
        t.run(lease, pid=4242, starttime=0x0000000100000002, domain="u:r:shell:s0", enforcing=1, seccomp=2)
        self.assertTrue(lease.server.open)          # stays listening during await
        self.assertEqual(lease.server.accepted, 1)
        W.GhostsamLeaseFactory.close(lease)
        self.assertFalse(lease.server.open)         # closed on close
        self.assertEqual(bytes(lease.nonce), b"\x00" * 32)  # nonce zeroed
        with self.assertRaises(W.WireError) as ctx:
            t.run(lease, pid=4242, starttime=1, domain="u:r:shell:s0", enforcing=1, seccomp=2)
        self.assertEqual(ctx.exception.token, "GHOSTSAM_SERVER_CLOSED")
        lease2 = W.GhostsamLeaseFactory.create(manager_uid=10000, boot_id=BOOT,
                                               endpoint="maplesu-jb-b", nonce=NONCE)
        self.assertIsNot(lease2.server, lease.server)


class KRepairT30Tests(unittest.TestCase):
    def _read(self, rel):
        return (ROOT / "manager/src/main/java/dev/maplesu/manager/jailbreak" / rel).read_text(encoding="utf-8")

    def test_f1_default_transport_maps_closed_listener(self):
        src = self._read("ghostsam/DefaultLeaseTransport.kt")
        self.assertIn("GHOSTSAM_SERVER_CLOSED", src)
        self.assertIn("catch (e: IOException)", src)
        self.assertIn("catch (e: IllegalStateException)", src)

    def test_f2_f3_single_entry_via_adapter_provider(self):
        attempt = self._read("ghostsam/GhostsamAttempt.kt")
        self.assertIn("AdapterProvider(", attempt)
        self.assertIn("GhostsamBackend.ghostsamFacts()", attempt)
        self.assertIn("transportFactory", self._read("ghostsam/AdapterProvider.kt"))
        # capability gate still reachable via AdapterProvider.run
        ap = self._read("ghostsam/AdapterProvider.kt")
        self.assertIn("CapabilityGate.assertNoUltra(request.facts)", ap)

    def test_f4_ghostsam_label_and_readiness_gate(self):
        dlg = self._read("JailbreakSelectionDialog.kt")
        self.assertIn('"GhostSam"', dlg)
        self.assertIn("ghostsamReadiness.ready", dlg)
        backend = self._read("ghostsam/GhostsamBackend.kt")
        self.assertIn("fun readiness(", backend)
        self.assertIn("fun ultraFacts(", backend)
        self.assertIn("ghostsamReady", self._read("JailbreakSelectionUi.kt"))
        self.assertIn("JailbreakMethod.GHOSTSAM -> ghostsamReady", self._read("JailbreakSelectionUi.kt"))
        self.assertIn('"GhostSam"', self._read("JailbreakLogPanel.kt"))

    def test_f6_real_timestamps_and_attempt_link(self):
        ex = self._read("JailbreakExecutor.kt")
        idx = ex.index("private fun escalateGhostsam")
        section = ex[idx: idx + 900]
        self.assertIn("System.currentTimeMillis()", section)
        self.assertIn("request.attemptId", section)
        self.assertNotIn("startedAtMillis = 0", section)


class LGateDefaultFactsTests(unittest.TestCase):
    # Product default facts carry ONLY lease fields (no Ultra keys at all).
    DEFAULT = {"jailbreakLeaseValid": True, "leaseCapability": "RAW_ROOT_LEASE", "r7": "A_JAILBREAK"}

    def test_default_ultra_facts_pass_gate(self):
        W.CapabilityGate.assert_no_ultra(self.DEFAULT)  # lease-only facts pass
        for state in ("ABSENT", "NONE"):
            facts = dict(self.DEFAULT, ultraState=state)  # explicit absence sentinels pass
            W.CapabilityGate.assert_no_ultra(facts)

    def test_unknown_ultra_state_rejected(self):
        # UNKNOWN means "unverified", not absence: it must stay fail-closed (no fail-open).
        facts = dict(self.DEFAULT, ultraState="UNKNOWN")
        with self.assertRaises(W.WireError) as ctx:
            W.CapabilityGate.assert_no_ultra(facts)
        self.assertEqual(ctx.exception.token, "CAPABILITY_OUT_OF_SCOPE:ultraState=UNKNOWN")
        W.CapabilityGate.assert_no_ultra({})
        W.CapabilityGate.assert_no_ultra(self.DEFAULT)

    def test_any_truthy_ultra_field_rejected(self):
        cases = [
            ("ultraState", "RUNNING", "CAPABILITY_OUT_OF_SCOPE:ultraState"),
            ("ultraKeyPresent", True, "CAPABILITY_OUT_OF_SCOPE:ultraKeyPresent"),
            ("ultraKernelRootVerified", True, "CAPABILITY_OUT_OF_SCOPE:ultraKernelRootVerified"),
            ("IRootManagementService", "binder", "CAPABILITY_OUT_OF_SCOPE:IRootManagementService"),
        ]
        for field, value, token in cases:
            with self.subTest(field=field):
                with self.assertRaises(W.WireError) as ctx:
                    W.CapabilityGate.assert_no_ultra(dict(self.DEFAULT, **{field: value}))
                self.assertEqual(ctx.exception.token, token)

    def test_gate_runs_before_provisioner_in_mirror(self):
        res = W.AdapterProvider().run(
            consumer_present=False, consumer_digest_ok=False, primitive_available=False,
            pending=None, peer_uid=0, peer_pid=1, starttime=1, domain="", enforcing=1, seccomp=0,
            facts={"ultraState": "RUNNING"})
        self.assertFalse(res["ok"])
        self.assertEqual(res["token"], "CAPABILITY_OUT_OF_SCOPE:ultraState")  # not CONSUMER_MISSING

    def test_correct_facts_reach_raw_root_lease(self):
        res = W.AdapterProvider().run(
            consumer_present=True, consumer_digest_ok=True, primitive_available=True,
            pending=pending(), peer_uid=0, peer_pid=4242, starttime=0x0000000100000002,
            domain="u:r:shell:s0", enforcing=1, seccomp=2, facts=dict(self.DEFAULT))
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["capability"], ["RAW_ROOT_LEASE"])

    def test_static_order_gate_before_binder(self):
        src = (ROOT / "manager/src/main/java/dev/maplesu/manager/jailbreak/ghostsam/AdapterProvider.kt").read_text(encoding="utf-8")
        gate = src.index("CapabilityGate.assertNoUltra(request.facts)")
        self.assertLess(gate, src.index("provisioner.resolve()"))
        self.assertLess(gate, src.index("binder.prepare()"))
        self.assertLess(gate, src.index("binder.awaitOnce()"))
        backend = (ROOT / "manager/src/main/java/dev/maplesu/manager/jailbreak/ghostsam/GhostsamBackend.kt").read_text(encoding="utf-8")
        self.assertIn("fun ghostsamFacts(", backend)
        self.assertNotIn("ultraState", backend.split("fun ghostsamFacts(")[1].split("}")[0])


def _selection_can_start(method, *, ghostsam_ready=False, running=False, checks_ready=True,
                         blockers_present=False, parsing=False):
    if running or not checks_ready or blockers_present or parsing:
        return False
    return ghostsam_ready if method == "ghostsam" else True

class MUiGateT35Tests(unittest.TestCase):
    def test_ghostsam_canstart_positive_and_negative(self):
        self.assertTrue(_selection_can_start("ghostsam", ghostsam_ready=True))
        self.assertFalse(_selection_can_start("ghostsam", ghostsam_ready=False))
        # other gates still dominate
        self.assertFalse(_selection_can_start("ghostsam", ghostsam_ready=True, running=True))
        self.assertFalse(_selection_can_start("ghostsam", ghostsam_ready=True, blockers_present=True))
        self.assertFalse(_selection_can_start("ghostsam", ghostsam_ready=True, checks_ready=False))

    def test_dialog_passes_ghostsam_ready_and_refresh_key(self):
        dlg = (ROOT / "manager/src/main/java/dev/maplesu/manager/jailbreak/JailbreakSelectionDialog.kt").read_text(encoding="utf-8")
        self.assertIn("ghostsamReady = ghostsamReadiness.ready", dlg)
        self.assertIn("remember(context, method)", dlg)

    def test_backend_facts_drop_unused_context(self):
        backend = (ROOT / "manager/src/main/java/dev/maplesu/manager/jailbreak/ghostsam/GhostsamBackend.kt").read_text(encoding="utf-8")
        self.assertIn("fun ghostsamFacts():", backend)
        self.assertNotIn("fun ghostsamFacts(context", backend)
        self.assertIn("fun ultraFacts():", backend)


if __name__ == "__main__":
    unittest.main()
