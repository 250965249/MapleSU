"""GhostSam provider adapter V2 — host-executable reference implementation.

This module is the MapleSU-side V2 adapter logic, written so it can be executed and
byte-checked on a plain host (no Android device / NDK). It mirrors what the Kotlin
components (`GhostsamPrimitiveClient`, `CommandBuilder`, `LeaseBinder`,
`AdapterProvider`, `CapabilityGate`) and the self-built consumer do on device.

Contract sources:
  - MJBL v2 frame + argv rules: jailbreak-providers/lease/src/root_consumer.cpp,
    jailbreak-providers/android/.../LeaseProtocol.java, lease_contract.c
  - GhostSam 'C' primitive: gs-ci LocalSuDaemon.kt ('C' + LE u32 + UTF-8 command)

V2 differences vs upstream V1 (per t16 §4.3 + t19 P2):
  - self-built consumer; nonce is supplied via STDIN, never argv
  - never writes /sys/fs/selinux/enforce (no selinuxfs write)
  - lease restore is handed back to GhostSam primitive ('C'), not done in-process
"""

from __future__ import annotations

import hmac
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path

_TESTS = Path(__file__).resolve().parents[3] / "jailbreak-providers" / "lease" / "tests"
if str(_TESTS) not in sys.path:
    sys.path.insert(0, str(_TESTS))
import lease_contract_ref as C  # noqa: E402

MJBL_MAGIC = 0x4D4A424C
VERSION_V2 = 2
PROVIDER_GHOSTLOCK = 1
PROVIDER_DIRTYFRAG = 2
CAPABILITY_ROOT_WORKER = 1
BOOT_ID_MAX = 128
DOMAIN_MAX = 256
RESTORE_FRAME_LEN = 10
FAILURE_STAGES = {"ARGUMENTS": 1, "ROOT_WORKER": 2, "IDENTITY": 3, "SOCKET": 4,
                  "PEER": 5, "STDIO": 6, "EXEC": 7}


def self_starttime(stat_line: str) -> int:
    """N1 mirror: same last-')' anchor + skip state + field 22 semantics as the C consumer."""
    return C.self_starttime(stat_line)


class WireError(RuntimeError):
    def __init__(self, token: str):
        super().__init__(token)
        self.token = token


def _u32(v: int) -> bytes:
    if not (0 <= v <= 0xFFFFFFFF):
        raise WireError("LEASE_FIELD_RANGE_INVALID")
    return struct.pack(">I", v)


def _field(text: bytes, limit: int, token: str) -> bytes:
    if len(text) > limit:
        raise WireError(token)
    return _u32(len(text)) + text


# --------------------------------------------------------------------------- MJBL v2
def encode_mjbl_v2(provider: int, pid: int, uid: int, starttime: int, nonce: bytes,
                   boot_id: str, domain: str, enforcing: int, seccomp: int,
                   capability: int = CAPABILITY_ROOT_WORKER) -> bytes:
    if len(nonce) != 32:
        raise WireError("LEASE_NONCE_INVALID")
    if provider not in (PROVIDER_GHOSTLOCK, PROVIDER_DIRTYFRAG):
        raise WireError("LEASE_PROVIDER_INVALID")
    if enforcing not in (0, 1):
        raise WireError("LEASE_ENFORCING_INVALID")
    if seccomp not in (0, 1, 2):
        raise WireError("LEASE_SECCOMP_UNAVAILABLE")
    out = bytearray()
    out += _u32(MJBL_MAGIC) + _u32(VERSION_V2) + _u32(provider) + _u32(pid) + _u32(uid)
    out += _u32((starttime >> 32) & 0xFFFFFFFF) + _u32(starttime & 0xFFFFFFFF)
    out += _u32(capability)
    out += nonce
    out += _field(boot_id.encode("utf-8"), BOOT_ID_MAX, "LEASE_BOOT_ID_INVALID")
    out += _field(domain.encode("utf-8"), DOMAIN_MAX, "LEASE_DOMAIN_INVALID")
    out += _u32(enforcing) + _u32(seccomp)
    return bytes(out)


def decode_mjbl_v2(data: bytes, *, expected_nonce: bytes, expected_boot_id: str,
                   peer_pid: int, peer_uid: int, expected_starttime: int | None = None) -> dict:
    """Decode + validate an MJBL v2 identity frame (fail-closed, named tokens)."""
    pos = 0

    def u32() -> int:
        nonlocal pos
        if pos + 4 > len(data):
            raise WireError("LEASE_FRAME_TRUNCATED")
        v = struct.unpack_from(">I", data, pos)[0]
        pos += 4
        return v

    if u32() != MJBL_MAGIC:
        raise WireError("LEASE_MAGIC_INVALID")
    version = u32()
    if version != VERSION_V2:
        raise WireError("LEASE_VERSION_INVALID")
    provider = u32()
    if provider not in (PROVIDER_GHOSTLOCK, PROVIDER_DIRTYFRAG):
        raise WireError("LEASE_PROVIDER_INVALID")
    pid = u32()
    if pid != peer_pid or pid <= 1:
        raise WireError("LEASE_SHELL_PID_INVALID")
    uid = u32()
    if peer_uid != 0:
        raise WireError("LEASE_ROOT_PEER_REQUIRED")
    if uid != peer_uid:
        raise WireError("LEASE_UID_MISMATCH")
    start_hi = u32()
    start_lo = u32()
    starttime = (start_hi << 32) | start_lo
    if starttime == 0:
        raise WireError("LEASE_WORKER_STARTTIME_INVALID")
    if expected_starttime is not None and starttime != expected_starttime:
        raise WireError("LEASE_WORKER_STARTTIME_INVALID")
    cap = u32()
    if cap != CAPABILITY_ROOT_WORKER:
        raise WireError("LEASE_CAPABILITY_MISSING")
    if pos + 32 > len(data):
        raise WireError("LEASE_FRAME_TRUNCATED")
    nonce = data[pos:pos + 32]; pos += 32
    if not hmac.compare_digest(nonce, expected_nonce):
        raise WireError("LEASE_NONCE_MISMATCH")
    boot_len = u32()
    if boot_len > BOOT_ID_MAX or pos + boot_len > len(data):
        raise WireError("LEASE_BOOT_ID_INVALID")
    boot = data[pos:pos + boot_len].decode("utf-8", "replace"); pos += boot_len
    if boot != expected_boot_id:
        raise WireError("LEASE_BOOT_ID_MISMATCH")
    dom_len = u32()
    if dom_len > DOMAIN_MAX or pos + dom_len > len(data):
        raise WireError("LEASE_DOMAIN_INVALID")
    domain = data[pos:pos + dom_len].decode("utf-8", "replace"); pos += dom_len
    enforcing = u32()
    if enforcing not in (0, 1):
        raise WireError("LEASE_ENFORCING_INVALID")
    seccomp = u32()
    if seccomp not in (0, 1, 2):
        raise WireError("LEASE_SECCOMP_UNAVAILABLE")
    if pos != len(data):
        raise WireError("LEASE_FRAME_TRAILING")
    return {"provider": provider, "pid": pid, "uid": uid,
            "starttime": (start_hi << 32) | start_lo, "boot_id": boot,
            "domain": domain, "enforcing": enforcing, "seccomp": seccomp}


# --------------------------------------------------------------------------- stdin TLV (V2)
# First packet on the self-built consumer's stdin: a compact TLV stream carrying the lease
# parameters that must NEVER appear in argv (t19 P2 / t21 §4.3). Layout (all big-endian
# lengths): repeated [tag u8][len u16 BE][value], terminated by tag 0x00 (no length/value).
TLV_NONCE = 0x01
TLV_ENDPOINT = 0x02
TLV_UID = 0x03
TLV_BOOT = 0x04
TLV_END = 0x00


def encode_stdin_tlv(nonce: bytes, endpoint: str, uid: int, boot_id: str) -> bytes:
    if len(nonce) != 32:
        raise WireError("LEASE_NONCE_INVALID")
    out = bytearray()

    def put(tag: int, value: bytes) -> None:
        if len(value) > 0xFFFF:
            raise WireError("LEASE_TLV_TOO_LONG")
        out.append(tag)
        out.extend(struct.pack(">H", len(value)))
        out.extend(value)

    put(TLV_NONCE, nonce)
    put(TLV_ENDPOINT, endpoint.encode("utf-8"))
    put(TLV_UID, struct.pack(">I", uid & 0xFFFFFFFF))
    put(TLV_BOOT, boot_id.encode("utf-8"))
    out.append(TLV_END)
    return bytes(out)


def decode_stdin_tlv(data: bytes) -> dict:
    pos = 0
    seen: dict[int, bytes] = {}
    while True:
        if pos >= len(data):
            raise WireError("LEASE_TLV_TRUNCATED")
        tag = data[pos]; pos += 1
        if tag == TLV_END:
            if pos != len(data):
                raise WireError("LEASE_TLV_TRAILING")
            break
        if pos + 2 > len(data):
            raise WireError("LEASE_TLV_TRUNCATED")
        (length,) = struct.unpack_from(">H", data, pos); pos += 2
        if pos + length > len(data):
            raise WireError("LEASE_TLV_TRUNCATED")
        if tag not in (TLV_NONCE, TLV_ENDPOINT, TLV_UID, TLV_BOOT):
            raise WireError("LEASE_TLV_UNKNOWN_TAG")
        if tag in seen:
            raise WireError("LEASE_TLV_DUPLICATE")
        seen[tag] = data[pos:pos + length]; pos += length
    for tag, token in ((TLV_NONCE, "LEASE_NONCE_INVALID"), (TLV_ENDPOINT, "LEASE_ENDPOINT_INVALID"),
                       (TLV_UID, "LEASE_UID_INVALID"), (TLV_BOOT, "LEASE_BOOT_ID_INVALID")):
        if tag not in seen:
            raise WireError(token)
    if len(seen[TLV_NONCE]) != 32:
        raise WireError("LEASE_NONCE_INVALID")
    if len(seen[TLV_UID]) != 4:
        raise WireError("LEASE_UID_INVALID")
    return {"nonce": seen[TLV_NONCE], "endpoint": seen[TLV_ENDPOINT].decode("utf-8", "replace"),
            "uid": struct.unpack(">I", seen[TLV_UID])[0],
            "boot_id": seen[TLV_BOOT].decode("utf-8", "replace")}


# --------------------------------------------------------------------------- LeaseFactory (V2)
class ReferenceLocalServerSocket:
    """N2: factory-owned listener lifecycle model (open on create, close on lease close/fail)."""

    def __init__(self, endpoint: str):
        self.endpoint = endpoint
        self.open = True
        self.accepted = 0

    def accept(self):
        if not self.open:
            raise WireError("GHOSTSAM_SERVER_CLOSED")
        self.accepted += 1
        return self

    def close(self):
        self.open = False


class GhostsamLeaseFactory:
    """MapleSU-side self-owned lease construction (does NOT call RootShellLease.prepare()).
    N2: creates and owns the LocalServerSocket(endpoint) for the lease lifetime."""

    @staticmethod
    def create(manager_uid: int, boot_id: str, provider: int = PROVIDER_GHOSTLOCK,
               endpoint: str | None = None, nonce: bytes | None = None) -> "PendingLease":
        if manager_uid < 10000:
            raise WireError("LEASE_ORDINARY_APP_UID_REQUIRED")
        if not C.boot_id(boot_id.encode()):
            raise WireError("LEASE_BOOT_ID_UNAVAILABLE")
        if provider not in (PROVIDER_GHOSTLOCK, PROVIDER_DIRTYFRAG):
            raise WireError("LEASE_PROVIDER_INVALID")
        if nonce is None:
            nonce = bytes(range(32)) if endpoint else __import__("os").urandom(32)
        if len(nonce) != 32:
            raise WireError("LEASE_NONCE_INVALID")
        if endpoint is None:
            import uuid
            endpoint = "maplesu-jb-" + str(uuid.uuid4())
        if not C.endpoint(endpoint.encode()):
            raise WireError("LEASE_ENDPOINT_INVALID")
        return PendingLease(endpoint=endpoint, nonce=nonce, nonce_hex=nonce.hex(),
                            manager_uid=manager_uid, boot_id=boot_id, provider=provider,
                            server=ReferenceLocalServerSocket(endpoint))

    @staticmethod
    def close(lease: "PendingLease") -> None:
        server = getattr(lease, "server", None)
        if server is not None:
            server.close()
        for i in range(len(lease.nonce)):
            lease.nonce = lease.nonce[:i] + b"\x00" + lease.nonce[i + 1:]


# --------------------------------------------------------------------------- result frames
def accept_frame() -> bytes:
    return b"A"


def handover_frame() -> bytes:
    return b"D"


def end_frame() -> bytes:
    return b"X"


def ready_frame(child_pid: int) -> bytes:
    if child_pid <= 1:
        raise WireError("LEASE_SHELL_PID_INVALID")
    return b"R" + _u32(child_pid)


def failure_frame(stage: str) -> bytes:
    if stage not in FAILURE_STAGES:
        raise WireError("LEASE_STAGE_INVALID")
    return bytes([ord("F"), FAILURE_STAGES[stage], 0, 0, 0])


def restore_frame(applied: int, origin: int, enforcing: int, checkreqprot: int,
                  policy: int, unload_errno: int) -> bytes:
    """'P' + 10 bytes: applied,origin,enforcing,checkreqprot,policy,unload_errno(BE u32)."""
    if applied not in (0, 1, 2, 3):
        raise WireError("LEASE_RESTORE_STATE_INVALID")
    if origin not in (0, 1, 2, 3):
        raise WireError("LEASE_RESTORE_ORIGIN_INVALID")
    if enforcing not in (0, 1, 0xFF):
        raise WireError("LEASE_RESTORE_ENFORCING_INVALID")
    if checkreqprot not in (0, 1, 2, 0xFF):
        raise WireError("LEASE_RESTORE_CHECKREQPROT_INVALID")
    if policy not in (0, 1, 2):
        raise WireError("LEASE_RESTORE_POLICY_INVALID")
    payload = bytes([applied, origin, enforcing, checkreqprot, policy]) + _u32(unload_errno & 0xFFFFFFFF)
    if len(payload) != RESTORE_FRAME_LEN - 1:
        raise WireError("LEASE_RESTORE_FRAME_INVALID")
    return b"P" + payload


def parse_restore_frame(data: bytes) -> dict:
    if len(data) != RESTORE_FRAME_LEN or data[0:1] != b"P":
        raise WireError("LEASE_RESTORE_FRAME_INVALID")
    applied, origin, enforcing, checkreqprot, policy = data[1], data[2], data[3], data[4], data[5]
    if applied not in (0, 1, 2, 3):
        raise WireError("LEASE_RESTORE_STATE_INVALID")
    if origin not in (0, 1, 2, 3):
        raise WireError("LEASE_RESTORE_ORIGIN_INVALID")
    if enforcing not in (0, 1, 0xFF):
        raise WireError("LEASE_RESTORE_ENFORCING_INVALID")
    if checkreqprot not in (0, 1, 2, 0xFF):
        raise WireError("LEASE_RESTORE_CHECKREQPROT_INVALID")
    if policy not in (0, 1, 2):
        raise WireError("LEASE_RESTORE_POLICY_INVALID")
    unload = struct.unpack(">I", data[6:10])[0]
    return {"applied": applied, "origin": origin, "enforcing": enforcing,
            "checkreqprot": checkreqprot, "policy": policy, "unload_errno": unload}


# --------------------------------------------------------------------------- primitive 'C'
def encode_c_frame(command: str) -> bytes:
    if "\x00" in command:
        raise WireError("COMMAND_NUL_INVALID")
    payload = command.encode("utf-8")
    if len(payload) > 0x7FFFFFFF:
        raise WireError("COMMAND_TOO_LONG")
    return b"C" + struct.pack("<I", len(payload)) + payload


def decode_c_frame(data: bytes) -> str:
    if len(data) < 5 or data[0:1] != b"C":
        raise WireError("COMMAND_FRAME_INVALID")
    (length,) = struct.unpack_from("<I", data, 1)
    if len(data) != 5 + length:
        raise WireError("COMMAND_FRAME_LENGTH_MISMATCH")
    return data[5:].decode("utf-8")


# --------------------------------------------------------------------------- CommandBuilder
def _reject_unsafe(value: str) -> str:
    if "\x00" in value or "\n" in value or "\r" in value:
        raise WireError("ARG_INVALID")
    if "'" in value:
        raise WireError("ARG_QUOTE_INVALID")
    return value


def build_argv(consumer_path: str, endpoint: str, nonce_hex: str, uid: int,
               boot_id: str, provider_key: str, enforce: str | None = None,
               include_nonce: bool = True) -> list[str]:
    # Validate via the authoritative contract (same rules as lease_contract.c).
    if not C.endpoint(endpoint.encode()):
        raise WireError("ARG_ENDPOINT_INVALID")
    if C.nonce(nonce_hex.encode()) is None:
        raise WireError("ARG_NONCE_INVALID")
    if C.decimal(str(uid).encode(), 10000) is None:
        raise WireError("ARG_UID_INVALID")
    if not C.boot_id(boot_id.encode()):
        raise WireError("ARG_BOOT_ID_INVALID")
    if provider_key not in ("ghostlock", "dirtyfrag"):
        raise WireError("ARG_PROVIDER_INVALID")
    argv = [_reject_unsafe(consumer_path), _reject_unsafe(endpoint)]
    if include_nonce:  # canonical (lease_contract.c) argv; V2 runtime omits it (nonce goes via stdin)
        argv.append(_reject_unsafe(nonce_hex))
    argv += [str(uid), _reject_unsafe(boot_id), provider_key]
    if enforce is not None:
        argv.append(_reject_unsafe(enforce))
    return argv


def build_command(consumer_path: str, endpoint: str, nonce_hex: str, uid: int,
                  boot_id: str, provider_key: str, enforce: str | None = None,
                  include_nonce: bool = True, fd_args: bool = False) -> str:
    if fd_args:
        # V2 contract form: all lease params go via the consumer's stdin TLV; argv only selects it.
        argv = [_reject_unsafe(consumer_path), "--fd-args"]
        if enforce is not None:
            argv.append(_reject_unsafe(enforce))
        return "exec " + " ".join("'" + a + "'" for a in argv)
    argv = build_argv(consumer_path, endpoint, nonce_hex, uid, boot_id, provider_key, enforce, include_nonce)
    return "exec " + " ".join("'" + a + "'" for a in argv)


# --------------------------------------------------------------------------- CapabilityGate
class CapabilityGate:
    ALLOWED = frozenset({"RAW_ROOT_LEASE"})
    ULTRA_FIELDS = ("ultraState", "ultraKeyPresent", "ultraKernelRootVerified", "IRootManagementService")

    @classmethod
    def declare(cls) -> frozenset:
        return cls.ALLOWED

    @classmethod
    def assert_no_ultra(cls, facts: dict) -> None:
        for name in cls.ULTRA_FIELDS:
            v = facts.get(name)
            if v is None or v is False or v in ("NONE", "ABSENT"):
                continue
            # UNKNOWN = unverified, NOT absence: keep it fail-closed with a distinct token.
            if v == "UNKNOWN":
                raise WireError("CAPABILITY_OUT_OF_SCOPE:" + name + "=UNKNOWN")
            raise WireError("CAPABILITY_OUT_OF_SCOPE:" + name)


# --------------------------------------------------------------------------- consumer (V2)
@dataclass
class PendingLease:
    endpoint: str
    nonce: bytes
    nonce_hex: str
    manager_uid: int
    boot_id: str
    provider: int
    server: object | None = None  # factory-owned ReferenceLocalServerSocket (N2)


class ConsumerV2:
    """Self-built consumer model: lease params arrive in a stdin TLV first packet (not argv)."""

    @staticmethod
    def stdin_packet(pending: PendingLease) -> bytes:
        return encode_stdin_tlv(pending.nonce, pending.endpoint, pending.manager_uid, pending.boot_id)

    @staticmethod
    def identity_frame(pending: PendingLease, pid: int, starttime: int, domain: str,
                       enforcing: int, seccomp: int, stdin_packet: bytes | None = None) -> bytes:
        packet = stdin_packet if stdin_packet is not None else ConsumerV2.stdin_packet(pending)
        tlv = decode_stdin_tlv(packet)
        if not hmac.compare_digest(tlv["nonce"], pending.nonce):
            raise WireError("LEASE_NONCE_MISMATCH")
        if tlv["endpoint"] != pending.endpoint:
            raise WireError("LEASE_ENDPOINT_INVALID")
        if tlv["uid"] != pending.manager_uid:
            raise WireError("LEASE_UID_INVALID")
        if tlv["boot_id"] != pending.boot_id:
            raise WireError("LEASE_BOOT_ID_MISMATCH")
        return encode_mjbl_v2(pending.provider, pid, 0, starttime, tlv["nonce"],
                              pending.boot_id, domain, enforcing, seccomp)


# --------------------------------------------------------------------------- LeaseBinder
class LeaseBinder:
    def __init__(self, dry: bool = True):
        self.dry = dry
        self._used = False
        self.transport_open = False
        self.nonce_zeroed = False

    def await_once(self) -> None:
        if self._used:
            raise WireError("LEASE_AWAIT_ALREADY_USED")
        self._used = True

    def open(self) -> None:
        self.transport_open = True

    def close(self) -> None:
        self.transport_open = False
        self.nonce_zeroed = True


# --------------------------------------------------------------------------- AdapterProvider
class AdapterProvider:
    """Orchestrates admission -> artifact -> lease -> handover; every failure is a named token."""

    def __init__(self, binder: LeaseBinder | None = None):
        self.binder = binder or LeaseBinder()

    def run(self, *, consumer_present: bool, consumer_digest_ok: bool,
            primitive_available: bool, pending: PendingLease | None,
            peer_uid: int, peer_pid: int, starttime: int, domain: str,
            enforcing: int, seccomp: int, facts: dict | None = None) -> dict:
        # t32: capability gate before any provisioner/binder work.
        try:
            CapabilityGate.assert_no_ultra(facts or {})
        except WireError as exc:
            return {"ok": False, "token": exc.token}
        if not consumer_present:
            return {"ok": False, "token": "CONSUMER_MISSING"}
        if not consumer_digest_ok:
            return {"ok": False, "token": "DIGEST_MISMATCH"}
        if pending is None:
            return {"ok": False, "token": "LEASE_PENDING_MISSING"}
        self.binder.open()
        try:
            if not primitive_available:
                return {"ok": False, "token": "GHOSTSAM_PRIMITIVE_DENIED"}
            self.binder.await_once()
            frame = ConsumerV2.identity_frame(pending, peer_pid, starttime, domain, enforcing, seccomp)
            identity = decode_mjbl_v2(frame, expected_nonce=pending.nonce,
                                      expected_boot_id=pending.boot_id,
                                      peer_pid=peer_pid, peer_uid=peer_uid)
            return {"ok": True, "token": "DAEMON_READY", "identity": identity,
                    "capability": sorted(CapabilityGate.declare())}
        except WireError as exc:
            return {"ok": False, "token": exc.token}
        finally:
            self.binder.close()


# --------------------------------------------------------------------------- result reader
# Design-accurate result frames: 'P' is exactly 10 bytes; 'X' and 'D' are single-byte tags
# (they carry no u32 payload in root_consumer.cpp). Strict reader rejects malformed shapes.
def parse_result_frame(data: bytes) -> dict:
    if not data:
        raise WireError("LEASE_RESULT_FRAME_INVALID")
    tag = data[0:1]
    if tag == b"P":
        return {"tag": "P", **parse_restore_frame(data)}
    if tag == b"X":
        if len(data) != 1:
            raise WireError("LEASE_RESULT_TRAILING")
        return {"tag": "X"}
    if tag == b"D":
        if len(data) != 1:
            raise WireError("LEASE_D_PAYLOAD_NONEMPTY")
        return {"tag": "D"}
    if tag == b"R":
        if len(data) != 5:
            raise WireError("LEASE_READY_FRAME_INVALID")
        (pid,) = struct.unpack(">I", data[1:5])
        if pid <= 1:
            raise WireError("LEASE_SHELL_PID_INVALID")
        return {"tag": "R", "pid": pid}
    if tag == b"F":
        if len(data) != 5 or data[1] not in FAILURE_STAGES.values():
            raise WireError("LEASE_STAGE_INVALID")
        return {"tag": "F", "stage": data[1]}
    raise WireError("LEASE_RESULT_TAG_INVALID")


# --------------------------------------------------------------------------- reference transport
class ReferenceLeaseTransport:
    """Host model of the intended LeaseTransport wiring (product side NOT wired).

    On one 'C' stream: write 'C'+LE len+command, then immediately write the stdin TLV first
    packet (GhostSam daemon dup2()s the conn to the child stdin). The App then accepts on its
    LocalServerSocket and reads the MJBL identity frame. Here the identity frame is produced by
    ConsumerV2 (self-built consumer model) and validated via decode_mjbl_v2.
    """

    def __init__(self):
        self.stream = bytearray()

    def run(self, pending: PendingLease, *, pid: int, starttime: int, domain: str,
            enforcing: int, seccomp: int) -> dict:
        server = getattr(pending, "server", None)
        if server is not None:
            server.accept()  # N2: listener is factory-owned and must be open
        cmd = build_command("/c", pending.endpoint, pending.nonce_hex, pending.manager_uid,
                            pending.boot_id, "ghostlock", include_nonce=False, fd_args=True)
        self.stream.extend(encode_c_frame(cmd))
        self.stream.extend(ConsumerV2.stdin_packet(pending))
        frame = ConsumerV2.identity_frame(pending, pid, starttime, domain, enforcing, seccomp)
        return decode_mjbl_v2(frame, expected_nonce=pending.nonce, expected_boot_id=pending.boot_id,
                              peer_pid=pid, peer_uid=0, expected_starttime=starttime)


# --------------------------------------------------------------------------- admission mirror
class GhostsamAdmission:
    """Host mirror of GhostsamBackend.admissionBlockers + registration invariants."""

    KEY = "ghostsam"
    ARTIFACT = "libmaplesu_ghostsam_consumer.so"
    CAPABILITIES = frozenset({"RAW_ROOT_LEASE"})

    @staticmethod
    def blockers(*, owner_only: bool = True, arm64: bool = True, artifact_present: bool = True,
                 primitive_available: bool = True, capability: str = "RAW_ROOT_LEASE") -> list[str]:
        out: list[str] = []
        if not owner_only:
            out.append("PROVIDER_OWNER_ONLY")
        if not arm64:
            out.append("PROVIDER_ABI_UNSUPPORTED")
        if not artifact_present:
            out.append("ARTIFACT_UNVERIFIED")
        if not primitive_available:
            out.append("GHOSTSAM_PRIMITIVE_DENIED")
        if capability not in GhostsamAdmission.CAPABILITIES:
            out.append("CAPABILITY_OUT_OF_SCOPE:" + capability)
        return out
