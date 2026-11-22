"""Pair frozen production SDK C++ transport with actual target A64 patch bytes.

No SDK archive, APK, emitter rebuild, device access or partition write is performed.
Only nofault functions and preparation/saved-ID reads are captured host stubs.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import time

from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn import arm64_const as R

ROOT = Path(__file__).resolve().parents[2]
IMAGE = "sha256:272ada1e61c525116032246df2a790d1ccec1804b7a9e0b09203c5e650dcb78e"
MASK = (1 << 64) - 1


def identity(path):
    data = path.read_bytes()
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def branch_target(at, word):
    immediate = word & 0x3ffffff
    return at + (immediate - (0x4000000 if immediate & 0x2000000 else 0)) * 4


class Fixture:
    def __init__(self, directory):
        self.directory = directory
        publication = json.loads((directory / "UPSTREAM-PUBLICATION.json").read_bytes())
        published = {entry["path"]: entry for entry in publication["files"]}
        for local, upstream in {
            "host-receipt.json": "matrix/android15-6.6-ddd760da/host-receipt.json",
            "patch.spec": "matrix/android15-6.6-ddd760da/patch.spec",
            "emitted.txt": "green-replay/emitted.txt",
        }.items():
            assert identity(directory / local)["sha256"] == published[upstream]["sha256"]
        receipt = json.loads((directory / "host-receipt.json").read_bytes())
        records = {row["role"]: row for row in receipt["records"]}
        replacements = {}
        for line in (directory / "patch.spec").read_text().splitlines():
            if line and not line.startswith("#"):
                at, before, after = line.split("|")
                replacements[int(at)] = bytes.fromhex(after)
        self.bodies = {}
        for role, source in {"gate": "die+0x0", "frame": "arm64_notify_die+0x0", "request": "request-v2"}.items():
            at = records[source]["offset"]
            self.bodies[role] = (at, replacements[at])
        at, code = self.bodies["request"]
        calls = [branch_target(at + i, word) for i in range(0, 272, 4)
                 for word in [int.from_bytes(code[i:i + 4], "little")]
                 if word & 0xfc000000 == 0x94000000]
        assert len(calls) == 3 and calls[1] == calls[2] and calls[0] != calls[1]
        self.copy_from, self.copy_to = calls[:2]
        frame_at, frame = self.bodies["frame"]
        self.continuation = branch_target(frame_at + 24, int.from_bytes(frame[24:28], "little"))
        assert self.continuation == records["do_execveat_common+0x0"]["offset"] + 4
        prologue = int.from_bytes(frame[20:24], "little")
        assert prologue & 0xffc003ff == 0xd10003ff
        self.stack_delta = (prologue >> 10) & 0xfff
        self.panic = records["panic+0x0"]["offset"]
        self.key = replacements[self.panic]
        assert len(self.key) == 48 and 0 not in self.key
        self.metadata = records["free_initmem+0x0"]["offset"] + 4
        fields = receipt["layout"]["fields"]
        self.cred_offset = fields["task_struct.cred"]["offsetBytes"]
        self.suid = fields["cred.suid"]["offsetBytes"]
        self.euid = fields["cred.euid"]["offsetBytes"]
        self.base_sha256 = receipt["baseKernelSha256"]

    def replay(self, transport, slide):
        case = transport["case"]
        packet, request, response = [bytes.fromhex(transport[key]) for key in ("packet", "request", "response")]
        frame = bytes((packet[48 + i] + packet[66 + i]) & 255 for i in range(18))
        assert frame.hex() == transport["frame"] and len(packet) == 85 and len(request) == len(response) == 48
        request_pointer, response_pointer = transport["requestPointer"], transport["responsePointer"]
        assert struct.unpack_from("<Q", frame, 10)[0] == request_pointer
        fields = struct.unpack("<IHHIIQQQQ", request)
        assert fields[:5] == (0x3251534d, 2, 48, fields[3], 0) and fields[6] == response_pointer
        assert request_pointer >> 32 and response_pointer >> 32 and not any(response)
        original_request = request
        injected = None
        edits = {"bad_magic": (0, b"\0" * 4), "bad_version": (4, b"\1\0"),
                 "bad_length": (6, b"\x2f\0"), "bad_reserved": (12, b"\1\0\0\0")}
        if case in edits:
            offset, value = edits[case]
            changed = bytearray(request); changed[offset:offset + len(value)] = value
            request = bytes(changed); injected = f"request bytes {offset}:{offset + len(value)}"
        if case == "bad_key":
            packet = bytes([packet[0] ^ 1]) + packet[1:]; injected = "authentication byte 0"

        u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        image_end = max([self.copy_from, self.copy_to, self.continuation, self.panic + 48] +
                        [at + len(code) for at, code in self.bodies.values()])
        u.mem_map(slide, (image_end + 0xfff) & ~0xfff)
        u.mem_map(0x30000000, 0x40000)
        pages = set()
        for pointer in (request_pointer, response_pointer):
            for page in range(pointer & ~0xfff, (pointer + 47 & ~0xfff) + 4096, 4096):
                if page not in pages: u.mem_map(page, 4096); pages.add(page)
        task, cred, filename, name, stack = 0x30001000, 0x30002000, 0x30003000, 0x30004000, 0x30030000
        body_stack = stack - 80 - 112
        u.mem_write(request_pointer, request); u.mem_write(response_pointer, response)
        u.mem_write(name, packet); u.mem_write(filename, struct.pack("<Q", name))
        u.mem_write(task + self.cred_offset, struct.pack("<Q", cred))
        u.mem_write(cred, b"\x56" * 128)
        saved = struct.unpack_from("<Q", frame, 2)[0]
        u.mem_write(cred + self.suid, struct.pack("<Q", saved))
        u.mem_write(cred + self.euid, struct.pack("<I", 10000))
        initial_cred = bytes(u.mem_read(cred, 128))
        for at, code in self.bodies.values(): u.mem_write(slide + at, code)
        u.mem_write(slide + self.panic, self.key)
        initial = [0x1234567800000000 + i for i in range(31)]
        initial[1] = filename
        for i, value in enumerate(initial): u.reg_write(getattr(R, f"UC_ARM64_REG_X{i}"), value)
        u.reg_write(R.UC_ARM64_REG_SP, stack); u.reg_write(R.UC_ARM64_REG_SP_EL0, task)
        calls, cred_writes, completion_events, request_snapshots = [], [], [], []

        def x(index): return u.reg_read(getattr(R, f"UC_ARM64_REG_X{index}"))

        def writes(uc, access, address, size, value, unused):
            if cred <= address < cred + 128: cred_writes.append([address - cred, size])

        target = slide + self.continuation

        def execute(uc, pc, size, unused):
            if pc == target: uc.emu_stop(); return
            if pc not in (slide + self.copy_from, slide + self.copy_to): return
            assert u.reg_read(R.UC_ARM64_REG_SP) % 16 == 0
            link, destination, source, count = x(30), x(0), x(1), x(2)
            direction = "from" if pc == slide + self.copy_from else "to"
            calls.append(dict(direction=direction, destination=destination, source=source, bytes=count))
            outcome = 0
            if direction == "from":
                assert source == request_pointer and count == 48
                assert body_stack <= destination and destination + count <= body_stack + 112
                if case in ("from_error", "query_from_error"): outcome = -14
                else:
                    snapshot = bytes(u.mem_read(source, count)); request_snapshots.append(snapshot.hex())
                    u.mem_write(destination, snapshot)
                    if case == "request_snapshot": u.mem_write(request_pointer, b"\xee" * 48)
            else:
                assert destination == response_pointer and count in (48, 4)
                assert body_stack <= source and source + count <= body_stack + 112
                completion_events.append(bytes(u.mem_read(response_pointer, 48)).hex())
                assert int.from_bytes(u.mem_read(response_pointer, 4), "little") == 0
                if count == 48 and case in ("to_error", "partial_to"):
                    if case == "partial_to": u.mem_write(destination, bytes(u.mem_read(source, 17)))
                    outcome = -14
                elif count == 4 and case == "completion_error": outcome = -14
                else: u.mem_write(destination, bytes(u.mem_read(source, count)))
            for i in range(18): u.reg_write(getattr(R, f"UC_ARM64_REG_X{i}"), 0xbad00000 + i)
            u.reg_write(R.UC_ARM64_REG_X0, outcome & MASK); u.reg_write(R.UC_ARM64_REG_PC, link)

        u.hook_add(UC_HOOK_CODE, execute); u.hook_add(UC_HOOK_MEM_WRITE, writes)
        u.emu_start(slide + self.bodies["frame"][0] + 28, target + 4, count=20000)
        assert u.reg_read(R.UC_ARM64_REG_PC) == target
        assert u.reg_read(R.UC_ARM64_REG_SP) == stack - self.stack_delta
        assert all(x(i) == initial[i] for i in [*range(8), *range(18, 31)])
        assert not cred_writes and bytes(u.mem_read(cred, 128)) == initial_cred
        received = bytes(u.mem_read(response_pointer, 48))
        counts = [(row["direction"], row["bytes"]) for row in calls]
        if case == "bad_key": assert not calls and not any(received)
        elif case in ("from_error", "query_from_error"): assert counts == [("from", 48)] and not any(received)
        elif case in ("to_error", "partial_to"):
            assert counts == [("from", 48), ("to", 48)] and not any(received[:4])
        else:
            assert counts == [("from", 48), ("to", 48), ("to", 4)]
            values = struct.unpack("<IHHIiQQQII", received)
            expected_status = -22 if case in edits else (-95 if fields[3] == 99 else 0)
            assert values[:6] == (0 if case == "completion_error" else 0x3252534d, 2, 48, fields[3], expected_status, fields[5])
            assert values[6] == (0 if expected_status else (3 if fields[3] == 1 else fields[7]))
            if not expected_status and fields[3] == 1:
                assert values[8:] == (48, 2)
                metadata = struct.unpack("<IHHQqqqII", u.mem_read(values[7], 48))
                assert metadata[:4] == (0x324d534d, 2, 48, 3)
                assert values[7] + metadata[4] == slide
                assert values[7] + metadata[5] == slide + self.metadata
                assert metadata[6:] == (0, 0, 0)
            else: assert values[7:] == (0, 0, 0)
        delivered = bytearray(received)
        if case in ("response_id", "response_command", "query_bad_metadata"):
            offset = {"response_id": 16, "response_command": 8, "query_bad_metadata": 32}[case]
            delivered[offset] ^= 1
            if case == "query_bad_metadata": delivered[32:40] = bytes(8)
            injected = f"response bytes at {offset} after emitter completion"
        if case in ("from_error", "query_from_error", "to_error", "partial_to", "completion_error"):
            injected = "captured nofault failure"
        if case == "request_snapshot": injected = "user request changed after complete nofault snapshot"
        return dict(case=case, slide=slide, source="actual target patch.spec", packet=packet.hex(),
                    requestOriginal=original_request.hex(), requestInjected=request.hex(),
                    requestSnapshots=request_snapshots, emitterResponse=received.hex(), deliveredResponse=delivered.hex(),
                    calls=calls, credentialWrites=cred_writes, completionEvents=completion_events,
                    injection=injected, abiPreserved=True, stackAligned=True), bytes(delivered)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    evidence = args.evidence.resolve()
    source = evidence / "source"
    baseline = json.loads((evidence / "INPUTS.json").read_text(encoding="utf-8-sig"))
    for row in baseline: assert identity(source / row["path"])["sha256"] == row["sha256"]
    fixture = Fixture(evidence / "fixture")
    build = evidence / "build"; build.mkdir(exist_ok=True)
    tests = evidence / "tests"; tests.mkdir(exist_ok=True)
    test = ROOT / "runtime/maplesu-sdk/sdk/tools/tests/kernel_request_key/test_pairing.cpp"
    shutil.copyfile(test, tests / test.name)
    shutil.copyfile(Path(__file__), tests / Path(__file__).name)
    (build / "kernel_module_kit_umbrella.h").write_text('#pragma once\n#include "module_err_def.h"\n')
    (build / "module_base_kernel_mem.h").write_text('#pragma once\nnamespace kernel_module { uint32_t get_page_size(); }\n')
    prefix = "/work/source/runtime/maplesu-sdk/"
    docker = ["docker", "run", "--rm", "--pull", "never", "--network", "none", "--read-only",
              "--tmpfs", "/tmp:rw,size=16m", "--mount", f"type=bind,source={evidence},target=/work",
              "-w", "/work/build", IMAGE]
    command = [*docker, "g++", "-std=c++20", "-O1", "-I/work/build", "-I" + prefix + "sdk/include",
               "-I" + prefix + "include", "/work/tests/test_pairing.cpp",
               prefix + "sdk/src/kernel_request/module_base_kernel_request.cpp",
               prefix + "sdk/src/module/module_current_identity.cpp",
               "-Wl,--wrap=syscall,--wrap=getresuid,--wrap=getresgid", "-o", "pairing-test"]
    started = datetime.now(timezone.utc).isoformat()
    free_before = {drive: shutil.disk_usage(drive).free for drive in ("C:/", "D:/")}
    compile_result = subprocess.run(command, capture_output=True, text=True, timeout=60)
    (evidence / "compile.log").write_text(compile_result.stdout + compile_result.stderr, encoding="utf-8")
    assert compile_result.returncode == 0, compile_result.stderr
    minimum_free = {drive: min(value, shutil.disk_usage(drive).free) for drive, value in free_before.items()}
    results, transports, simulations, summaries = [], [], [], []
    started_test = time.monotonic()
    for slide in (0, 0x40000000):
        process = subprocess.Popen([*docker[:2], "-i", *docker[2:], "./pairing-test"],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, encoding="utf-8")
        process.stdin.write(fixture.key.hex() + "\n"); process.stdin.flush()
        try:
            for line in process.stdout:
                row = json.loads(line)
                row["slide"] = slide
                if row["type"] == "transport":
                    transports.append(row)
                    simulation, answer = fixture.replay(row, slide)
                    simulations.append(simulation)
                    process.stdin.write(answer.hex() + "\n"); process.stdin.flush()
                elif row["type"] == "result": results.append(row); assert row["passed"], row
                elif row["type"] == "summary": summaries.append(row)
                for drive in minimum_free: minimum_free[drive] = min(minimum_free[drive], shutil.disk_usage(drive).free)
            process.stdin.close()
            code = process.wait(timeout=15)
            stderr = process.stderr.read()
            assert code == 0, stderr
        except BaseException:
            process.kill(); process.wait(timeout=15)
            raise
    for name, rows in (("transports.jsonl", transports), ("simulations.jsonl", simulations),
                       ("client-results.jsonl", results)):
        (evidence / name).write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    for row in baseline: assert identity(source / row["path"])["sha256"] == row["sha256"]
    assert len(summaries) == 2 and all(row["failures"] == 0 and row["uniqueRequestIds"] == row["cases"] for row in summaries)
    receipt = dict(schema="maplesu-client-emitter-pairing/1", recordedAt=started, passed=True,
                   image=IMAGE, compile=dict(argv=command, exit=compile_result.returncode),
                   testSeconds=round(time.monotonic() - started_test, 3), summaries=summaries,
                   pairedCases=len(results), fixtureKernelSha256=fixture.base_sha256,
                   instructionDerivedOffsets=dict(copy_from_user_nofault=fixture.copy_from,
                       copy_to_user_nofault=fixture.copy_to, originalContinuation=fixture.continuation),
                   sourceFreezeVerified=True, deviceAccess=False, partitionWrites=False,
                   fullSdkBuild=False, apkBuild=False, productionConsumerSwitched=False,
                   space=dict(freeBefore=free_before, minimumSampledFree=minimum_free,
                              evidenceBytes=sum(path.stat().st_size for path in evidence.rglob("*") if path.is_file())),
                   boundaries=["Host C++ ABI compiles production client from frozen source, not Android SDK archive.",
                       "Actual target A64 instructions execute in Unicorn; no live kernel or device execution.",
                       "copy_from/to_user_nofault, preparation and saved-ID reads are captured stubs.",
                       "Fault injection is explicitly recorded; baseline frames and pointers originate in the actual SDK client.",
                       "Only the fixture patch/receipt provenance is rechecked; full Image is not reread or rebuilt."])
    (evidence / "RECEIPT.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(dict(passed=True, pairedCases=len(results), summaries=summaries, space=receipt["space"])))


if __name__ == "__main__": main()
