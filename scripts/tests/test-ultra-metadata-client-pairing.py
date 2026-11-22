"""Pair frozen production metadata consumers, actual client and target A64 emitter bytes."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys

from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn import arm64_const as R

ROOT = Path(__file__).resolve().parents[2]
SLIDE = 0xffff000040000000
MASK = (1 << 64) - 1


def identity(path):
    raw = path.read_bytes()
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


class Target:
    def __init__(self, work, fixture):
        helper = work / "source/scripts/tests/test-ultra-client-read-pairing.py"
        spec = importlib.util.spec_from_file_location("frozen_read_pairing", helper)
        module = importlib.util.module_from_spec(spec)
        previous_bytecode = sys.dont_write_bytecode
        try:
            sys.dont_write_bytecode = True
            spec.loader.exec_module(module)
        finally:
            sys.dont_write_bytecode = previous_bytecode
        self.base = module.Emulator(fixture)
        self.execution = json.loads((fixture / "execution.json").read_bytes())
        for name, key in (("patch.spec", "spec"), ("host-receipt.json", "receipt")):
            assert identity(fixture / name)["sha256"] == self.execution[key]["sha256"]
        self.image_path = Path(self.execution["kernel"]["path"])
        self.image_identity = identity(self.image_path)
        assert self.image_identity["sha256"] == self.execution["kernel"]["sha256"]
        raw = self.image_path.read_bytes()
        patched = bytearray(raw)
        self.rows = []
        for line in (fixture / "patch.spec").read_text().splitlines():
            if not line or line.startswith("#"):
                continue
            at, before, after = line.split("|")
            at = int(at)
            before, after = bytes.fromhex(before), bytes.fromhex(after)
            assert len(before) == len(after) and raw[at:at + len(before)] == before
            patched[at:at + len(after)] = after
            self.rows.append((at, after))
        self.patched_sha256 = hashlib.sha256(patched).hexdigest()
        assert self.patched_sha256 == self.base.receipt["patchedKernelSha256"]
        self.patched = bytes(patched)
        at, code = self.base.bodies["request"]
        marker = bytes.fromhex("4d534d32")
        index = code.index(marker)
        assert code.count(marker) == 1
        self.metadata_offset = at + index
        self.metadata = self.patched[self.metadata_offset:self.metadata_offset + 48]
        fields = struct.unpack("<IHHQqqqII", self.metadata)
        assert fields[:4] == (0x324d534d, 2, 48, 7)
        assert self.metadata_offset + fields[4] == 0
        self.append_offset = self.metadata_offset + fields[5]
        publishing = [(a, data) for a, data in self.rows if a <= self.append_offset < a + len(data)]
        assert len(publishing) == 1
        self.published_append_bytes = publishing[0][0] + len(publishing[0][1]) - self.append_offset
        recipe_path = work / "source/manager/src/main/java/dev/maplesu/manager/ultrakernel/UltraKernelRecipeK22.kt"
        expected_recipe = next(row["sha256"] for row in self.execution["sources"]
                               if row["path"].replace("\\", "/").endswith("/UltraKernelRecipeK22.kt"))
        assert identity(recipe_path)["sha256"] == expected_recipe
        recipe = json.loads(recipe_path.read_text(encoding="utf-8").split('"""')[1])
        records = recipe["records"]
        producer_record = next(row for row in records if row["role"] == "free_initmem+0x0")
        self.recipe_append_bytes = producer_record["length"] - 4
        assert self.published_append_bytes == self.recipe_append_bytes == 54
        self.append = self.patched[self.append_offset:self.append_offset + self.published_append_bytes]
        protocol = (work / "source/runtime/ultra/authorization/request_protocol.h").read_text()
        contract = re.search(r"^#define MAPLESU_LEGACY_METADATA_V2_BYTES (\d+)u$", protocol, re.M)
        self.shared_append_bytes = int(contract.group(1)) if contract else None
        if self.shared_append_bytes is not None:
            assert self.shared_append_bytes == self.recipe_append_bytes
        self.ordinary_offset = 0x1000
        self.ordinary = self.patched[self.ordinary_offset:self.ordinary_offset + 600]

    def replay(self, row):
        request, response, packet = [bytes.fromhex(row[name]) for name in ("request", "response", "packet")]
        fields = struct.unpack("<IHHIIQQQQ", request)
        command, request_id, response_pointer, arg0, arg1 = fields[3], fields[5], fields[6], fields[7], fields[8]
        request_pointer = row["requestPointer"]
        frame = bytes((packet[48 + i] + packet[66 + i]) & 255 for i in range(18))
        assert frame.hex() == row["frame"] and struct.unpack_from("<Q", frame, 10)[0] == request_pointer
        assert command in (1, 3) and response_pointer == row["responsePointer"] and not any(response)
        read, destination = bytes.fromhex(row["readArgs"]), bytes.fromhex(row["destination"])
        output = count = None
        if command == 3:
            output, count, reserved = struct.unpack("<QII", read)
            assert len(read) == 16 and len(destination) == count and reserved == 0 and 1 <= count <= 256
            assert min(request_pointer, response_pointer, arg1, output) > 0xffffffff
            assert SLIDE <= arg0 <= SLIDE + len(self.patched) - count
        u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        u.mem_map(SLIDE, (len(self.patched) + 4095) & ~4095)
        # Preserve actual producer bytes and requested image spans, without a second large file.
        for at, code in self.base.bodies.values():
            u.mem_write(SLIDE + at, self.patched[at:at + len(code)])
        u.mem_write(SLIDE + self.base.panic, self.base.key)
        if command == 3:
            at = arg0 - SLIDE
            u.mem_write(arg0, self.patched[at:at + count])
        u.mem_map(0x30000000, 0x40000)
        pages = set()

        def put(pointer, data):
            for page in range(pointer & ~4095, ((pointer + len(data) - 1) & ~4095) + 4096, 4096):
                if page not in pages:
                    u.mem_map(page, 4096)
                    pages.add(page)
            u.mem_write(pointer, data)

        put(request_pointer, request)
        put(response_pointer, response)
        if command == 3:
            put(arg1, read)
            put(output, destination)
        task, cred, filename, name, stack = 0x30001000, 0x30002000, 0x30003000, 0x30004000, 0x30030000
        body_stack = stack - 80 - 384
        u.mem_write(name, packet)
        u.mem_write(filename, struct.pack("<Q", name))
        u.mem_write(task + self.base.cred, struct.pack("<Q", cred))
        u.mem_write(cred, b"\x56" * 128)
        u.mem_write(cred + self.base.suid, frame[2:10])
        u.mem_write(cred + self.base.euid, struct.pack("<I", 10000))
        initial_cred = bytes(u.mem_read(cred, 128))
        initial = [0x1234567800000000 + i for i in range(31)]
        initial[1] = filename
        for i, value in enumerate(initial):
            u.reg_write(getattr(R, f"UC_ARM64_REG_X{i}"), value)
        u.reg_write(R.UC_ARM64_REG_SP, stack)
        u.reg_write(R.UC_ARM64_REG_SP_EL0, task)
        calls, credential_writes, completion = [], [], []

        def x(i):
            return u.reg_read(getattr(R, f"UC_ARM64_REG_X{i}"))

        def writes(uc, access, address, size, value, unused):
            if cred <= address < cred + 128:
                credential_writes.append([address - cred, size])

        def execute(uc, pc, size, unused):
            if pc == SLIDE + self.base.target:
                uc.emu_stop()
                return
            functions = {SLIDE + self.base.from_user: "from", SLIDE + self.base.from_kernel: "kernel",
                         SLIDE + self.base.to_user: "to"}
            if pc not in functions:
                return
            assert u.reg_read(R.UC_ARM64_REG_SP) % 16 == 0
            target, source, length, link = x(0), x(1), x(2), x(30)
            direction = functions[pc]
            calls.append(dict(direction=direction, destination=target, source=source, bytes=length))
            outcome = 0
            if direction == "from":
                assert (source, length) in ((request_pointer, 48), (arg1, 16))
                assert body_stack <= target and target + length <= body_stack + 384
                u.mem_write(target, bytes(u.mem_read(source, length)))
            elif direction == "kernel":
                assert target == body_stack + 128 and source == arg0 and length == count
                if row["phase"] == "kernel_fault":
                    outcome = -14
                else:
                    u.mem_write(target, bytes(u.mem_read(source, length)))
            else:
                assert body_stack <= source and source + length <= body_stack + 384
                if source == body_stack + 128:
                    assert target == output and length == count
                    if row["phase"] == "partial_data":
                        u.mem_write(target, bytes(u.mem_read(source, 17)))
                        outcome = -14
                    else:
                        u.mem_write(target, bytes(u.mem_read(source, length)))
                else:
                    assert target == response_pointer and length in (48, 4)
                    completion.append(bytes(u.mem_read(response_pointer, 48)).hex())
                    assert not any(u.mem_read(response_pointer, 4))
                    u.mem_write(target, bytes(u.mem_read(source, length)))
            for i in range(18):
                u.reg_write(getattr(R, f"UC_ARM64_REG_X{i}"), 0xbad00000 + i)
            u.reg_write(R.UC_ARM64_REG_X0, outcome & MASK)
            u.reg_write(R.UC_ARM64_REG_PC, link)

        u.hook_add(UC_HOOK_CODE, execute)
        u.hook_add(UC_HOOK_MEM_WRITE, writes)
        u.emu_start(SLIDE + self.base.bodies["frame"][0] + 28, SLIDE + self.base.target + 4, count=20000)
        assert u.reg_read(R.UC_ARM64_REG_PC) == SLIDE + self.base.target
        assert u.reg_read(R.UC_ARM64_REG_SP) == stack - self.base.stack_delta
        assert all(x(i) == initial[i] for i in [*range(8), *range(18, 31)])
        assert not credential_writes and bytes(u.mem_read(cred, 128)) == initial_cred
        actual_response = bytes(u.mem_read(response_pointer, 48))
        values = struct.unpack("<IHHIiQQQII", actual_response)
        expected_status = -14 if row["phase"] in ("kernel_fault", "partial_data") else 0
        assert values[:6] == (0x3252534d, 2, 48, command, expected_status, request_id)
        if command == 1:
            assert values[6:] == (7, SLIDE + self.metadata_offset, 48, 2)
            returned = bytes(u.mem_read(values[7], 48))
            assert returned == self.metadata
        else:
            assert values[6] == (0 if expected_status else count) and values[7:] == (0, 0, 0)
            returned = bytes(u.mem_read(output, count))
            if not expected_status:
                assert returned == self.patched[arg0 - SLIDE:arg0 - SLIDE + count]
        return dict(phase=row["phase"], command=command, requestId=request_id, source=arg0,
                    response=actual_response.hex(), data=returned.hex(), calls=calls,
                    completionEvents=completion, credentialWrites=credential_writes, abiPreserved=True), actual_response, returned


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True, help="Dedicated C: freeze/build directory")
    parser.add_argument("--fixture", type=Path, required=True)
    args = parser.parse_args()
    work, fixture = args.work.resolve(), args.fixture.resolve()
    freeze = json.loads((work / "FREEZE.json").read_bytes())
    for row in freeze["sources"]:
        assert identity(work / "source" / row["path"])["sha256"] == row["sha256"]
    tests, build = work / "tests", work / "build"
    tests.mkdir(exist_ok=True)
    build.mkdir(exist_ok=True)
    test = ROOT / "runtime/maplesu-sdk/sdk/tools/tests/request_metadata/test_pairing.cpp"
    shutil.copyfile(test, tests / test.name)
    shutil.copyfile(Path(__file__), tests / Path(__file__).name)
    seams = work / "source/runtime/maplesu-sdk/sdk/tools/tests/request_metadata"
    for source in seams.glob("*.h"):
        if source.name not in ("module_base_kernel_request.h", "unistd.h"):
            shutil.copyfile(source, build / source.name)
    local_fixture = work / "fixture"
    local_fixture.mkdir(exist_ok=True)
    for name in ("patch.spec", "host-receipt.json", "execution.json"):
        shutil.copyfile(fixture / name, local_fixture / name)
    target = Target(work, local_fixture)
    image = "sha256:272ada1e61c525116032246df2a790d1ccec1804b7a9e0b09203c5e650dcb78e"
    docker = ["docker", "run", "--rm", "--pull", "never", "--network", "none", "--read-only", "--tmpfs",
              "/tmp:rw,size=32m", "--mount", f"type=bind,source={work},target=/work", "-w", "/work/build", image]
    prefix = "/work/source/"
    tus = ["runtime/ultra/authorization/kernel_read.cpp",
           "runtime/maplesu-sdk/sdk/src/kernel_mem/module_base_kernel_mem.cpp",
           "runtime/maplesu-sdk/sdk/src/module/module_append_package_parser.cpp",
           "runtime/maplesu-sdk/sdk/src/kernel_request/module_base_kernel_request.cpp",
           "runtime/maplesu-sdk/sdk/src/module/module_current_identity.cpp"]
    wrappers = ["syscall", "getresuid", "getresgid",
                "_ZN13kernel_module26maplesu_request_v2_channelER19maplesu_response_v2Rb",
                "_ZN13kernel_module23maplesu_request_v2_readEmPvj"]
    compile_command = [*docker, "g++", "-std=c++20", "-O1", "-ffunction-sections", "-fdata-sections",
                       "-DMAPLESU_KERNEL_READ_CANONICAL", "-I/work/build",
                       "-I" + prefix + "runtime/maplesu-sdk/sdk/include",
                       "-I" + prefix + "runtime/maplesu-sdk/include",
                       "-I" + prefix + "runtime/ultra/authorization", "/work/tests/test_pairing.cpp",
                       *[prefix + path for path in tus], "-Wl,--gc-sections," + ",".join("--wrap=" + w for w in wrappers),
                       "-o", "metadata-client-pairing"]
    free_before = {drive: shutil.disk_usage(drive).free for drive in ("C:/", "D:/")}
    compiled = subprocess.run(compile_command, capture_output=True, text=True, timeout=60)
    (work / "compile.log").write_text(compiled.stdout + compiled.stderr)
    assert compiled.returncode == 0, compiled.stderr
    process = subprocess.Popen([*docker[:2], "-i", *docker[2:], "./metadata-client-pairing"], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8")
    initial = [target.base.key.hex(), f"{SLIDE} {SLIDE + target.append_offset} {SLIDE + target.ordinary_offset} "
               f"{target.published_append_bytes}", target.append.hex(), target.ordinary.hex()]
    process.stdin.write("\n".join(initial) + "\n")
    process.stdin.flush()
    rows, simulations = [], []
    try:
        for line in process.stdout:
            row = json.loads(line)
            rows.append(row)
            if row["type"] == "transport":
                simulation, response, data = target.replay(row)
                simulations.append(simulation)
                process.stdin.write(response.hex() + " " + data.hex() + "\n")
                process.stdin.flush()
        process.stdin.close()
        exit_code = process.wait(timeout=15)
        stderr = process.stderr.read()
    except BaseException:
        process.kill()
        process.wait(timeout=15)
        raise
    for name, values in (("client.jsonl", rows), ("simulations.jsonl", simulations)):
        (work / name).write_text("".join(json.dumps(row) + "\n" for row in values))
    (work / "run.stderr.log").write_text(stderr)
    stable = all(identity(work / "source" / row["path"])["sha256"] == row["sha256"] for row in freeze["sources"])
    summary = next((row for row in rows if row["type"] == "summary"), None)
    assert summary and len(simulations) == summary["transports"] and len({row["requestId"] for row in simulations}) == len(simulations)
    assert simulations[0]["command"] == 1 and all(row["command"] == 3 for row in simulations[1:])
    receipt = dict(schema="maplesu-metadata-client-pairing/1", recordedAt=datetime.now(timezone.utc).isoformat(),
                   passed=exit_code == 0 and summary["failures"] == 0 and stable and
                       target.shared_append_bytes == target.recipe_append_bytes, image=image,
                   compile=dict(argv=compile_command, exit=compiled.returncode), testExit=exit_code,
                   sourceFreezeVerified=stable, freeze=identity(work / "FREEZE.json"), summary=summary,
                   testSources={p.name: identity(p) for p in tests.iterdir()}, kernel=dict(path=str(target.image_path),
                       **target.image_identity), patchedKernelSha256=target.patched_sha256,
                   kernelSlide=SLIDE, metadataOffset=target.metadata_offset, metadataBytes=target.metadata.hex(),
                   appendOffset=target.append_offset, appendPublishedBytes=target.published_append_bytes,
                   appendRequiredBytes=58, appendObservedBytes=target.append.hex(), ordinaryOffset=target.ordinary_offset,
                   recipeAppendBytes=target.recipe_append_bytes, sharedAppendBytes=target.shared_append_bytes,
                   missingFieldImplemented=False,
                   fullSdkBuild=False, apkBuild=False, deviceAccess=False, partitionWrites=False,
                   space=dict(freeBefore=free_before, freeAfter={d: shutil.disk_usage(d).free for d in free_before}),
                   boundaries=["Five actual frozen production C++ TUs are host-compiled; Android archive is not rebuilt.",
                       "Actual target A64 bytes execute in Unicorn; nofault functions, prepare and ID syscalls are captured boundaries.",
                       "Append and ordinary READ bytes come from the actual Image after exact spec overlay; raw Image is not copied.",
                       "Actual syscall wrapper counts every QUERY/READ; prepare boundary counts actual client calls, including cold and warm.",
                       "External channel/read wrappers preserve real client bodies; intra-TU channel calls may bypass these external counters.",
                       "Legacy asm/symbol/executor seams are inert counters required to link unselected legacy code.",
                       "m073 runtime, real fork, hardware page faults, Root, authorization and devices are outside this test."])
    (work / "RECEIPT.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(dict(passed=receipt["passed"], summary=summary,
                         appendPublished=target.published_append_bytes, evidence=str(work))))
    raise SystemExit(0 if receipt["passed"] else 1)


if __name__ == "__main__":
    main()
