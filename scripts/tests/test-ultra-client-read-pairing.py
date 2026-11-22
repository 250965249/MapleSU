"""Pair the frozen actual SDK QUERY/READ client with actual target A64 bytes."""
from datetime import datetime, timezone
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess

from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn import arm64_const as R

ROOT=Path(__file__).resolve().parents[2]
IMAGE="sha256:272ada1e61c525116032246df2a790d1ccec1804b7a9e0b09203c5e650dcb78e"
SLIDE=0xffff000040000000
MASK=(1<<64)-1


def ident(path):
    return dict(bytes=path.stat().st_size,sha256=hashlib.sha256(path.read_bytes()).hexdigest())


def branch(at, word):
    immediate=word&0x3ffffff
    return at+(immediate-(0x4000000 if immediate&0x2000000 else 0))*4


class Emulator:
    def __init__(self,fixture):
        receipt=json.loads((fixture/"host-receipt.json").read_bytes())
        self.receipt=receipt
        records={row["role"]:row for row in receipt["records"]}
        self.bodies={}
        rows={}
        for line in (fixture/"patch.spec").read_text().splitlines():
            if line and not line.startswith("#"):
                at,before,after=line.split("|"); rows[int(at)]=bytes.fromhex(after)
        for role,record in {"gate":"die+0x0","frame":"arm64_notify_die+0x0","request":"request-v2"}.items():
            at=records[record]["offset"]; self.bodies[role]=(at,rows[at])
        self.panic=records["panic+0x0"]["offset"]; self.key=rows[self.panic]
        assert len(self.key)==48 and len(self.bodies["request"][1])==544
        at,code=self.bodies["request"]
        calls=[branch(at+i,word) for i in range(0,len(code)-48,4)
               for word in [int.from_bytes(code[i:i+4],"little")] if word&0xfc000000==0x94000000]
        assert len(calls)==6 and calls[0]==calls[1] and calls[3]==calls[4]==calls[5]
        self.from_user,self.from_kernel,self.to_user=calls[0],calls[2],calls[3]
        at,code=self.bodies["frame"]
        self.target=branch(at+24,int.from_bytes(code[24:28],"little"))
        assert self.target==records["do_execveat_common+0x0"]["offset"]+4
        prologue=int.from_bytes(code[20:24],"little")
        assert prologue&0xffc003ff==0xd10003ff
        self.stack_delta=(prologue>>10)&0xfff
        fields=receipt["layout"]["fields"]
        self.cred=fields["task_struct.cred"]["offsetBytes"]
        self.suid=fields["cred.suid"]["offsetBytes"]; self.euid=fields["cred.euid"]["offsetBytes"]
        self.metadata=None

    def replay(self,row):
        request,response,packet=[bytes.fromhex(row[name]) for name in ("request","response","packet")]
        fields=struct.unpack("<IHHIIQQQQ",request)
        command,request_id,response_pointer,arg0,arg1=fields[3],fields[5],fields[6],fields[7],fields[8]
        request_pointer=row["requestPointer"]
        frame=bytes((packet[48+i]+packet[66+i])&255 for i in range(18))
        assert frame.hex()==row["frame"] and struct.unpack_from("<Q",frame,10)[0]==request_pointer
        assert command in (1,3) and response_pointer==row["responsePointer"] and not any(response)
        read=bytes.fromhex(row["readArgs"]); destination=bytes.fromhex(row["destination"])
        output=count=None
        if command==3:
            output,count,reserved=struct.unpack("<QII",read)
            assert len(read)==16 and len(destination)==count and reserved==0 and 1<=count<=256
            assert min(request_pointer,response_pointer,arg1,output)>0xffffffff
        u=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
        image_end=max([self.from_user,self.from_kernel,self.to_user,self.target,self.panic+48]+
                      [at+len(code) for at,code in self.bodies.values()])
        u.mem_map(SLIDE,(image_end+4095)&~4095)
        u.mem_map(0x30000000,0x40000)
        data_source=0xffff000001200000
        u.mem_map(data_source,4096)
        data=bytes((i*73+19)&255 for i in range(257));u.mem_write(data_source,data)
        pages=set()
        def put(pointer,raw):
            for page in range(pointer&~4095,((pointer+len(raw)-1)&~4095)+4096,4096):
                if page not in pages:u.mem_map(page,4096);pages.add(page)
            u.mem_write(pointer,raw)
        put(request_pointer,request);put(response_pointer,response)
        if command==3:put(arg1,read);put(output,destination)
        task,cred,filename,name,stack=0x30001000,0x30002000,0x30003000,0x30004000,0x30030000
        body_stack=stack-80-384
        u.mem_write(name,packet);u.mem_write(filename,struct.pack("<Q",name))
        u.mem_write(task+self.cred,struct.pack("<Q",cred));u.mem_write(cred,b"\x56"*128)
        u.mem_write(cred+self.suid,frame[2:10]);u.mem_write(cred+self.euid,struct.pack("<I",10000))
        initial_cred=bytes(u.mem_read(cred,128))
        for at,code in self.bodies.values():u.mem_write(SLIDE+at,code)
        u.mem_write(SLIDE+self.panic,self.key)
        initial=[0x1234567800000000+i for i in range(31)];initial[1]=filename
        for i,value in enumerate(initial):u.reg_write(getattr(R,f"UC_ARM64_REG_X{i}"),value)
        u.reg_write(R.UC_ARM64_REG_SP,stack);u.reg_write(R.UC_ARM64_REG_SP_EL0,task)
        calls,credential_writes,completion=[],[],[]
        def x(i):return u.reg_read(getattr(R,f"UC_ARM64_REG_X{i}"))
        def writes(uc,access,address,size,value,unused):
            if cred<=address<cred+128:credential_writes.append([address-cred,size])
        def execute(uc,pc,size,unused):
            if pc==SLIDE+self.target:uc.emu_stop();return
            if pc not in (SLIDE+self.from_user,SLIDE+self.from_kernel,SLIDE+self.to_user):return
            assert u.reg_read(R.UC_ARM64_REG_SP)%16==0
            target,source,length,link=x(0),x(1),x(2),x(30)
            direction={SLIDE+self.from_user:"from",SLIDE+self.from_kernel:"kernel",SLIDE+self.to_user:"to"}[pc]
            calls.append(dict(direction=direction,destination=target,source=source,bytes=length))
            outcome=0
            if direction=="from":
                assert (source,length) in ((request_pointer,48),(arg1,16))
                assert body_stack<=target and target+length<=body_stack+384
                u.mem_write(target,bytes(u.mem_read(source,length)))
            elif direction=="kernel":
                assert target==body_stack+128 and source==arg0 and length==count
                if row["phase"]=="kernel_fault":outcome=-14
                else:u.mem_write(target,bytes(u.mem_read(source,length)))
            else:
                assert body_stack<=source and source+length<=body_stack+384
                if source==body_stack+128:
                    assert target==output and length==count
                    if row["phase"]=="partial_data":
                        u.mem_write(target,bytes(u.mem_read(source,17)));outcome=-14
                    else:u.mem_write(target,bytes(u.mem_read(source,length)))
                else:
                    assert target==response_pointer and length in (48,4)
                    completion.append(bytes(u.mem_read(response_pointer,48)).hex())
                    assert not any(u.mem_read(response_pointer,4))
                    u.mem_write(target,bytes(u.mem_read(source,length)))
            for i in range(18):u.reg_write(getattr(R,f"UC_ARM64_REG_X{i}"),0xbad00000+i)
            u.reg_write(R.UC_ARM64_REG_X0,outcome&MASK);u.reg_write(R.UC_ARM64_REG_PC,link)
        u.hook_add(UC_HOOK_CODE,execute);u.hook_add(UC_HOOK_MEM_WRITE,writes)
        u.emu_start(SLIDE+self.bodies["frame"][0]+28,SLIDE+self.target+4,count=20000)
        assert u.reg_read(R.UC_ARM64_REG_PC)==SLIDE+self.target
        assert u.reg_read(R.UC_ARM64_REG_SP)==stack-self.stack_delta
        assert all(x(i)==initial[i] for i in [*range(8),*range(18,31)])
        assert not credential_writes and bytes(u.mem_read(cred,128))==initial_cred
        actual_response=bytes(u.mem_read(response_pointer,48));values=struct.unpack("<IHHIiQQQII",actual_response)
        expected_status=-14 if row["phase"] in ("kernel_fault","partial_data") else 0
        assert values[:6]==(0x3252534d,2,48,command,expected_status,request_id)
        if command==1:
            assert values[6]==7 and values[8:]==(48,2)
            self.metadata=(values[7],bytes(u.mem_read(values[7],48)))
            assert struct.unpack("<IHHQqqqII",self.metadata[1])[:4]==(0x324d534d,2,48,7)
            returned=self.metadata[1]
        else:
            assert values[6]==(0 if expected_status else count) and values[7:]==(0,0,0)
            returned=bytes(u.mem_read(output,count))
            if row["phase"] in ("metadata_read","warm_metadata_read"):
                assert arg0==self.metadata[0] and returned==self.metadata[1]
        return dict(phase=row["phase"],command=command,requestId=request_id,source=arg0,
                    response=actual_response.hex(),data=returned.hex(),calls=calls,
                    completionEvents=completion,credentialWrites=credential_writes,abiPreserved=True),actual_response,returned


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("--evidence",type=Path,required=True)
    parser.add_argument("--fixture",type=Path,required=True);args=parser.parse_args()
    evidence=args.evidence.resolve();fixture=args.fixture.resolve()
    inputs=json.loads((evidence/"INPUTS.json").read_text(encoding="utf-8-sig"))
    for row in inputs:assert ident(evidence/"source"/row["path"])["sha256"]==row["sha256"]
    local_fixture=evidence/"fixture";local_fixture.mkdir(exist_ok=True)
    for name in ("patch.spec","host-receipt.json","execution.json"):
        shutil.copyfile(fixture/name,local_fixture/name)
    execution=json.loads((local_fixture/"execution.json").read_bytes())
    assert ident(local_fixture/"patch.spec")["sha256"]==execution["spec"]["sha256"]
    assert ident(local_fixture/"host-receipt.json")["sha256"]==execution["receipt"]["sha256"]
    emulator=Emulator(local_fixture)
    build=evidence/"build";build.mkdir(exist_ok=True);tests=evidence/"tests";tests.mkdir(exist_ok=True)
    test=ROOT/"runtime/maplesu-sdk/sdk/tools/tests/kernel_request_key/test_pairing_read.cpp"
    shutil.copyfile(test,tests/test.name);shutil.copyfile(Path(__file__),tests/Path(__file__).name)
    (build/"kernel_module_kit_umbrella.h").write_text('#pragma once\n#include "module_err_def.h"\n')
    (build/"module_base_kernel_mem.h").write_text('#pragma once\nnamespace kernel_module { uint32_t get_page_size(); }\n')
    docker=["docker","run","--rm","--pull","never","--network","none","--read-only","--tmpfs","/tmp:rw,size=16m",
            "--mount",f"type=bind,source={evidence},target=/work","-w","/work/build",IMAGE]
    prefix="/work/source/runtime/maplesu-sdk/"
    compile_command=[*docker,"g++","-std=c++20","-O1","-I/work/build","-I"+prefix+"sdk/include","-I"+prefix+"include",
                     "/work/tests/test_pairing_read.cpp",prefix+"sdk/src/kernel_request/module_base_kernel_request.cpp",
                     prefix+"sdk/src/module/module_current_identity.cpp","-Wl,--wrap=syscall,--wrap=getresuid,--wrap=getresgid",
                     "-o","client-read-pairing"]
    free_before={drive:shutil.disk_usage(drive).free for drive in ("C:/","D:/")}
    compiled=subprocess.run(compile_command,capture_output=True,text=True,timeout=60)
    (evidence/"compile.log").write_text(compiled.stdout+compiled.stderr)
    assert compiled.returncode==0,compiled.stderr
    minimum=dict(free_before)
    process=subprocess.Popen([*docker[:2],"-i",*docker[2:],"./client-read-pairing"],stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,encoding="utf-8")
    rows,simulations=[],[]
    process.stdin.write(emulator.key.hex()+"\n");process.stdin.flush()
    try:
        for line in process.stdout:
            row=json.loads(line);rows.append(row)
            if row["type"]=="transport":
                simulation,response,data=emulator.replay(row);simulations.append(simulation)
                process.stdin.write(response.hex()+" "+data.hex()+"\n");process.stdin.flush()
            elif row["type"]=="query":assert row["passed"]
            elif row["type"] in ("result","summary"):assert row["failures"]==0,row
            for drive in minimum:minimum[drive]=min(minimum[drive],shutil.disk_usage(drive).free)
        process.stdin.close();exit_code=process.wait(timeout=15);stderr=process.stderr.read()
        assert exit_code==0,stderr
    except BaseException:process.kill();process.wait(timeout=15);raise
    for name,values in (("client.jsonl",rows),("simulations.jsonl",simulations)):
        (evidence/name).write_text("".join(json.dumps(row)+"\n" for row in values))
    assert len(simulations)==7 and simulations[0]["command"]==1 and all(row["command"]==3 for row in simulations[1:])
    assert len({row["requestId"] for row in simulations})==7
    for row in inputs:assert ident(evidence/"source"/row["path"])["sha256"]==row["sha256"]
    receipt=dict(schema="maplesu-client-read-pairing/1",recordedAt=datetime.now(timezone.utc).isoformat(),
                 passed=True,image=IMAGE,compile=dict(argv=compile_command,exit=compiled.returncode),
                 kernelSlide=SLIDE,pairedTransports=len(simulations),metadataAddress=emulator.metadata[0],
                 metadataBytes=emulator.metadata[1].hex(),sourceFreezeVerified=True,
                 fullSdkBuild=False,apkBuild=False,deviceAccess=False,partitionWrites=False,
                 productionConsumerSwitched=False,space=dict(freeBefore=free_before,minimumSampledFree=minimum),
                 boundaries=["Production C++ is host-compiled from frozen inputs; Android archive not rebuilt.",
                     "Actual 544B target A64 bytes run in Unicorn; nofault and preparation/IDs are captured stubs.",
                     "READ descriptor/destination bytes originate in actual client, not reconstructed wire."])
    (evidence/"RECEIPT.json").write_text(json.dumps(receipt,indent=2)+"\n")
    print(json.dumps(dict(passed=True,transports=len(simulations),phases=[row["phase"] for row in simulations],space=receipt["space"])))


if __name__=="__main__":main()
