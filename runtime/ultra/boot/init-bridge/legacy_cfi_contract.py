"""Exact-image legacy CFI IDs and actual module checker evaluation.

All addresses below are private relocation-model addresses, never device offsets.
Unsupported instructions/relocations retain a real package failure. No runtime
owner, loader or device acceptance is inferred from a static return path.
"""
import io
import struct
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

MASK=(1<<64)-1

def word(data, at):
    if at < 0 or at % 4 or at+4 > len(data): raise ValueError('LEGACY_CFI_INSTRUCTION_BOUNDS')
    return struct.unpack_from('<I',data,at)[0]

def signed(value,bits):
    return value-(1<<bits) if value&(1<<(bits-1)) else value

def offsets(table,name):
    return set(table.all_offsets(name))

def mode(image,table,config):
    checker=offsets(table,'__cfi_check')
    slow=set().union(*(offsets(table,n) for n in ('__cfi_slowpath','__cfi_slowpath_diag','__cfi_slowpath.cfi_jt','__cfi_slowpath_diag.cfi_jt')))
    if checker or slow:
        if len(checker)!=1 or not slow: raise ValueError('LEGACY_CFI_IMAGE_MODE_INCOMPLETE')
        return 'legacy-lto-cfi'
    return 'kcfi' if config.get('CONFIG_CFI')=='y' or config.get('CONFIG_CFI_CLANG')=='y' else 'none'

def callsite_types(image,table,caller,register=None):
    from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
    from capstone.arm64 import ARM64_OP_IMM,ARM64_OP_REG
    starts=offsets(table,caller)
    if len(starts)!=1: raise ValueError('LEGACY_CFI_CALLER:'+caller)
    start=next(iter(starts))
    end=min((row[0] for row in table.rows if row[0]>start),default=len(image))
    if start%4 or not start<end<=len(image) or end-start>262144: raise ValueError('LEGACY_CFI_CALLER_BOUNDS')
    slow=set().union(*(offsets(table,n) for n in ('__cfi_slowpath','__cfi_slowpath_diag','__cfi_slowpath.cfi_jt','__cfi_slowpath_diag.cfi_jt')))
    decoder=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN); decoder.detail=True
    instructions=list(decoder.disasm(image[start:end],start))
    result=[]
    for index,ins in enumerate(instructions):
        if ins.mnemonic!='bl' or ins.operands[0].type!=ARM64_OP_IMM or ins.operands[0].imm not in slow: continue
        continuation=None
        if register is not None:
            # The slowpath must check the same callback that its continuation calls.
            argument=False
            for previous in reversed(instructions[max(0,index-32):index]):
                if previous.mnemonic in ('b','bl','blr','br','ret') or previous.mnemonic.startswith(('b.','cb','tb')): break
                _,writes=previous.regs_access()
                written={previous.reg_name(item).replace('w','x',1) for item in writes}
                if register in written: break
                if 'x1' in written:
                    argument=previous.mnemonic=='mov' and previous.op_str=='x1, '+register
                    break
            if not argument: continue
            # LLVM may outline the check into a cold block which branches back
            # to the original indirect call. Follow that actual continuation,
            # not adjacent, possibly unreachable instructions in file order.
            by_address={item.address:item for item in instructions}
            at=ins.address+ins.size; visited=[]
            while at in by_address and at not in visited and len(visited)<32:
                item=by_address[at]; visited.append(at)
                if item.mnemonic=='blr':
                    if item.op_str==register: continuation=visited
                    break
                if item.mnemonic=='b' and item.operands[0].type==ARM64_OP_IMM:
                    at=item.operands[0].imm
                    continue
                if item.mnemonic in ('bl','br','ret','retaa','retab') or item.mnemonic.startswith(('b.','cb','tb')):
                    break
                _,writes=item.regs_access()
                if register in {item.reg_name(value).replace('w','x',1) for value in writes}: break
                at+=item.size
            if continuation is None: continue
        tracked='x0'; lanes=0; value=0; origins=[]; found=None
        for previous in reversed(instructions[max(0,index-32):index]):
            if previous.mnemonic in ('b','bl','blr','br','ret') or previous.mnemonic.startswith(('b.','cb','tb')):
                break
            _,writes=previous.regs_access()
            names={previous.reg_name(item).replace('w','x',1) for item in writes}
            if tracked not in names: continue
            raw=word(image,previous.address); op=raw&0xff800000
            if op in (0xd2800000,0x92800000,0xf2800000):
                shift=((raw>>21)&3)*16; immediate=((raw>>5)&65535)<<shift; mask=65535<<shift
                origins.append(previous.address)
                if op==0xf2800000:
                    value|=immediate&~lanes; lanes|=mask
                    continue
                base=(~immediate&MASK) if op==0x92800000 else immediate
                found=(base&~lanes|value)&MASK; break
            if raw&0xffe0ffe0==0xaa0003e0:
                tracked='x'+str((raw>>16)&31); origins.append(previous.address)
                if tracked=='x31': found=value; break
                continue
            if raw&0xff000000==0x58000000:
                at=previous.address+signed((raw>>5)&0x7ffff,19)*4
                if not 0<=at<=len(image)-8: break
                base=struct.unpack_from('<Q',image,at)[0]
                found=(base&~lanes|value)&MASK; origins.append(previous.address); break
            break
        if found is None: raise ValueError('LEGACY_CFI_TYPE_ARGUMENT_UNPROVEN:'+caller+':'+hex(ins.address))
        fact={'caller':caller,'callOffset':ins.address,'slowpathOffset':ins.operands[0].imm,
              'typeIdHex':f'{found:016x}','materializationOffsets':list(reversed(origins))}
        if continuation is not None:
            fact.update(continuationOffsets=continuation,indirectCallOffset=continuation[-1],
                        indirectCallRegister=register)
        result.append(fact)
    if not result: raise ValueError('LEGACY_CFI_CALLSITE_MISSING:'+caller)
    return result

def unchecked_trace_callsite(image,table,caller):
    """Prove a native tracepoint iterator's actual uninstrumented callback loop."""
    from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
    from policy_btf_abi import Btf
    from capstone.arm64 import ARM64_OP_REG,ARM64_OP_MEM
    import hashlib
    def fail(label): raise ValueError('LEGACY_CFI_UNCHECKED_TRACE:'+label)
    def unique(name):
        values=offsets(table,name)
        if len(values)!=1: fail('SYMBOL:'+name)
        return values.pop()
    if not caller.startswith('__traceiter_'): fail('CALLER')
    event=caller[len('__traceiter_'):]
    start=unique(caller); end=min((row[0] for row in table.rows if row[0]>start),default=len(image))
    if start%4 or not 0<=start<end<=len(image) or end-start>65536: fail('BOUNDS')
    btf_start=unique('__start_BTF'); btf_end=unique('__stop_BTF')
    if not 0<=btf_start<btf_end<=len(image): fail('BTF_BOUNDS')
    btf=Btf(image[btf_start:btf_end])
    iterator=btf.function(caller)
    signatures={btf.function(name) for name in ('__bpf_trace_'+event,'trace_event_raw_event_'+event)}
    if len(signatures)!=1: fail('CALLBACK_ABI')
    signature=signatures.pop()
    if not signature.startswith('fv(') or iterator.partition('(')[2]!=signature.partition('(')[2]: fail('ITERATOR_ABI')
    tracepoint=btf.named_structure_members('tracepoint'); record=btf.named_structure_members('tracepoint_func')
    def field(layout,name):
        result=layout['members'].get(name,{})
        if result.get('bytes')!=8: fail('FIELD:'+name)
        return result['offset']
    func_offset=field(record,'func'); data_offset=field(record,'data')
    point=unique('__tracepoint_'+event); point_end=min((row[0] for row in table.rows if row[0]>point),default=len(image))
    if not 0<=point<point+tracepoint['bytes']<=point_end<=len(image): fail('OBJECT_BOUNDS')
    entry=struct.unpack_from('<Q',image,point+field(tracepoint,'iterator'))[0]-table.text_base
    canonical=offsets(table,caller+'.cfi_jt')|offsets(table,'__cfi_jt_'+caller)
    if entry!=start:
        if entry not in canonical: fail('ITERATOR_POINTER')
        at=entry
        if word(image,at) in (0xd503245f,0xd50324df): at+=4
        raw=word(image,at)
        if raw&0xfc000000!=0x14000000 or at+signed(raw&0x03ffffff,26)*4!=start: fail('ITERATOR_CANONICAL')
    funcs=point+field(tracepoint,'funcs')
    decoder=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN); decoder.detail=True
    rows=list(decoder.disasm(image[start:end],start)); by_address={row.address:row for row in rows}
    if len(rows)*4!=end-start: fail('DECODE')
    # Resolve the entire reachable CFG, including both empty and loop edges.
    pending=[start]; reachable=set()
    while pending:
        at=pending.pop()
        if at in reachable: continue
        ins=by_address.get(at)
        if ins is None: fail('CFG_BOUNDS')
        reachable.add(at); op=ins.mnemonic
        if op in ('bl','br','brk','hlt'): fail('INSTRUMENTED_OR_UNKNOWN_CALL')
        if op in ('ret','retab','retaa'): continue
        if op=='b': pending.append(ins.operands[0].imm); continue
        if op.startswith(('b.','cb','tb')): pending.append(ins.operands[-1].imm)
        pending.append(at+4)
    body=[row for row in rows if row.address in reachable]
    bases=[i for i,row in enumerate(body[:-1]) if row.mnemonic=='adrp' and body[i+1].mnemonic=='add' and
        row.operands[0].reg==body[i+1].operands[0].reg==body[i+1].operands[1].reg and
        row.operands[1].imm+body[i+1].operands[2].imm==funcs]
    if len(bases)!=1: fail('FUNCS_ADDRESS')
    first=bases[0]; chunk=body[first:first+13]
    if len(chunk)!=13: fail('LOOP_BOUNDS')
    base=chunk[0].reg_name(chunk[0].operands[0].reg)
    if chunk[2].mnemonic not in ('ldar','ldapr','ldr') or chunk[2].op_str.split(', ',1)[1]!='['+base+']': fail('LIST_LOAD')
    node=chunk[2].reg_name(chunk[2].operands[0].reg)
    if chunk[3].mnemonic!='cbz' or chunk[3].reg_name(chunk[3].operands[0].reg)!=node: fail('EMPTY_EDGE')
    saved={}
    for ins in chunk[4:6]:
        if ins.mnemonic!='mov' or ins.reg_name(ins.operands[1].reg) not in ('x1','x2'): fail('ARGUMENT_SAVE')
        saved[ins.reg_name(ins.operands[1].reg)]=ins.reg_name(ins.operands[0].reg)
    if set(saved)!=set(('x1','x2')): fail('ARGUMENT_SAVE')
    def memory_load(ins,register,offset,writeback=False):
        args=ins.operands
        return (len(args)==2 and args[0].type==ARM64_OP_REG and ins.reg_name(args[0].reg)==register and
                args[1].type==ARM64_OP_MEM and ins.reg_name(args[1].mem.base)==node and
                args[1].mem.index==0 and args[1].mem.disp==offset and ins.writeback==writeback and
                args[1].ext==0 and args[1].shift.value==0)
    fn=chunk[6].reg_name(chunk[6].operands[0].reg)
    if chunk[6].mnemonic not in ('ldar','ldapr','ldr') or not memory_load(chunk[6],fn,func_offset): fail('CALLBACK_LOAD')
    if ((chunk[7].mnemonic,chunk[7].op_str)!=('mov','x1, '+saved['x1']) or
            (chunk[8].mnemonic!='ldr' or not memory_load(chunk[8],'x0',data_offset)) or
            (chunk[9].mnemonic,chunk[9].op_str)!=('mov','x2, '+saved['x2']) or
            (chunk[10].mnemonic,chunk[10].op_str)!=('blr',fn)): fail('CALL_ARGUMENTS')
    following=body[first+13] if first+13<len(body) else None
    loaded=chunk[11].reg_name(chunk[11].operands[0].reg)
    if ((chunk[11].mnemonic!='ldr' or not memory_load(chunk[11],loaded,record['bytes'],True)) or
            chunk[12].mnemonic!='cbnz' or chunk[12].reg_name(chunk[12].operands[0].reg)!=loaded or
            chunk[12].operands[1].imm!=chunk[6].address or following is None or
            chunk[3].operands[1].imm!=following.address): fail('LOOP_EDGES')
    for ins in body[:first]:
        _,writes=ins.regs_access()
        if any(ins.reg_name(reg) in ('x1','x2','w1','w2') for reg in writes): fail('ARGUMENT_CLOBBER')
        if ins.mnemonic not in ('paciasp','pacibsp','bti','nop','str','stp','mov','sub','add'): fail('PROLOGUE')
    tail=body[first+13:]
    if not tail or tail[-1].mnemonic not in ('ret','retab','retaa') or any(ins.mnemonic not in
            ('ldr','ldp','mov','add','autiasp','autibsp','ret','retab','retaa','nop') for ins in tail): fail('EPILOGUE')
    if sum(ins.mnemonic=='blr' for ins in body)!=1 or len([ins for ins in body if ins.mnemonic.startswith(('b.','cb','tb'))])!=2: fail('CFG_SHAPE')
    return {'caller':caller,'callOffset':chunk[10].address,'cfiMode':'unchecked-native-callsite',
            'callbackSignature':'*'+signature,'iteratorSignature':iterator,'start':start,'bytes':end-start,
            'sha256':hashlib.sha256(image[start:end]).hexdigest(),'reachableOffsets':sorted(reachable),
            'tracepointOffset':point,'tracepointBytes':tracepoint['bytes'],
            'tracepointSha256':hashlib.sha256(image[point:point+tracepoint['bytes']]).hexdigest(),
            'iteratorOffset':entry,'funcsPointerOffset':funcs,'recordBytes':record['bytes'],
            'funcOffset':func_offset,'dataOffset':data_offset,'btfSha256':hashlib.sha256(image[btf_start:btf_end]).hexdigest(),
            'proof':'actual-symbol-bounded-uninstrumented-trace-loop-and-btf',
            'runtimeOwnerQualified':False,'deviceQualified':False}


def target_facts(image,table):
    init=callsite_types(image,table,'do_one_initcall','x19')
    work=callsite_types(image,table,'process_one_work')
    if len({row['typeIdHex'] for row in init})!=1: raise ValueError('LEGACY_CFI_INIT_TYPE_AMBIGUOUS')
    callers={
        'msu_su_session_ioctl':('vfs_ioctl','do_vfs_ioctl'),
        'msu_su_session_compat_ioctl':('compat_ptr_ioctl','__arm64_compat_sys_ioctl'),
        'msu_su_session_flush':('filp_close',), 'msu_su_session_release':('__fput',),
        'msu_su_session_free_rcu':('rcu_do_batch',),
        'msu_su_session_resume':('task_work_run',),
        'msu_su_session_exit_work':('process_one_work',)}
    callbacks={}
    for name,names in callers.items():
        facts=[]
        for caller in names:
            if offsets(table,caller): facts.extend(callsite_types(image,table,caller))
        callbacks[name]=facts
    task_callers={
        'msu_task_profile_sys_enter':('__traceiter_sys_enter',),
        'msu_task_profile_marker_entry':('pre_handler_kretprobe',),
        'msu_task_profile_marker_return':('kretprobe_trampoline_handler','__kretprobe_trampoline_handler','trampoline_handler')}
    task_callbacks={}
    for name,names in task_callers.items():
        facts=[]
        for caller in names:
            if not offsets(table,caller): continue
            try: facts.extend(callsite_types(image,table,caller))
            except ValueError as error:
                if str(error)!='LEGACY_CFI_CALLSITE_MISSING:'+caller or not caller.startswith('__traceiter_'): raise
                facts.append(unchecked_trace_callsite(image,table,caller))
        if not facts: raise ValueError('LEGACY_CFI_TASK_PROFILE_CALLER:'+name)
        task_callbacks[name]=facts
    task_types={caller:sorted({row['typeIdHex'] for rows in task_callbacks.values() for row in rows
                              if row['caller']==caller and 'typeIdHex' in row})
                for caller in sorted({row['caller'] for rows in task_callbacks.values() for row in rows})}
    import hashlib
    return {'mode':'legacy-lto-cfi','targetSha256':hashlib.sha256(image).hexdigest(),
            'taskProfileCallsites':task_callbacks,'taskProfileCallerTypeSets':task_types,
            'initCallsites':init,'workCallsites':work,
            'callbackCallsites':callbacks,'callerTypeSets':{caller:sorted({row['typeIdHex'] for row in callsite_types(image,table,caller)}) for caller in sorted({'do_one_initcall','process_one_work'}|{row['caller'] for rows in callbacks.values() for row in rows})},'runtimeOwnerQualified':False,'deviceQualified':False}

class ModuleChecker:
    """Apply actual ELF relocations, then follow only a concrete __cfi_check path."""
    def __init__(self,data):
        self.elf=ELFFile(io.BytesIO(data)); self.symbols=self.elf.get_section_by_name('.symtab')
        if self.elf['e_machine']!='EM_AARCH64' or self.elf['e_type']!='ET_REL' or self.symbols is None:
            raise ValueError('LEGACY_CFI_MODULE_ELF')
        self.sections={}; self.bases={}; cursor=0x10000000
        for index,section in enumerate(self.elf.iter_sections()):
            if not section['sh_flags']&2: continue
            alignment=max(4096,section['sh_addralign']); cursor=(cursor+alignment-1)&~(alignment-1)
            self.bases[index]=cursor
            self.sections[index]=bytearray(section['sh_size'] if section['sh_type']=='SHT_NOBITS' else section.data())
            cursor+=len(self.sections[index])+4096
        self.relocations={}; self.unresolved=[]
        for rels in self.elf.iter_sections():
            if not isinstance(rels,RelocationSection) or rels['sh_info'] not in self.sections: continue
            table=self.elf.get_section(rels['sh_link'])
            for rel in rels.iter_relocations():
                key=(rels['sh_info'],rel['r_offset'])
                if key in self.relocations: raise ValueError('LEGACY_CFI_RELOCATION_OVERLAP')
                self.relocations[key]=(rel,table.get_symbol(rel['r_info_sym']))
        for (section,at),(rel,symbol) in self.relocations.items():
            if not isinstance(symbol['st_shndx'],int) or symbol['st_shndx'] not in self.bases:
                self.unresolved.append((self.bases[section]+at,4)); continue
            target=self.bases[symbol['st_shndx']]+symbol['st_value']+rel['r_addend']
            place=self.bases[section]+at; kind=rel['r_info_type']; body=self.sections[section]
            if kind in (257,260):
                struct.pack_into('<Q',body,at,(target if kind==257 else target-place)&MASK); continue
            if kind==261:
                struct.pack_into('<I',body,at,(target-place)&0xffffffff); continue
            raw=word(body,at)
            if kind in (282,283): raw=(raw&0xfc000000)|(((target-place)>>2)&0x03ffffff)
            elif kind==274:
                delta=target-place
                raw=(raw&~0x60ffffe0)|((delta&3)<<29)|(((delta>>2)&0x7ffff)<<5)
            elif kind==275:
                delta=((target&~4095)-(place&~4095))>>12
                raw=(raw&~0x60ffffe0)|((delta&3)<<29)|(((delta>>2)&0x7ffff)<<5)
            elif kind==277: raw=(raw&~0x003ffc00)|((target&4095)<<10)
            elif kind in (278,284,285,286,299):
                scale={278:0,284:1,285:2,286:3,299:4}[kind]
                raw=(raw&~0x003ffc00)|(((target&4095)>>scale)<<10)
            elif kind==273: raw=(raw&~0x00ffffe0)|((((target-place)>>2)&0x7ffff)<<5)
            else:
                self.unresolved.append((place,4)); continue
            struct.pack_into('<I',body,at,raw)

    def symbol(self,name):
        rows=self.symbols.get_symbol_by_name(name) or []
        if not rows: rows=[row for row in self.symbols.iter_symbols() if row.name.startswith(name+'.llvm.')]
        if len(rows)!=1 or rows[0]['st_shndx'] not in self.bases: raise ValueError('LEGACY_CFI_MODULE_SYMBOL:'+name)
        return rows[0]

    def address(self,name):
        sym=self.symbol(name); return self.bases[sym['st_shndx']]+sym['st_value']

    def read(self,address,size):
        if any(address < at+width and at < address+size for at,width in self.unresolved):
            raise ValueError('LEGACY_CFI_UNRESOLVED_RELOCATION')
        for index,base in self.bases.items():
            data=self.sections[index]
            if base<=address and address+size<=base+len(data): return bytes(data[address-base:address-base+size])
        raise ValueError('LEGACY_CFI_MODEL_ADDRESS')

    def canonical(self,name):
        body=self.symbol(name); expected=self.address(name)
        rows=self.symbols.get_symbol_by_name('__cfi_jt_'+name) or self.symbols.get_symbol_by_name(name+'.cfi_jt') or []
        if len(rows)!=1 or rows[0]['st_shndx'] not in self.bases or not self.elf.get_section(rows[0]['st_shndx'])['sh_flags']&4:
            raise ValueError('LEGACY_CFI_CANONICAL:'+name)
        entry=self.bases[rows[0]['st_shndx']]+rows[0]['st_value']; branch=entry
        raw=int.from_bytes(self.read(branch,4),'little')
        if raw in (0xd503245f,0xd50324df): branch+=4; raw=int.from_bytes(self.read(branch,4),'little')
        if raw&0xfc000000!=0x14000000 or (expected!=entry and branch+signed(raw&0x03ffffff,26)*4!=expected):
            raise ValueError('LEGACY_CFI_CANONICAL_TARGET:'+name)
        self.read(branch+signed(raw&0x03ffffff,26)*4,4)
        return entry

    def accepts(self,type_id,target):
        from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
        from capstone.arm64 import ARM64_OP_IMM,ARM64_OP_REG,ARM64_OP_MEM
        decoder=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN); decoder.detail=True
        checker=self.symbol('__cfi_check'); begin=self.address('__cfi_check'); end=begin+checker['st_size']
        if end<=begin: raise ValueError('LEGACY_CFI_CHECKER_SIZE')
        registers={'x0':type_id,'x1':target,'x2':0,'sp':0x7000000000}; z=n=c=v=False
        def get(name):
            if name in ('xzr','wzr'): return 0
            return registers.get('x'+name[1:] if name.startswith('w') else name,0)&(0xffffffff if name.startswith('w') else MASK)
        def put(name,value):
            if name not in ('xzr','wzr'): registers['x'+name[1:] if name.startswith('w') else name]=value&(0xffffffff if name.startswith('w') else MASK)
        def value(ins,operand):
            if operand.type==ARM64_OP_IMM: result=operand.imm
            elif operand.type==ARM64_OP_REG: result=get(ins.reg_name(operand.reg))
            elif operand.type==ARM64_OP_MEM:
                at=get(ins.reg_name(operand.mem.base))+operand.mem.disp
                result=int.from_bytes(self.read(at,8),'little')
            else: raise ValueError('LEGACY_CFI_CHECKER_OPERAND')
            shift=operand.shift.value
            if shift:
                shift_name=str(operand.shift.type)
                # Capstone ARM64_SFT_LSL=1, LSR=3, ASR=4, ROR=5.
                if operand.shift.type==1: result<<=shift
                elif operand.shift.type==3: result>>=shift
                elif operand.shift.type==4: result=signed(result,64)>>shift
                elif operand.shift.type==5: result=(result>>shift)|(result<<(64-shift))
                else: raise ValueError('LEGACY_CFI_CHECKER_SHIFT:'+shift_name)
            return result&MASK
        def condition(name):
            values={'eq':z,'ne':not z,'hs':c,'cs':c,'lo':not c,'cc':not c,'mi':n,'pl':not n,
                    'vs':v,'vc':not v,'hi':c and not z,'ls':not c or z,'ge':n==v,'lt':n!=v,
                    'gt':not z and n==v,'le':z or n!=v,'al':True}
            if name not in values: raise ValueError('LEGACY_CFI_CHECKER_CONDITION:'+name)
            return values[name]
        pc=begin
        for _ in range(4096):
            if not begin<=pc<end: return False
            ins=next(decoder.disasm(self.read(pc,4),pc,count=1),None)
            if ins is None: raise ValueError('LEGACY_CFI_CHECKER_DECODE')
            op=ins.mnemonic; args=ins.operands; following=pc+4
            if op in ('bti','nop','paciasp','pacibsp','autiasp','autibsp'): pass
            elif op in ('ret','retab','retaa'): return True
            elif op=='b': following=args[0].imm
            elif op.startswith('b.'):
                if condition(op[2:]): following=args[0].imm
            elif op in ('cbz','cbnz'):
                if (value(ins,args[0])==0)==(op=='cbz'): following=args[1].imm
            elif op in ('tbz','tbnz'):
                if bool(value(ins,args[0])&(1<<args[1].imm))==(op=='tbnz'): following=args[2].imm
            elif op in ('bl','blr','br'): return False
            elif op in ('stp','str','ldp'):
                # Only the standard frame spill/restore, with no use in CFI predicates.
                if not ins.op_str.endswith(('!','[sp]','[sp, #0x10]','[sp], #0x10')) and 'sp' not in ins.op_str:
                    raise ValueError('LEGACY_CFI_CHECKER_MEMORY:'+op)
                if op=='ldp':
                    for a in args[:2]:
                        if ins.reg_name(a.reg) not in ('x29','x30'): raise ValueError('LEGACY_CFI_CHECKER_RESTORE')
            elif op in ('cmp','cmn','tst'):
                a,b=value(ins,args[0]),value(ins,args[1]); bits=32 if ins.reg_name(args[0].reg).startswith('w') else 64
                mask=(1<<bits)-1; result=(a-b if op=='cmp' else a+b if op=='cmn' else a&b)&mask
                z=result==0; n=bool(result&(1<<(bits-1))); c=a>=b if op=='cmp' else a+b>mask
                v=bool(((a^b)&(a^result))&(1<<(bits-1))) if op=='cmp' else False
            elif op in ('mov','movz','movn','movk','adr','adrp','ldr','add','sub','and','orr','eor','bic','lsl','lsr','asr','ror','neg','mvn','ubfx'):
                dest=ins.reg_name(args[0].reg); a=value(ins,args[1])
                b=value(ins,args[2]) if len(args)>2 else 0
                if op=='ldr' and args[1].type==ARM64_OP_IMM:
                    result=int.from_bytes(self.read(a,4 if dest.startswith('w') else 8),'little')
                elif op in ('mov','movz','adr','adrp','ldr'): result=a
                elif op=='movn': result=~a
                elif op=='movk':
                    shift=args[1].shift.value; result=(get(dest)&~(65535<<shift))|a
                elif op=='add': result=a+b
                elif op=='sub': result=a-b
                elif op=='and': result=a&b
                elif op=='orr': result=a|b
                elif op=='eor': result=a^b
                elif op=='bic': result=a&~b
                elif op=='lsl': result=a<<b
                elif op=='lsr': result=a>>b
                elif op=='asr': result=signed(a,32 if dest.startswith('w') else 64)>>b
                elif op=='ror': result=(a>>b)|(a<<(64-b))
                elif op=='neg': result=-a
                elif op=='mvn': result=~a
                else: result=(a>>b)&((1<<args[3].imm)-1)
                put(dest,result)
            else: raise ValueError('LEGACY_CFI_CHECKER_INSTRUCTION:'+op)
            pc=following
        raise ValueError('LEGACY_CFI_CHECKER_STEP_BOUND')

    def member(self,name,callsites):
        canonical=self.canonical(name); ids={row['typeIdHex'] for row in callsites}
        accepted=[value for value in ids if self.accepts(int(value,16),canonical)]
        if len(accepted)!=1: raise ValueError('LEGACY_CFI_MEMBERSHIP:'+name)
        return {'symbol':name,'typeIdHex':accepted[0],'canonicalSectionModelAddress':canonical,
                'proof':'actual-relocated-module-checker-path','runtimeOwnerQualified':False}

def verify_module(data,target,callbacks=()):
    if target.get('mode')!='legacy-lto-cfi': raise ValueError('LEGACY_CFI_TARGET_MODE')
    checker=ModuleChecker(data)
    members=[checker.member('init_module',target['initCallsites']),
             checker.member('msu_legacy_kernel_probe_work',target['workCallsites'])]
    for name in callbacks: members.append(checker.member(name,target['callbackCallsites'].get(name,[])))
    return {'mode':'legacy-lto-cfi','members':members,'moduleLoaded':False,
            'runtimeOwnerQualified':False,'deviceQualified':False}
