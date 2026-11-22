"""Reference ABI declarations bound to actual same-target objects and ELF imports.

BTF remains authoritative when it contains the declaration. Missing BTF FUNC/VAR
may use a retained same-target header declaration, with current object provenance,
actual symbol relocations, matching configuration and reference symbol extent.
No runtime or device qualification is granted here.
"""
from pathlib import Path
import hashlib
import json
import re
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection


def config_symbols_sha256(data):
    values = {}
    for line in data.decode().splitlines():
        if line.startswith('CONFIG_') and '=' in line:
            key, value = line.split('=', 1)
        else:
            item = re.fullmatch(r'# (CONFIG_[A-Za-z0-9_]+) is not set', line)
            if not item:
                continue
            key, value = item[1], 'n'
        if key in values and values[key] != value:
            raise ValueError('Conflicting actual config symbol: ' + key)
        values[key] = value
    enabled = {key: value for key, value in values.items() if value != 'n'}
    return hashlib.sha256(json.dumps(enabled, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def _name(die):
    item = die.attributes.get('DW_AT_name')
    return item.value.decode() if item else ''


def _type(die):
    return die.get_DIE_from_attribute('DW_AT_type') if die is not None and 'DW_AT_type' in die.attributes else None


def _resolve(die):
    for _ in range(64):
        if die is None or die.tag not in ('DW_TAG_typedef', 'DW_TAG_const_type',
                'DW_TAG_volatile_type', 'DW_TAG_restrict_type', 'DW_TAG_atomic_type'):
            return die
        die = _type(die)
    raise ValueError('Reference declaration DWARF modifier cycle')


class _DwarfTypes:
    def __init__(self, btf):
        self.btf = btf
        self.cache = {}

    def matches(self, die, index, active=frozenset()):
        die, index = _resolve(die), self.btf.resolve(index)
        if die is None or not index:
            return die is None and not index
        key = (die.offset, index)
        if key in active:
            return True
        if len(active) >= 64:
            raise ValueError('Reference declaration DWARF/BTF graph depth')
        active = active | {key}
        entry = self.btf.types[index]
        label, kind, count, value, bits, at = entry
        attrs = die.attributes
        size = attrs.get('DW_AT_byte_size')
        size = size.value if size else None
        if die.tag == 'DW_TAG_base_type':
            return kind == 1 and size == value and _name(die) == self.btf.name(label)
        if die.tag == 'DW_TAG_pointer_type':
            return kind == 2 and (size or die.cu['address_size']) == 8 and self.matches(_type(die), value, active)
        if die.tag == 'DW_TAG_array_type':
            dimensions = []
            for bound in die.iter_children():
                if bound.tag != 'DW_TAG_subrange_type':
                    continue
                lower = bound.attributes.get('DW_AT_lower_bound')
                if lower and lower.value != 0:
                    return False
                length = bound.attributes.get('DW_AT_count')
                upper = bound.attributes.get('DW_AT_upper_bound')
                dimensions.append(length.value if length else upper.value + 1 if upper else 0)
            current = index
            for length in dimensions:
                current = self.btf.resolve(current)
                _, array_kind, _, _, _, array_at = self.btf.types[current]
                if array_kind != 3 or self.btf.u32(array_at + 8) != length:
                    return False
                current = self.btf.u32(array_at)
            return bool(dimensions) and self.matches(_type(die), current, active)
        if die.tag in ('DW_TAG_structure_type', 'DW_TAG_union_type'):
            expected = 4 if die.tag == 'DW_TAG_structure_type' else 5
            if kind == 7:
                return size is None and self.btf.name(label) == _name(die) and bits == (expected == 5)
            if kind != expected or self.btf.name(label) != _name(die) or size != value:
                return False
            members = [item for item in die.iter_children() if item.tag == 'DW_TAG_member']
            if len(members) != count:
                return False
            for ordinal, member in enumerate(members):
                offset = at + ordinal * 12
                raw = self.btf.u32(offset + 8)
                btf_offset, width = (raw & 0xffffff, raw >> 24) if bits else (raw, 0)
                member_attrs = member.attributes
                member_bits = member_attrs.get('DW_AT_bit_size')
                if (member_bits.value if member_bits else 0) != width:
                    return False
                location = member_attrs.get('DW_AT_data_bit_offset')
                if location:
                    dwarf_offset = location.value
                else:
                    location = member_attrs.get('DW_AT_data_member_location')
                    dwarf_offset = location.value * 8 if location and isinstance(location.value, int) else 0 if expected == 5 else None
                    if 'DW_AT_bit_offset' in member_attrs:
                        return False
                if dwarf_offset != btf_offset or _name(member) != self.btf.name(self.btf.u32(offset)):
                    return False
                if not self.matches(_type(member), self.btf.u32(offset + 4), active):
                    return False
            return True
        if die.tag == 'DW_TAG_enumeration_type':
            if kind not in (6, 19) or size != value or self.btf.name(label) != _name(die):
                return False
            values = [item for item in die.iter_children() if item.tag == 'DW_TAG_enumerator']
            if len(values) != count:
                return False
            stride = 8 if kind == 6 else 12
            mask = (1 << (size * 8)) - 1
            for ordinal, enum in enumerate(values):
                position = at + ordinal * stride
                number = self.btf.u32(position + 4)
                if kind == 19:
                    number |= self.btf.u32(position + 8) << 32
                if _name(enum) != self.btf.name(self.btf.u32(position)) or enum.attributes['DW_AT_const_value'].value & mask != number & mask:
                    return False
            return True
        if die.tag == 'DW_TAG_subroutine_type':
            return kind == 13 and self.prototype_matches(die, index, active)
        return False

    def prototype_matches(self, die, index, active=frozenset()):
        _, kind, count, returned, _, at = self.btf.types[self.btf.resolve(index)]
        if kind != 13 or not self.matches(_type(die), returned, active):
            return False
        parameters = [item for item in die.iter_children() if item.tag in ('DW_TAG_formal_parameter', 'DW_TAG_unspecified_parameters')]
        return len(parameters) == count and all(self.matches(_type(item), self.btf.u32(at + ordinal * 8 + 4), active)
                for ordinal, item in enumerate(parameters))

    def index(self, die):
        die = _resolve(die)
        if die is None:
            return 0
        if die.offset not in self.cache:
            candidates = [index for index in range(1, len(self.btf.types)) if self.matches(die, index)]
            signatures = {self.btf.signature(index) for index in candidates}
            if len(signatures) != 1:
                raise ValueError('Missing/ambiguous exact same-object DWARF/BTF type: ' + _name(die))
            self.cache[die.offset] = candidates[0]
        return self.cache[die.offset]

    def function(self, die):
        returned = self.index(_type(die))
        parameters = [self.index(_type(item)) for item in die.iter_children()
                      if item.tag in ('DW_TAG_formal_parameter', 'DW_TAG_unspecified_parameters')]
        signature = 'f' + self.btf.signature(returned) + '(' + ''.join(self.btf.signature(index) + ';' for index in parameters) + ')'
        return signature, returned, parameters


class ReferenceAbi:
    def __init__(self, btf, target, source, symbol_kinds, provenance, object_btf, identity):
        self.base, self.target, self.source = btf, Path(target), source
        self.provenance, self.object_btf, self.identity = provenance, object_btf, identity
        self.extents = json.loads((self.target / 'reference-symbol-extents.json').read_text())
        self.functions, self.variables = dict(btf.functions), dict(btf.variables)
        for name, kinds in symbol_kinds.items():
            if kinds == {'OBJECT'}:
                self.variables.setdefault(name, [])
            elif kinds == {'FUNC'}:
                self.functions.setdefault(name, [])
        self.evidence, self.cache = {}, {}

    def __getattr__(self, name):
        return getattr(self.base, name)

    def _reference(self, name, kind):
        rows = self.extents.get(name, [])
        if len(rows) != 1:
            raise ValueError('Missing/ambiguous actual reference ELF extent: ' + name)
        row = rows[0]
        offset = row['address'] - row['sectionAddress']
        if row['kind'] != kind or row['bytes'] <= 0 or offset < 0 or offset + row['bytes'] > row['sectionBytes'] or not row['sectionFlags'] & 2:
            raise ValueError('Actual reference ELF kind/extent mismatch: ' + name)
        if kind == 'FUNC' and (not row['sectionFlags'] & 4 or row['address'] % 4):
            raise ValueError('Actual reference ELF function is not executable/aligned: ' + name)
        if kind == 'OBJECT' and row['sectionFlags'] & 4:
            raise ValueError('Actual reference ELF data object is executable: ' + name)
        return row

    def _type_bindings(self, local, indexes):
        bindings = []
        for index in sorted(set(indexes)):
            index = local.resolve(index)
            if not index:
                continue
            label, kind, count, value, bits, at = local.types[index]
            name = local.name(label)
            if kind in (4, 5, 7) and name:
                candidates = [i for i, item in enumerate(self.base.types) if item and
                              item[1] in (4, 5, 7) and self.base.name(item[0]) == name]
                if kind == 7:
                    candidates = [i for i in candidates if self.base.types[i][1] == (5 if bits else 4) or self.base.types[i][1] == 7]
                else:
                    candidates = [i for i in candidates if self.base.signature(i) == local.signature(index)]
                if not candidates:
                    raise ValueError('Same-target declaration/reference aggregate identity mismatch: ' + name)
                bindings.append(dict(name=name, objectTypeId=index, referenceTypeIds=candidates,
                    objectTypeSignature=local.signature(index), opaqueDeclaration=kind == 7))
            elif kind in (1, 6, 19):
                signature = local.signature(index)
                candidates = [i for i, item in enumerate(self.base.types) if item and item[1] == kind and self.base.signature(i) == signature]
                if not candidates:
                    raise ValueError('Same-target declaration/reference scalar identity mismatch')
                bindings.append(dict(objectTypeId=index, referenceTypeIds=candidates, signature=signature))
            elif kind == 2:
                bindings.extend(self._type_bindings(local, [value]))
            elif kind == 3:
                bindings.extend(self._type_bindings(local, [local.u32(at)]))
            elif kind == 13:
                bindings.extend(self._type_bindings(local, [value] + [local.u32(at + ordinal * 8 + 4) for ordinal in range(count)]))
        return bindings

    def _fallback(self, name, kind):
        key = (kind, name)
        if key in self.cache:
            return self.cache[key]
        extent = self._reference(name, kind)
        config_sha = self.source.get('configSha256')
        if not config_sha or hashlib.sha256(self.base.data).hexdigest() != self.source['btfSha256']:
            raise ValueError('Missing actual reference config/BTF identity for declaration fallback')
        matches = []
        for receipt in sorted((self.target / 'build-dependencies').glob('*.json')):
            object_name = receipt.stem
            path = self.target / (object_name + '.o')
            with path.open('rb') as stream:
                elf = ELFFile(stream)
                table = elf.get_section_by_name('.symtab')
                symbols = table.get_symbol_by_name(name) if table else None
                if not symbols or not any(item['st_shndx'] == 'SHN_UNDEF' for item in symbols):
                    continue
                relocations = []
                pointer_names = set()
                for section in elf.iter_sections():
                    if not isinstance(section, RelocationSection):
                        continue
                    destination = elf.get_section(section['sh_info'])
                    if not destination['sh_flags'] & 2:
                        continue
                    linked = elf.get_section(section['sh_link'])
                    for relocation in section.iter_relocations():
                        symbol = linked.get_symbol(relocation['r_info_sym'])
                        if symbol.name != name or symbol['st_shndx'] != 'SHN_UNDEF':
                            continue
                        relocations.append(dict(section=destination.name, offset=relocation['r_offset'],
                            type=relocation['r_info_type'], symbolIndex=relocation['r_info_sym'], addend=relocation['r_addend']))
                        for pointer in table.iter_symbols():
                            if pointer['st_info']['type'] == 'STT_OBJECT' and pointer['st_shndx'] == section['sh_info'] and pointer['st_size'] == 8 and pointer['st_value'] == relocation['r_offset']:
                                if relocation['r_info_type'] == 257 and relocation['r_addend'] == 0:
                                    pointer_names.add(pointer.name)
                if not relocations:
                    continue
                proof = self.provenance(self.target, object_name)
                config = [row for row in proof['dependencies'] if Path(row['path']).name == '.config']
                if len(config) != 1:
                    raise ValueError('Declaration object has no unique actual configuration: ' + object_name)
                if config[0]['sha256'] != config_sha:
                    captured_config = self.target / config[0]['archivePath']
                    expected_symbols = self.source.get('configSymbolsSha256')
                    if not expected_symbols or config_symbols_sha256(captured_config.read_bytes()) != expected_symbols:
                        raise ValueError('Declaration object/reference configuration symbols differ: ' + object_name)
                local = self.object_btf(path)
                typeids = table.get_symbol_by_name('__kcfi_typeid_' + name) if kind == 'FUNC' else None
                kcfi = dict(declarationTypeidPresent=bool(typeids), comparisonPerformed=False)
                if typeids:
                    if len(typeids) != 1 or typeids[0]['st_shndx'] != 'SHN_ABS' or extent.get('prefixWord') != typeids[0]['st_value']:
                        raise ValueError('Actual declaration/reference KCFI prefix differs: ' + name)
                    kcfi.update(comparisonPerformed=True, declarationTypeid=typeids[0]['st_value'], matched=True)
                found = []
                if kind == 'FUNC':
                    for pointer in sorted(pointer_names):
                        for variable in local.variables.get(pointer, []):
                            pointer_type = local.resolve(local.types[variable][3])
                            entry = local.types[pointer_type]
                            if entry[1] != 2:
                                continue
                            proto_index = local.resolve(entry[3])
                            proto = local.types[proto_index]
                            if proto[1] == 13:
                                parameters = [local.u32(proto[5] + i * 8 + 4) for i in range(proto[2])]
                                found.append((local.signature(proto_index), proto[3], parameters,
                                    dict(method='same-object-BTF-pointer-relocation', declaration=pointer, typeId=proto_index)))
                elif kind == 'OBJECT':
                    for pointer in sorted(pointer_names):
                        for variable in local.variables.get(pointer, []):
                            pointer_type = local.resolve(local.types[variable][3])
                            entry = local.types[pointer_type]
                            if entry[1] != 2:
                                continue
                            pointee = local.resolve(entry[3])
                            object_bytes = local.type_size(pointee)
                            raw_upper = extent.get('sourceFormat') == 'raw-arm64-image' and not extent.get('extentExact')
                            if object_bytes <= 0 or (object_bytes > extent['boundaryUpperBoundBytes'] if raw_upper else object_bytes != extent['bytes']):
                                raise ValueError('Typed address declaration/reference object extent differs: ' + name)
                            found.append((local.signature(pointee), pointee, [],
                                dict(method='same-object-BTF-typed-address-relocation', declaration=pointer,
                                     typeId=pointee, declarationObjectBytes=object_bytes)))
                if not found and elf.has_dwarf_info():
                    dwarf = elf.get_dwarf_info()
                    matcher = _DwarfTypes(local)
                    for cu in dwarf.iter_CUs():
                        for die in cu.iter_DIEs():
                            # A fortified source name may denote a different, hidden-argument ABI.
                            # Explicit assembler/linkage identity owns the actual ELF import.
                            linkage = die.attributes.get('DW_AT_linkage_name') or die.attributes.get('DW_AT_MIPS_linkage_name')
                            declared = linkage.value.decode() if linkage else _name(die)
                            if declared != name or die.tag != ('DW_TAG_subprogram' if kind == 'FUNC' else 'DW_TAG_variable'):
                                continue
                            if kind == 'FUNC':
                                signature, returned, parameters = matcher.function(die)
                                indexes = [returned] + parameters
                            else:
                                index = matcher.index(_type(die))
                                object_bytes = local.type_size(index)
                                raw_upper = extent.get('sourceFormat') == 'raw-arm64-image' and not extent.get('extentExact')
                                if object_bytes <= 0 or (object_bytes > extent['boundaryUpperBoundBytes'] if raw_upper else object_bytes != extent['bytes']):
                                    raise ValueError('Header declaration/reference object extent differs: ' + name)
                                signature, returned, parameters, indexes = local.signature(index), index, [], [index]
                            found.append((signature, returned, parameters, dict(method='same-object-DWARF-declaration-to-BTF-type',
                                declarationDieOffset=die.offset, declarationName=_name(die),
                                declarationLinkageName=linkage.value.decode() if linkage else None,
                                compileUnit=_name(cu.get_top_DIE()),
                                typeDieOffset=_type(die).offset if _type(die) else None)))
                for signature, returned, parameters, method in found:
                    bindings = self._type_bindings(local, [returned] + parameters)
                    if kind == 'OBJECT':
                        method['declarationObjectBytes'] = local.type_size(returned)
                    method['declarationConfigSha256'] = config[0]['sha256']
                    method['referenceConfigSymbolsSha256'] = self.source.get('configSymbolsSha256')
                    matches.append((signature, parameters, dict(**method, objectIdentity=self.identity(path),
                        parameterSignatures=[local.signature(index) for index in parameters],
                        kcfiDeclarationBinding=kcfi,
                        commandIdentity=self.identity(self.target / ('.' + object_name + '.o.cmd')),
                        dependencyReceiptIdentity=self.identity(receipt), sourceIdentity=proof['sourceIdentity'],
                        referenceExtent=extent, referenceConfigSha256=config_sha,
                        externalSymbolRelocations=relocations, typeBindings=bindings)))
        signatures = {item[0] for item in matches}
        if len(signatures) != 1:
            raise ValueError('Missing/ambiguous real same-target declaration ABI: ' + name)
        signature, parameters, evidence = matches[0]
        if kind == 'OBJECT' and extent.get('sourceFormat') == 'raw-arm64-image':
            sizes = {item[2]['declarationObjectBytes'] for item in matches}
            if len(sizes) != 1 or not 0 < next(iter(sizes)) <= extent['boundaryUpperBoundBytes']:
                raise ValueError('Raw reference declaration object extent differs: ' + name)
            markers_path = self.target / 'reference-function-markers.json'
            markers = json.loads(markers_path.read_text())
            marker = markers.get('suDataMarkers', {}).get(name)
            if marker is not None:
                marker.update(available=True, bytes=sizes.pop(), declarationExtentExact=True,
                    extentProvenance='actual-same-target-declaration-and-matching-reference-BTF-types',
                    originalSymbolExtentExact=extent.get('extentExact', False), reason=None)
                markers_path.write_text(json.dumps(markers, indent=2) + '\n')
        self.evidence[name] = dict(kind=kind, signature=signature, declarations=[item[2] for item in matches],
                                   deviceValidated=False, executionQualified=False)
        self.cache[key] = signature, parameters
        return self.cache[key]

    def function(self, name):
        try:
            return self.base.function(name)
        except ValueError:
            if self.base.functions.get(name):
                raise
            return self._fallback(name, 'FUNC')[0]

    def variable(self, name):
        try:
            return self.base.variable(name)
        except ValueError:
            if self.base.variables.get(name):
                raise
            return self._fallback(name, 'OBJECT')[0]

    def function_parameter(self, name, parameter):
        try:
            return self.base.function_parameter(name, parameter)
        except ValueError:
            if self.base.functions.get(name):
                raise
            _, parameters = self._fallback(name, 'FUNC')
            if parameter < 0 or parameter >= len(parameters):
                raise ValueError('Missing same-target declaration function parameter: ' + name)
            # Parameters are actual same-object BTF type ids; preserve the
            # canonical strings in evidence rather than borrowing reference ids.
            signatures = {item['parameterSignatures'][parameter] for item in self.evidence[name]['declarations']
                          if 'parameterSignatures' in item}
            if len(signatures) != 1 or not next(iter(signatures)).startswith('*f'):
                raise ValueError('Missing/ambiguous real callback declaration parameter: ' + name)
            return signatures.pop()
