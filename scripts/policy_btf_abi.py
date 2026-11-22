"""Canonical function ABI from BTF; keep the encoding in kernel_layout.cpp in sync."""
import struct


class Btf:
    def __init__(self, data):
        magic, version, flags, header, offset, size, strings, string_size = struct.unpack_from("<HBBIIIII", data)
        if (magic, version, flags) != (0xeb9f, 1, 0):
            raise ValueError("BTF header")
        self.data = data
        self.strings = data[header + strings:header + strings + string_size]
        self.types = [None]
        self.functions = {}
        self.variables = {}
        at, end = header + offset, header + offset + size
        while at < end:
            name, info, value = struct.unpack_from("<III", data, at)
            kind, count = info >> 24 & 31, info & 65535
            extra = {1: 4, 2: 0, 3: 12, 4: 12*count, 5: 12*count, 6: 8*count,
                     7: 0, 8: 0, 9: 0, 10: 0, 11: 0, 12: 0, 13: 8*count,
                     14: 4, 15: 12*count, 16: 0, 17: 4, 18: 0, 19: 12*count}[kind]
            if at + 12 + extra > end:
                raise ValueError("BTF type bounds")
            if kind == 12:
                self.functions.setdefault(self.name(name), []).append(len(self.types))
            elif kind == 14:
                self.variables.setdefault(self.name(name), []).append(len(self.types))
            self.types.append((name, kind, count, value, bool(info >> 31), at + 12))
            at += 12 + extra

    def name(self, offset):
        return self.strings[offset:self.strings.index(0, offset)].decode()

    def u32(self, at):
        return struct.unpack_from("<I", self.data, at)[0]

    def signature(self, index, depth=0, pointer=False):
        if not index:
            return "v"
        if depth >= 32:
            raise ValueError("BTF signature cycle")
        for _ in range(64):
            if not index:
                return "v"
            name, kind, count, value, bits, at = self.types[index]
            if kind not in (8, 9, 10, 11, 18):
                break
            index = value
        else:
            raise ValueError("BTF modifier cycle")
        def nested(next_index, indirect=False):
            return self.signature(next_index, depth + 1, indirect)
        if kind == 1:
            result = f"i{value}:{self.u32(at)}"
        elif kind == 2:
            result = "*" + nested(value, True)
        elif kind == 3:
            result = f"a{self.u32(at + 8)}:" + nested(self.u32(at))
        elif kind in (4, 5):
            result = ("s" if kind == 4 else "u") + self.name(name)
            if not pointer or not name:
                result += f":{value}{{" + "".join(
                    f"{self.u32(at+i*12+8)}={nested(self.u32(at+i*12+4))};" for i in range(count)) + "}"
        elif kind in (6, 19):
            stride = 8 if kind == 6 else 12
            values = []
            for i in range(count):
                pos = at + i*stride
                number = self.u32(pos + 4)
                if kind == 19:
                    number |= self.u32(pos + 8) << 32
                values.append(f"{self.name(self.u32(pos))}={number};")
            result = f"e{value}" + ("s{" if bits else "u{") + "".join(values) + "}"
        elif kind == 7:
            result = ("u" if bits else "s") + self.name(name)
        elif kind == 12:
            result = nested(value)
        elif kind == 13:
            result = "f" + nested(value) + "(" + "".join(nested(self.u32(at+i*8+4)) + ";" for i in range(count)) + ")"
        else:
            raise ValueError("Unsupported BTF ABI type")
        if len(result) > 65536:
            raise ValueError("BTF signature size")
        return result

    def function(self, name):
        signatures = {self.signature(index) for index in self.functions.get(name, [])}
        if len(signatures) != 1:
            raise ValueError("Missing/ambiguous function ABI: " + name)
        return signatures.pop()

    def variable(self, name):
        """The actual VAR's complete canonical type, not its ELF object class."""
        signatures = {self.signature(self.types[index][3])
                      for index in self.variables.get(name, [])}
        if len(signatures) != 1:
            raise ValueError("Missing/ambiguous variable ABI: " + name)
        return signatures.pop()

    def type_size(self, index):
        index = self.resolve(index)
        if not index:
            raise ValueError("Void has no object size")
        _, kind, _, value, _, at = self.types[index]
        if kind == 2:
            return 8
        if kind == 3:
            return self.type_size(self.u32(at)) * self.u32(at + 8)
        if kind in (1, 4, 5, 6, 19):
            return value
        raise ValueError("Unsupported BTF object size")

    def variable_members(self, name):
        """Actual object members in bytes; bitfields and duplicate VARs fail."""
        indexes = self.variables.get(name, [])
        if len(indexes) != 1:
            raise ValueError("Missing/ambiguous variable layout: " + name)
        return self.structure_members(self.types[indexes[0]][3])

    def typedef_members(self, name):
        indexes = [index for index, entry in enumerate(self.types)
                   if entry and entry[1] == 8 and self.name(entry[0]) == name]
        if len(indexes) != 1:
            raise ValueError("Missing/ambiguous typedef layout: " + name)
        return self.structure_members(indexes[0])

    def named_structure_members(self, name):
        indexes = [index for index, entry in enumerate(self.types)
                   if entry and entry[1] == 4 and self.name(entry[0]) == name]
        if len({self.signature(index) for index in indexes}) != 1:
            raise ValueError("Missing/ambiguous named structure layout: " + name)
        return self.structure_members(indexes[0])

    def named_structure_selected(self, name, selected):
        """Required fields, including C anonymous aggregates, with real offsets."""
        selected = set(selected)
        indexes = [index for index, entry in enumerate(self.types)
                   if entry and entry[1] == 4 and self.name(entry[0]) == name]
        layouts = []
        for root in indexes:
            fields, root_bytes = {}, self.types[root][3]

            def visit(index, base, active, inherited_bitfield=False, limit=None):
                index = self.resolve(index)
                if index in active or len(active) >= 32:
                    raise ValueError("Anonymous BTF aggregate cycle: " + name)
                _, kind, count, aggregate_bytes, bits, at = self.types[index]
                if kind not in (4, 5):
                    raise ValueError("Anonymous BTF member is not an aggregate: " + name)
                active = active | {index}
                limit = min(root_bytes * 8 if limit is None else limit, base + aggregate_bytes * 8)
                for i in range(count):
                    pos = at + i * 12
                    label, member_type = self.name(self.u32(pos)), self.u32(pos + 4)
                    raw = self.u32(pos + 8)
                    bitfield = bool(bits and raw >> 24)
                    offset = base + (raw & 0xffffff if bits else raw)
                    if label in selected:
                        if inherited_bitfield or bitfield or offset % 8 or label in fields:
                            raise ValueError("Bitfield/ambiguous required BTF member: " + name + "." + label)
                        size = self.type_size(member_type)
                        if size <= 0 or offset < 0 or offset + size * 8 > limit:
                            raise ValueError("Required BTF member outside structure: " + name + "." + label)
                        fields[label] = {"offset": offset // 8, "bytes": size,
                                         "signature": self.signature(member_type)}
                    elif not label:
                        resolved = self.resolve(member_type)
                        if resolved and self.types[resolved][1] in (4, 5):
                            visit(resolved, offset, active, inherited_bitfield or bitfield, limit)

            visit(root, 0, set())
            if fields.keys() != selected:
                raise ValueError("Missing required BTF structure members: " + name)
            layouts.append({"bytes": root_bytes, "signature": self.signature(root), "members": fields})
        if not layouts or any(item != layouts[0] for item in layouts[1:]):
            raise ValueError("Missing/ambiguous selected BTF structure: " + name)
        return layouts[0]

    def structure_members(self, index):
        index = self.resolve(index)
        _, kind, count, size, bits, at = self.types[index]
        if kind != 4:
            raise ValueError("BTF type is not a structure")
        members = {}
        for i in range(count):
            pos = at + i * 12
            label, member_type, offset = self.name(self.u32(pos)), self.u32(pos + 4), self.u32(pos + 8)
            if bits and offset >> 24 or offset % 8 or label in members:
                raise ValueError("Bitfield/ambiguous structure member: " + label)
            members[label] = {"offset": offset // 8, "bytes": self.type_size(member_type),
                              "signature": self.signature(member_type)}
        return {"bytes": size, "signature": self.signature(index), "members": members}

    def resolve(self, index):
        for _ in range(64):
            if not index or self.types[index][1] not in (8, 9, 10, 11, 18):
                return index
            index = self.types[index][3]
        raise ValueError("BTF modifier cycle")

    def function_parameter(self, name, parameter):
        """Preserve the pointer and the probe's own return type."""
        signatures = set()
        for index in self.functions.get(name, []):
            proto = self.types[self.resolve(self.types[index][3])]
            if proto[1] != 13 or parameter < 0 or parameter >= proto[2]:
                raise ValueError("Missing function parameter ABI: " + name)
            signature = self.signature(self.u32(proto[5] + parameter * 8 + 4))
            if not signature.startswith("*f"):
                raise ValueError("Non-callback function parameter ABI: " + name)
            signatures.add(signature)
        if len(signatures) != 1:
            raise ValueError("Missing/ambiguous function parameter ABI: " + name)
        return signatures.pop()

    def typedef_function(self, name):
        signatures = {self.signature(index) for index, entry in enumerate(self.types)
                      if entry and entry[1] == 8 and self.name(entry[0]) == name}
        if len(signatures) != 1 or not next(iter(signatures)).startswith("*f"):
            raise ValueError("Missing/ambiguous callback typedef ABI: " + name)
        return signatures.pop()

    def member_function(self, owner, member):
        """Canonical callback field ABI, including its function-pointer '*'."""
        signatures = set()
        for entry in self.types[1:]:
            name, kind, count, value, bits, at = entry
            if kind != 4 or self.name(name) != owner:
                continue
            found = 0
            for i in range(count):
                offset = at + i * 12
                if self.name(self.u32(offset)) != member:
                    continue
                found += 1
                if bits and self.u32(offset + 8) >> 24:
                    raise ValueError("Bitfield callback ABI: " + owner + "." + member)
                signature = self.signature(self.u32(offset + 4))
                if not signature.startswith("*f"):
                    raise ValueError("Non-function-pointer callback ABI: " + owner + "." + member)
                signatures.add(signature)
            if found != 1:
                raise ValueError("Missing/ambiguous callback member: " + owner + "." + member)
        if len(signatures) != 1:
            raise ValueError("Missing/ambiguous callback ABI: " + owner + "." + member)
        return signatures.pop()
