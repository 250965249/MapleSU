"""Derive the payload layout contract from the target compiler's DWARF."""
import argparse
from contextlib import ExitStack
import json
from pathlib import Path

from elftools.elf.elffile import ELFFile

# Every structure allocated by the payload checks its full size. Access-only
# containers permit trailing OEM fields when the consumed offsets still agree.
FIELDS = {
    "selinux_state": (False, ["policy", "policy_mutex", "status_lock"]),
    "selinux_policy": (True, ["sidtab", "policydb", "latest_granting"]),
    "policy_file": (True, ["data", "len"]),
    "policydb": (True, ["symtab", "sym_val_to_name", "len", "class_val_to_struct", "type_val_to_struct",
        "role_val_to_struct", "type_attr_map_array", "permissive_map", "te_avtab", "te_cond_avtab",
        "process_class", "process_trans_perms", "role_allow", "allow_unknown"]),
    "sidtab": (True, []), "sidtab_entry": (False, ["context"]), "hashtab": (True, "*"),
    "context": (True, "*"), "mls_range": (True, "*"), "mls_level": (True, "*"),
    "ebitmap": (True, "*"), "ebitmap_node": (True, "*"), "symtab": (True, "*"),
    "role_datum": (True, "*"), "user_datum": (True, "*"), "type_datum": (True, "*"),
    "class_datum": (True, "*"), "constraint_node": (True, "*"), "constraint_expr": (True, "*"),
    "role_allow": (True, "*"), "avtab": (True, "*"), "avtab_key": (True, "*"),
    "avtab_node": (True, "*"), "avtab_datum": (True, "*"),
    "avtab_extended_perms": (True, "*"), "extended_perms": (True, "*"),
    "extended_perms_data": (True, "*"), "av_decision": (True, "*"),
    "mutex": (True, "*"), "ratelimit_state": (True, "*"),
    "lsm_blob_sizes": (False, ["lbs_cred"]),
    "selinux_kernel_status": (True, "*"), "page": (True, ["flags"]),
    "task_struct": (False, ["thread_info", "ptrace", "parent", "real_cred", "cred", "stack_canary", "mm", "signal", "thread_node"]),
    "signal_struct": (False, ["thread_head"]),
    "thread_info": (False, ["preempt_count"]),
    "cred": (False, ["uid", "security"]), "file": (False, ["private_data", "f_op"]),
    "vm_area_struct": (False, ["vm_start", "vm_end", "vm_pgoff", "vm_flags", "vm_page_prot", "vm_file"]),
    "mm_struct": (False, ["mmap_lock"]), "callback_head": (True, "*"),
    "sock": (False, ["__sk_common", "sk_protocol", "sk_uid"]),
    "sock_common": (False, ["skc_family"]),
    "sk_buff": (False, ["data", "len", "cb", "data_len"]),
    "netlink_skb_parms": (False, ["portid", "dst_group"]), "nlmsghdr": (True, "*"),
}

def type_size(die):
    for _ in range(32):
        if die.tag == "DW_TAG_pointer_type":
            return 8
        if "DW_AT_byte_size" in die.attributes:
            return die.attributes["DW_AT_byte_size"].value
        if die.tag == "DW_TAG_array_type":
            count = 1
            for child in die.iter_children():
                if child.tag == "DW_TAG_subrange_type":
                    if "DW_AT_count" in child.attributes:
                        count *= child.attributes["DW_AT_count"].value
                    elif "DW_AT_upper_bound" in child.attributes:
                        count *= child.attributes["DW_AT_upper_bound"].value + 1
                    else:
                        count = 0  # Flexible array member has no element bound.
            return count * type_size(die.get_DIE_from_attribute("DW_AT_type"))
        die = die.get_DIE_from_attribute("DW_AT_type")
    raise ValueError("cyclic DWARF type")

def members(die, prefix=0):
    result = {}
    for item in die.iter_children():
        if item.tag != "DW_TAG_member":
            continue
        offset = item.attributes.get("DW_AT_data_member_location")
        bits = item.attributes.get("DW_AT_data_bit_offset")
        width = item.attributes.get("DW_AT_bit_size")
        member_type = item.get_DIE_from_attribute("DW_AT_type")
        if bits:
            bit_offset = prefix + bits.value
        else:
            bit_offset = prefix + (offset.value if offset else 0) * 8
            old_bits = item.attributes.get("DW_AT_bit_offset")
            if old_bits:
                bit_offset += type_size(member_type) * 8 - old_bits.value - width.value
        name = item.attributes.get("DW_AT_name")
        if name:
            result[name.value.decode()] = dict(bit_offset=bit_offset,
                bit_size=width.value if width else type_size(member_type) * 8)
        elif member_type.tag in {"DW_TAG_structure_type", "DW_TAG_union_type"}:
            result.update(members(member_type, bit_offset))
    return result

def contract(paths):
    with ExitStack() as stack:
        types = {}
        for path in paths:
            elf = ELFFile(stack.enter_context(path.open("rb")))
            for cu in elf.get_dwarf_info().iter_CUs():
                for die in cu.iter_DIEs():
                    name = die.attributes.get("DW_AT_name")
                    if die.tag == "DW_TAG_structure_type" and name and "DW_AT_byte_size" in die.attributes:
                        types.setdefault(name.value.decode(), die)
        result = []
        for name, (full_size, selection) in FIELDS.items():
            die = types[name]
            available = members(die)
            fields = list(available) if selection == "*" else list(selection)
            if name == "policydb":
                fields.extend(f for f in ["android_netlink_route", "android_netlink_getneigh"] if f in available)
            if name == "task_struct" and "rcu_read_lock_nesting" in available:
                fields = [*fields, "rcu_read_lock_nesting"]
            if name == "mm_struct" and "mm_lock_seq" in available:
                fields = [*fields, "mm_lock_seq"]
            result.append(dict(name=name, size=type_size(die) if full_size else 0,
                               fields=[dict(name=field, **available[field]) for field in fields]))
        # Kernels 6.18+ rename the credential blob. Keep only the compiled type.
        for name in ["task_security_struct", "cred_security_struct"]:
            if name in types:
                result.append(dict(name=name, size=0, fields=[dict(name="sid", **members(types[name])["sid"])]))
                break
        else:
            raise ValueError("credential security layout is absent")
        return result

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("objects", nargs="+", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    data = contract(args.objects)
    args.output.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    lines = ['#pragma once', '#include "kernel_layout.h"',
             'inline std::vector<maplesu::module_policy::LayoutType> compiled_layout() { return {']
    for item in data:
        fields = ",".join('{"%s",%d,%d}' % (f["name"], f["bit_offset"], f["bit_size"]) for f in item["fields"])
        lines.append('{"%s",%d,{%s}},' % (item["name"], item["size"], fields))
    lines.append('}; }')
    args.output.with_suffix(".h").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"DWARF contract: {len(data)} types / {sum(len(t['fields']) for t in data)} fields")

if __name__ == "__main__":
    main()
