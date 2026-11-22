"""Inspect GNU/BSD ar members for native artifact verification."""
import hashlib
import os

AR_MAGIC = b"!<arch>\n"


GNU_SPECIAL_NAMES = ("/", "//", "/SYM64/")


class GateError(Exception):
    """A check that must make the process exit non-zero (exit code 1)."""


class UsageError(Exception):
    """Bad invocation or unreadable input (exit code 2)."""


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _decode_gnu_long_name(table, offset):
    end = table.find(b"/\n", offset)
    if end < 0:
        raise GateError("corrupt GNU long-name table: unterminated entry at %d" % offset)
    return table[offset:end].decode("utf-8", "surrogateescape")


def _normalise_gnu_name(raw):
    name = raw[:-1] if raw.endswith("/") else raw
    if not name:
        raise GateError("empty member name in archive header")
    return name


def parse_ar(path):
    """Parse a GNU/BSD ``ar`` archive into its real members.

    Returns a dict with:
      members        list of {ord, name, size, sha256, body_offset, raw_name}
      member_count   number of real members (special entries excluded)
      special        list of special entries seen ('/', '//', '/SYM64/')
      symbol_index   {present: bool, size: int, name: str|None}
      long_name_table_size
    """
    try:
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError as exc:
        raise UsageError("cannot read archive %s: %s" % (path, exc))

    if not data.startswith(AR_MAGIC):
        raise GateError("%s is not a GNU ar archive (bad magic)" % path)

    offset = len(AR_MAGIC)
    long_names = b""
    raw_entries = []
    special = []
    symbol_index = {"present": False, "size": 0, "name": None}

    while offset + 60 <= len(data):
        header = data[offset:offset + 60]
        if header[58:60] != b"`\n":
            raise GateError(
                "corrupt ar header at offset %d (missing terminator)" % offset
            )
        raw_name = header[0:16].decode("latin-1").rstrip()
        try:
            size = int(header[48:58].decode("latin-1").strip())
        except ValueError:
            raise GateError(
                "corrupt ar header at offset %d (bad size field %r)"
                % (offset, header[48:58])
            )
        if size < 0:
            raise GateError("negative member size at offset %d" % offset)
        body_offset = offset + 60
        body_end = body_offset + size
        if body_end > len(data):
            raise GateError(
                "member at offset %d declares %d bytes but archive ends at %d"
                % (offset, size, len(data))
            )
        body = data[body_offset:body_end]

        if raw_name in GNU_SPECIAL_NAMES:
            special.append(raw_name)
            if raw_name == "//":
                long_names = body
            elif raw_name == "/":
                symbol_index = {"present": True, "size": size, "name": "/"}
            elif raw_name == "/SYM64/":
                symbol_index = {"present": True, "size": size, "name": "/SYM64/"}
        else:
            raw_entries.append(
                {"raw_name": raw_name, "size": size, "body": body,
                 "body_offset": body_offset}
            )

        offset = body_end
        if offset % 2:
            offset += 1

    members = []
    for index, entry in enumerate(raw_entries):
        raw_name = entry["raw_name"]
        body = entry["body"]
        size = entry["size"]

        if raw_name.startswith("#1/"):
            # BSD long name: the name is stored at the front of the member body.
            try:
                name_len = int(raw_name[3:])
            except ValueError:
                raise GateError("bad BSD long name header %r" % raw_name)
            if name_len < 0 or name_len > len(body):
                raise GateError("BSD long name length %d exceeds member body" % name_len)
            name = body[:name_len].decode("utf-8", "surrogateescape").rstrip("\x00")
            payload = body[name_len:]
            payload_offset = entry["body_offset"] + name_len
            payload_size = size - name_len
        elif raw_name.startswith("/") and raw_name[1:].isdigit():
            name = _decode_gnu_long_name(long_names, int(raw_name[1:]))
            payload = body
            payload_offset = entry["body_offset"]
            payload_size = size
        else:
            name = _normalise_gnu_name(raw_name)
            payload = body
            payload_offset = entry["body_offset"]
            payload_size = size

        if not name:
            raise GateError("member %d resolved to an empty name" % index)

        members.append(
            {
                "ord": index,
                "name": name,
                "size": payload_size,
                "sha256": sha256_bytes(payload),
                "body_offset": payload_offset,
            }
        )

    return {
        "path": os.path.abspath(path),
        "file_sha256": sha256_file(path),
        "file_size": len(data),
        "members": members,
        "member_count": len(members),
        "special": special,
        "symbol_index": symbol_index,
        "long_name_table_size": len(long_names),
    }

