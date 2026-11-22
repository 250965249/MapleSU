# MapleSU root-loader kernel ABI contract

`contracts/<uname>.json` is the kernel ABI that `jailbreak-providers/root-loader/module/`
is compiled against and that the loader gate checks:

* `module/kernel_compat.h` declares three kernel structures with hand-written layouts
  (no kernel headers, no kernel tree — NDK only). Every one of those numbers is a
  *claim* that this contract checks against the image.
* `module/root_glue.S.in` hand-writes `struct module` (`.gnu.linkonce.this_module`) and
  `__versions` because there is no kbuild and no modpost.
* The build/verify scripts of step 2 consume the JSON, never a literal offset table.

Current artifact: **`6.6.89-android15-8-g7e1f3c083cc6-abogki467167594-4k.json`**
(49 028 bytes as written by the run in §7 — read the sha256 and the size from a fresh
run rather than from this file; both are printed by the generator).

---

## 1. Regenerate

Run from the repository root with the exact uncompressed kernel Image and a
matching kallsyms TSV. The device inputs are supplied separately.

```shell
python jailbreak-providers/root-loader/contracts/derive_contract.py --image IMAGE --symbols SYMBOLS --out build/contract.json
python jailbreak-providers/root-loader/contracts/derive_contract.py --image IMAGE --symbols SYMBOLS --out build/contract-a.json
python jailbreak-providers/root-loader/contracts/derive_contract.py --image IMAGE --symbols SYMBOLS --out build/contract-b.json
python jailbreak-providers/root-loader/contracts/derive_contract.py --image IMAGE --symbols SYMBOLS --inspect kprobe selinux_state
```

Compare the two output SHA-256 values to verify deterministic generation. Input
image and symbol identities must match the contract being maintained.

Exit codes: `0` contract written and every ABI claim matched; `2` contract written but
at least one ABI claim **mismatched** (the contract carries the truth, the module source
needs fixing — see `abiChecks`); `1` the evidence itself is unusable (no `.BTF`, no
`struct module`, no IKCONFIG blob).

The script has no network access, no third-party imports (stdlib only) and no literal
kernel address: it re-parses `.BTF` and the image bytes on every run. The only kernel
numbers written down in it are the *claims of the module source* (0x600, +0x188, +0x28,
0x36b1c5a6 as a last-resort fallback), and each of those is either checked against BTF
or flagged when it cannot be confirmed.

---

## 2. Where each value comes from

Four sources, and every field says which one it is:

| # | Source | What it proves | Fields |
|---|---|---|---|
| 1 | **image `.BTF`** (`struct`/`FUNC` records) | structure sizes, member order, byte offsets, which functions exist | `thisModule`, `kprobe`, `selinuxState`, `structOffsets.subprocessInfo`, `btf`, `abiChecks.claims` |
| 2 | **image bytes** | vermagic string, the kCFI type id immediate | `vermagic*`, `kcfiInitTypeId`, `kcfiProvenance` |
| 2b | **image bytes** (embedded `IKCONFIG`) | the authoritative `CONFIG_*` values, including the two `CONFIG_STATIC_USERMODEHELPER*` strings | `config`, `configProvenance` |
| 3 | **kallsyms TSV** | symbol presence/type/address, `__ksymtab` vs `__ksymtab_gpl` class | `requiredSymbols`, `optionalSymbols`, `forbiddenSymbolsAbsent`, `runtimeLookups`, `exportTable`, `symbolListCoverage`, `addressSpace` |
| 4 | **module sources** | what the C/asm actually claims | `abiChecks` (claims + `documentationDefects`), `helperPathPolicy.moduleConstant` |

Everything is image-derived; nothing is release knowledge. Point the script at another
image with its own symbol list and it emits that image's contract, or fails loudly.

### 2.1 BTF-derived

`.BTF` starts at image offset `0x16f3980` (140 925 types, 2 481 277 string bytes).
Parsed with the kernel's own encoding (`kernel/bpf/btf.c`): 12-byte header per type,
`kind`/`vlen`/`kflag` in `info`, 12 bytes per member, bit offsets in `member.offset`.

`abiChecks.claims[]` holds the machine comparison of *source claim* vs *BTF truth*, with
the quoted source line. `abiChecks.status` is `match` or `mismatch`.

### 2.2 Image-byte-derived

* **vermagic** — the image contains exactly one
  `" SMP preempt mod_unload modversions aarch64\0"` tail at `0x10b36a3`; scanning back to
  the first non-printable byte gives the string at **`0x10b3670`** (same rule as
  `ir-loader/tests/loader_contract.py:kernel_vermagic`). `vermagicSuffix` is what
  `same_magic()` compares once a module carries `__versions`.
* **kCFI init type id** — clang emits a six-instruction check in front of indirect calls:
  `movk w17,#lo / movk w17,#hi,lsl#16 / cmp / b.eq +8 / brk / blr`. The generator scans
  the whole image for that shape; the site inside `do_one_initcall` (symbol offset
  `0x14adc`, next symbol at `0x14e3c`) decodes to `0x36b1c5a6`. `kcfiProvenance.provenance`
  is `image-bytes` when the scan succeeds and `carried-from-prior-evidence` when it does
  not (then the value is only the old `ir-loader/contract.json` number and must not ship).
* **CONFIG_*** — the image embeds its own `.config` (`IKCFG_ST` at `0x1135568`, gzip,
  45 655 → 211 505 bytes). This is why `config.cfi`, `config.shadowCallStack`,
  `config.moduleSigForce`, … are facts and not folklore.

### 2.3 Symbol-table-derived

The TSV is `offset<TAB>type<TAB>name`, offsets image-relative (`_text` is 0). Two
properties are checked at runtime rather than assumed:

* `addressSpace.fileOffsetEqualsSymbolOffset` —
  `__start_BTF` (TSV line 80905) is at `24066432` = `0x16f3980`, exactly the `.BTF` magic
  file offset. Offsets and file positions are the same space, which is what lets the
  contract name the function containing a code offset.
* `exportTable` — an export's class is the range its `__ksymtab_<name>` address falls in:
  `[__start___ksymtab, __stop___ksymtab)` = `[23680544, 23720696)` is `EXPORT_SYMBOL`,
  `[__start___ksymtab_gpl, __stop___ksymtab_gpl)` = `[23720696, 23786516)` is
  `EXPORT_SYMBOL_GPL`. The bounds are the kernel's own linker symbols, and all 8 831
  `__ksymtab_*` entries land inside one of the two ranges (`entryCounts`, `outside: 0`),
  so nothing is a heuristic guess. `__stop___ksymtab == __start___ksymtab_gpl` confirms
  the two sections are adjacent, as the linker script lays them out.

`requiredSymbols[]` carries, per import, the function's own row and its `__ksymtab_` row
verbatim (`tsvLine`, `tsvText`), the section it lands in and `gplOnly`.

---

## 3. Schema

Top level, in file order. All offsets are integers plus a `*Hex` string for reading;
all sizes are bytes.

| field | meaning |
|---|---|
| `schemaVersion` | `1`. Bump only on an incompatible change. |
| `kind`, `module`, `description`, `license` | identity: `maplesu-root-loader-kernel-abi`, `maplesu_root`, GPL. |
| `kernelRelease` | first token of `vermagic` (the `uname -r` string). |
| `imagePath`, `imageSha256`, `imageBytes` | which image this contract describes. |
| `symbolsPath`, `numSymbols` | symbol source and its row count (106 142). |
| `vermagic`, `vermagicSuffix`, `vermagicProvenance` | exact string for `.modinfo`, the compared tail, and where the string was found. |
| `addressSpace` | proof that TSV offsets are file offsets. |
| `btf` | magic offset, header size, type/string byte counts, type count, blob size. |
| `symbolListCoverage` | what the symbol list can and cannot answer (see §4). |
| `thisModule` | `struct module`: size, `nameOffset`, `initOffset`, `exitOffset`, `archOffset`, all `members[]`. |
| `kprobe` | `struct kprobe`: size, `addrOffset`, `symbolNameOffset`, all `members[]`. |
| `selinuxState` | `struct selinux_state`: size, `enforcingOffset`, `initializedOffset`, all `members[]`, plus how the symbol can be reached. |
| `structOffsets` | `struct subprocess_info` as BTF declares it: size `0x70`, `path` **+0x38**, `argv`/`envp`/`wait`/`retval`, all `members[]`. This is the field the static-UMH fix writes, so G5's store check and G7's shim check both read it here instead of hard-coding `0x38`. |
| `exportTable` | the two `__ksymtab` ranges, their quoted TSV rows, entry counts. |
| `kcfiInitTypeId`, `kcfiProvenance` | the 4-byte prefix `init_module` must start with, and how it was derived. |
| `modinfo` | required `.modinfo` tags, where they are emitted (`module/root_glue.S.in`), and why `license=GPL` is not optional. |
| `requiredSymbols` | imports that must resolve, with export class. |
| `optionalSymbols` | imports allowed but not required (`memset`). |
| `forbiddenSymbolsAbsent` | names that must never appear as an import, with per-name row counts. `call_usermodehelper_setup`/`_exec` are here *and* in `runtimeLookups`: not importable, but resolvable by name. |
| `runtimeLookups` | names resolved at run time through `kallsyms_lookup_name` (never ELF imports), each with a verdict. |
| `config` | the `CONFIG_*` facts the design depends on, including `staticUsermodehelper` (`y`) and `staticUsermodehelperPath` (`""`). |
| `configProvenance` | where the config came from. |
| `helperPathPolicy` | D-5 helper path decision vs the constant in the C file. |
| `handover` | the fixed design decisions: `UMH_WAIT_EXEC` only; `primaryPath` (setup → write `subprocess_info.path` → exec) with its `pathOffset`; the `fallback` four-argument wrapper and the fact that it is dead on this image; `cleanup_module` is the restore point; return `0` means handed-over-and-resident **and is explicitly not proof the helper ran**. |
| `abiChecks` | source claims vs BTF, plus `documentationDefects`. |

### 3.1 The ABI numbers (all BTF-derived, all verified)

| item | value | BTF |
|---|---|---|
| `sizeof(struct module)` | **0x600** (1536) | type id 119 (also 22484, 23631 — identical layouts) |
| `module.name` | **+0x18**, `char[56]` | member of the above |
| `module.init` | **+0x188**, function pointer | |
| `module.exit` | **+0x5b8**, function pointer | |
| `module.arch` | **+0x3b8**, `struct mod_arch_specific` | |
| `sizeof(struct kprobe)` | **0x80** | type id 4887 |
| `kprobe.addr` | **+0x28** | |
| `kprobe.symbol_name` | **+0x30** | |
| `sizeof(struct selinux_state)` | **0x80** | type id 21039 |
| `selinux_state.enforcing` | **+0x00**, `bool` | |
| `selinux_state.initialized` | **+0x01**, `bool` | |
| `sizeof(struct subprocess_info)` | **0x70** | type id 3405 |
| `subprocess_info.path` | **+0x38**, `char *` | the byte the static-UMH fix writes |
| `subprocess_info.argv` / `envp` | **+0x40** / **+0x48** | asserted to follow `path` |
| `kcfiInitTypeId` | **0x36b1c5a6** | image bytes, `do_one_initcall` site |

`selinux_state` is the one worth spelling out, because it is the byte the module
writes and a wrong offset there is a silent corruption of the policy mutex:

```
+0x00 enforcing                bool          <- written by the module
+0x01 initialized              bool
+0x02 policycap                bool[8]       -> 0x0a
+0x0a android_netlink_route    bool          (vendor field)
+0x0b android_netlink_getneigh  bool          (vendor field)
+0x10 status_page              struct page *
+0x18 status_lock              struct mutex  -> 0x48
+0x48 policy                   struct selinux_policy __rcu *
+0x50 policy_mutex             struct mutex  -> 0x80
```

Five bools sit between `enforcing` and the first pointer, so the "obvious" layout
(`{bool enforcing; bool initialized; ...}`) is one pointer-width mistake away from
clobbering `status_lock`. That is exactly why this offset is read from BTF and not
from a header or from memory.

### 3.2 Why `license=GPL`

`register_kprobe` and `unregister_kprobe` are in `__ksymtab_gpl` (proved in §2.3), so a
module without `license=GPL` cannot resolve them: the loader looks up GPL-only symbols
with `gplok=false` and fails the import. `_printk`, `call_usermodehelper` and `memset`
are in the plain `__ksymtab` and would resolve either way. `modinfo.licenseRationale`
records both lists, so the constraint is traceable to the image rather than to a habit.

---

## 3.3 Why the static-UMH values are in the contract

`CONFIG_STATIC_USERMODEHELPER=y` plus `CONFIG_STATIC_USERMODEHELPER_PATH=""` (both read
from the image's own IKCONFIG) mean every `call_usermodehelper_setup()` call has its
`path` overwritten with the empty rodata string before `call_usermodehelper_exec()`
looks at it. Exec then sees a lone NUL and returns **0** without forking — a silent
no-op. That is not an opinion about the kernel; it is two `CONFIG_` values plus the
`struct subprocess_info` layout:

| field | value | consequence |
|---|---|---|
| `config.staticUsermodehelper` | `y` | the path comes from the build, not the caller |
| `config.staticUsermodehelperPath` | `""` | the build's path is empty, so the wrapper is dead |
| `structOffsets.subprocessInfo.path` | `0x38` | where `setup()` stores that empty string and where `exec()` reads it |

The module therefore resolves `call_usermodehelper_setup` and
`call_usermodehelper_exec` by name (they are in kallsyms, not in `__ksymtab`), calls
setup, writes its own path back at `subprocess_info.path`, and only then calls exec with
`UMH_WAIT_EXEC`. `handover.primaryPath` records that sequence and the offset it depends
on; `handover.fallback` records the four-argument wrapper and the fact that it cannot
exec on this image. G5 fails a module that carries only the wrapper, which is exactly
the defect this contract field set exists to make unrepresentable.

---

## 4. The `.bss` blind spot (why `selinux_state` says "unverified")

The symbol list is extracted from the image **file**. `.bss` is a `NOLOAD` section: it
occupies no file bytes, so every `.bss` object's address is at or past the end of the
file, and the extractor's `0 <= offset < len(image)` filter drops it.

Numbers this contract carries (`symbolListCoverage`): the highest listed symbol is
`0x22f6808`, EOF is `0x22f6a00`, i.e. 504 bytes of file left over. `.bss` is page
aligned and starts at `0x22f7000` (the decoder below shows `__bss_start` there, exactly
EOF + 0x600), so no `.bss` byte is in the file at all. 106 142 rows made it into the
list.

Consequence, applied per name in `runtimeLookups[]`:

* a **function** name absent from the list is genuinely absent from the kernel (all of
  `.text` is inside the file) — that is how the four vendor handlers are cleared;
* a **data** name absent from the list proves nothing: it may be a perfectly good
  `.bss` symbol. `selinux_state` is therefore `status: not-in-list-bss-possible`,
  `lookupResult: unverified`, `mustProbeOnDevice: true`.

A complete compressed-kallsyms decode can independently check BSS names. For the
recorded image, the cross-check yielded:

```
__bss_start   DATA 0xffffffc0822f7000     # offset 0x22f7000 = EOF (0x22f6a00) + 0x600
selinux_state BSS  0xffffffc0823490e0     # offset 0x23490e0, well past EOF
_end          BSS  0xffffffc082390000
```

So `kallsyms_lookup_name("selinux_state")` *does* resolve on this image; step 2 of
`maplesu_root.c` works. The contract still says `unverified` because it must be
regenerable from its declared inputs, and those inputs (an EOF-clipped list) cannot see
`.bss`. The generator refuses to launder a fact it cannot re-derive.

To make it definitive inside the contract, regenerate the symbol list without the
file-range filter (keep symbols whose address is past EOF) and point `--symbols` at it:
`symbolListCoverage.clippedAtEof` becomes `false` and the data-name verdicts become
`present`/`not-in-kallsyms` instead of `unverified`.

---

## 5. Findings recorded by this contract

1. **All ten ABI claims match** (`abiChecks.status = match`): `sizeof(struct module)`,
   its `name`/`init`/`exit` offsets, `sizeof(struct kprobe)` and `addr`/`symbol_name`,
   `sizeof(struct selinux_state)` and `enforcing`/`initialized`, and the glue's module
   size. Nothing in `kernel_compat.h` or `root_glue.S.in` needs to change for layout.
2. **Six naming defects** (`abiChecks.documentationDefects`) — sizes and offsets agree,
   only the field *names* in `kernel_compat.h` do not:
   `+0x00 +0x08` are `hlist` (not `pre_handler`/`post_handler`), `+0x10 +0x18` are
   `list` (not `fault_handler`/`ignored_handler`), `+0x20` is `nmissed` (not `opcode`),
   `+0x38` is `offset` (not `nokprobe_inline`). Harmless — the module zeroes the object
   and touches only `addr`/`symbol_name` — but the comments mislead the next reader
   (`kprobe.opcode` really lives at `+0x50`, `pre_handler` at `+0x40`).
3. **`helperPathPolicy` is a MISMATCH** (D-5): the module hard-codes
   `/data/user_de/0/dev.maplesu.manager/maplesu-bootstrap`
   (`maplesu_root.c:51-52`) while the App stages the helper at
   `/data/user_de/0/dev.maplesu.manager/bs`. As written, step 4 hands
   `call_usermodehelper()` a path that does not exist and `init_module` returns `-ENOENT`
   after restoring the enforcing byte. Step 2/3 fix; this contract does not touch the C.
4. **The four vendor handlers are not in this build** (`runtimeLookups`, `not-in-build`):
   no symbol row and no BTF `FUNC` for any of them, so step 3 is a no-op on this device
   and the `!= NULL` guard is doing the work. Matches decision D-3 in
   `docs/patching/maplesu-kernel-entry-design-2026-10-29.md:97`.
5. **`call_usermodehelper_setup` / `_exec` exist as code but are not exported**
   (1 symbol row each, 0 `__ksymtab_` rows): the four-argument
   `call_usermodehelper()` is the only way in, which is the design's premise.
   `security_setenforce` and `selinux_enforcing` are absent outright (0 rows).
6. **`register_kprobe` is GPL-only** — see §3.2.

---

## 6. What this contract deliberately does not contain

* **No address of any kernel function or global that the module would use.** There is
  no per-release offset table anywhere: the module resolves everything at run time
  through `kallsyms_lookup_name`. Addresses appear only as *evidence* attached to a
  symbol row (which symbol, which section, since when) and are never a build input.
  `selinux_state`'s `.bss` address is not in the file for the same reason.
* **No device state.** Nothing here was produced by loading, pushing or rebooting
  anything; every input is a file in this repository.
* **No `cleanup_module`/`UMH_WAIT_PROC` escape hatch.** `handover` pins
  `UMH_WAIT_EXEC` (value 1) and keeps `cleanup_module` as `this_module.exit`; changing
  either invalidates this contract.
* **No promise that `abiChecks` is complete.** It checks what the sources claim. A field
  the sources do not mention (for example `module.mem`, `module.refcnt`) is described in
  `members[]` but not asserted against anything.

---

## 7. Verification log

```bash
$ "$PY" jailbreak-providers/root-loader/contracts/derive_contract.py
contract: .../6.6.89-android15-8-g7e1f3c083cc6-abogki467167594-4k.json
  sha256  4bd4a0465ae9739e61595558709654aabe513a933e786bfef01c1e2da0d7b889 (49028 bytes)
  release 6.6.89-android15-8-g7e1f3c083cc6-abogki467167594-4k
  image   346d51ea1f63413ffa5d99c5c426806291af3573f0a1d66a7621c388e835880e (36661760 bytes)
  symbols 106142 rows, max offset 0x22f6808, clipped at EOF: True
  module  0x600 name@0x18 init@0x188 exit@0x5b8 arch@0x3b8
  kprobe  0x80 addr@0x28 symbol_name@0x30
  selinux 0x80 enforcing@0x0 initialized@0x1
  kcfi    0x36b1c5a6 (image-bytes, 15013 sites)
  abiChecks match (10 checked)
```

* two runs produce the same sha256 (`cmp` byte-identical), including with `--out`;
* the file is pure ASCII with `\n` newlines, so `json.load(open(path))` works even on a
  host whose default codec is GBK (the CJK quote in `helperPathPolicy.decisionQuote` is
  `\uXXXX`-escaped on purpose);
* `abiChecks.status` is `match`; the run above is the one recorded in this file.
