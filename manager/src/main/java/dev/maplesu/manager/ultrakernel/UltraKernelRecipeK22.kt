package dev.maplesu.manager.ultrakernel

/**
 * The k22 recipe, embedded so the app can generate a Ultra plan without a shipped asset.
 *
 * Why a constant instead of an asset: the app's `assets/` tree is the *catalogue* (release-indexed,
 * digest-gated, one spec per release), and a recipe is not a spec - it carries no offset and no
 * address, only symbol locators. Keeping it next to the renderer means a generated plan can never
 * be produced from a recipe that the catalogue did not review.
 *
 * Derived from `tools/specgen/specgen/recipes/k22.json`, which retains the historical reference
 * blobs as an oracle. The production recipe uses generated bodies and resolves packed AVC fields
 * from the target kernel; copying the oracle over this constant would discard those corrections.
 * Keep [K22_RECIPE_SHA256] in sync with [K22_RECIPE_JSON] (UTF-8, no trailing newline).
 *
 * This recipe is release independent. Its code records name a body that
 * [UltraKernelBodies] assembles from this kernel's own symbol offsets, `task_struct` field offsets and
 * site addresses; the remaining records use field rules (`init_path`, `credential`, branch
 * and one-instruction stubs). **No record carries machine code**, which is what makes the same
 * recipe valid on 6.1/6.6/6.12 instead of only on the build the reference payload was compiled for.
 * A plan generated from it is still `experimental` and is never reported as `verified`: nothing
 * local can substitute for the one boot that label requires.
 */
internal const val K22_RECIPE_JSON: String = """{
  "schema": 1,
  "id": "k22",
  "note": "Nine records are assembled on device from `code` body ids (see UltraKernelBodies); the other nine are assembled from field rules. No record carries machine code any more. Derived from k22-ultra-6.6.89.spec by tools/specgen/derive_recipe.py.",
  "referenceKernelRelease": "6.6.89-android15-8-g7e1f3c083cc6-abogki467167594-4k",
  "credential": {
    "length": 48,
    "initPathTemplate": "/data/{key16}/init"
  },
  "records": [
    {
      "role": "die+0x0",
      "code": "execve-gate",
      "site": {
        "symbol": "die",
        "delta": 0
      },
      "length": 272,
      "referenceOrigSha256": "9320d65fecf25cc23728fdbcc79480579bad8f2c20754427d2f8480a3a1ab3f3",
      "space": "symbol",
      "cave": "die"
    },
    {
      "role": "die+0xD4",
      "code": "execve-tail",
      "site": {
        "symbol": "die",
        "delta": 272
      },
      "length": 16,
      "referenceOrigSha256": "73c1c2737fa165ccab7f77a6fe92a971f073aa097e555ec547975b3ece8f30ae",
      "space": "symbol",
      "cave": "die"
    },
    {
      "role": "arm64_notify_die+0x0",
      "code": "execve-frame",
      "site": {
        "symbol": "arm64_notify_die",
        "delta": 0
      },
      "length": 52,
      "referenceOrigSha256": "3e162151c8eb06cdd009cbf8011e570ad7061a3cae5241d62a8f1136616b3431",
      "space": "symbol",
      "cave": "arm64_notify_die"
    },
    {
      "role": "free_initmem+0x0",
      "site": {
        "symbol": "free_initmem",
        "delta": 0
      },
      "length": 58,
      "relocs": [
        {
          "at": 0,
          "kind": "word",
          "op": "ret"
        },
        {
          "at": 4,
          "kind": "u32_self",
          "delta": 4
        },
        {
          "at": 8,
          "kind": "u32_target",
          "target": {
            "symbol": "kallsyms_lookup_name",
            "delta": 0
          }
        },
        {
          "at": 12,
          "kind": "init_path",
          "length": 28
        },
        {
          "at": 40,
          "kind": "u32_target",
          "target": {
            "symbol": "do_execveat_common",
            "delta": 0
          }
        },
        {
          "at": 44,
          "kind": "avc_info",
          "target": {
            "symbol": "avc_denied",
            "delta": 0
          }
        },
        {
          "at": 52,
          "kind": "u32_target",
          "target": {
            "symbol": "filldir64",
            "delta": 0
          }
        },
        {
          "at": 56,
          "kind": "u16_struct",
          "name": "task_struct.seccomp"
        }
      ],
      "note": "pure data record, assembled from fields",
      "referenceOrigSha256": "08283291be29546858850df46b1c76711548fe8380356d0566651def93a137dc",
      "space": "symbol",
      "cave": "free_initmem"
    },
    {
      "role": "report_cfi_failure+0x0",
      "optional": true,
      "site": {
        "symbol": "report_cfi_failure",
        "delta": 0
      },
      "length": 8,
      "relocs": [
        {
          "at": 0,
          "kind": "word",
          "op": "movz",
          "rd": 0,
          "imm": 1,
          "sf": 1
        },
        {
          "at": 4,
          "kind": "word",
          "op": "ret"
        }
      ],
      "note": "one-instruction stub, assembled from ops",
      "referenceOrigSha256": "cb76cf07cf50f4687f6471e93d2a05ca26c33fdda97d1b17601dd6b074563848",
      "space": "symbol"
    },
    {
      "role": "free_reserved_area+0x0",
      "site": {
        "symbol": "free_reserved_area",
        "delta": 0
      },
      "length": 8,
      "relocs": [
        {
          "at": 0,
          "kind": "word",
          "op": "mov_wzr",
          "rd": 0
        },
        {
          "at": 4,
          "kind": "word",
          "op": "ret"
        }
      ],
      "note": "one-instruction stub, assembled from ops",
      "referenceOrigSha256": "b1aa0cbdb237837ffd242b0331fd8442cce21ae169321273a1e8fa9c4be8064c",
      "space": "symbol"
    },
    {
      "role": "do_execveat_common+0x0",
      "site": {
        "symbol": "do_execveat_common",
        "delta": 0
      },
      "length": 4,
      "relocs": [
        {
          "at": 0,
          "kind": "branch",
          "op": "b",
          "target": {
            "symbol": "arm64_notify_die",
            "delta": 24
          }
        }
      ],
      "note": "pure data record, assembled from fields",
      "referenceOrigSha256": "f42188d81718c4fb96428ed4d432fc815af923c9786e982c05344cc30fa371ac",
      "space": "symbol"
    },
    {
      "role": "avc_denied+0x28",
      "site": {
        "symbol": "avc_denied",
        "delta": 40
      },
      "length": 4,
      "relocs": [
        {
          "at": 0,
          "kind": "branch",
          "op": "b",
          "target": {
            "symbol": "drm_dev_printk",
            "delta": 36
          }
        }
      ],
      "note": "pure data record, assembled from fields",
      "referenceOrigSha256": "110f46b5b35c069160560c6ad6786f647dd44e8760a52a46fc22dbbcd7630b91",
      "space": "symbol"
    },
    {
      "role": "__drm_puts_coredump+0x0",
      "code": "puts-guide",
      "site": {
        "symbol": "__drm_puts_coredump",
        "delta": 0
      },
      "length": 88,
      "referenceOrigSha256": "cfd4728e688f9cde5f7e411746e1f2d3d48ac8cdb87d312926114706e4a8ae96",
      "space": "symbol",
      "cave": "__drm_puts_coredump"
    },
    {
      "role": "__drm_printfn_coredump+0x0",
      "code": "printfn-bracket",
      "site": {
        "symbol": "__drm_printfn_coredump",
        "delta": 0
      },
      "length": 188,
      "referenceOrigSha256": "094fdb9096a73c38c00871c0abf1c06fd8e7b37cf7205dbc87fe80a762dd7fc4",
      "space": "symbol",
      "cave": "__drm_printfn_coredump"
    },
    {
      "role": "drm_dev_printk+0x0",
      "code": "printk-flush",
      "site": {
        "symbol": "drm_dev_printk",
        "delta": 0
      },
      "length": 108,
      "referenceOrigSha256": "d3a8d010c9d4cf0dba427c2e3149f75e885f412e696773713bf26cf1366eb796",
      "space": "symbol",
      "cave": "drm_dev_printk"
    },
    {
      "role": "__dev_printk+0x0",
      "code": "dev-printk",
      "site": {
        "symbol": "__dev_printk",
        "delta": 0
      },
      "length": 84,
      "referenceOrigSha256": "f472ebd0dc356cd46101ad92e3fdfe484e3a66d12e0f858504795ce7f9f31e8b",
      "space": "symbol",
      "cave": "__dev_printk"
    },
    {
      "role": "panic+0x0",
      "site": {
        "symbol": "panic",
        "delta": 0
      },
      "length": 48,
      "relocs": [
        {
          "at": 0,
          "kind": "credential",
          "length": 48
        }
      ],
      "note": "pure data record, assembled from fields",
      "referenceOrigSha256": "63ce73dc81ea9d96814f3104bd6bc3845fd680b8a2860084940905d803a15b0d",
      "space": "symbol",
      "cave": "panic"
    },
    {
      "role": "__traceiter_kvm_userspace_exit+0x70",
      "site": {
        "symbol": "__traceiter_kvm_userspace_exit",
        "delta": 112
      },
      "length": 54,
      "relocs": [
        {
          "at": 0,
          "kind": "u32_self",
          "delta": 0
        },
        {
          "at": 4,
          "kind": "u32_target",
          "target": {
            "symbol": "kallsyms_lookup_name",
            "delta": 0
          }
        },
        {
          "at": 8,
          "kind": "init_path",
          "length": 28
        },
        {
          "at": 36,
          "kind": "u32_target",
          "target": {
            "symbol": "do_execveat_common",
            "delta": 0
          }
        },
        {
          "at": 40,
          "kind": "avc_info",
          "target": {
            "symbol": "avc_denied",
            "delta": 0
          }
        },
        {
          "at": 48,
          "kind": "u32_target",
          "target": {
            "symbol": "filldir64",
            "delta": 0
          }
        },
        {
          "at": 52,
          "kind": "u16_struct",
          "name": "task_struct.seccomp"
        }
      ],
      "note": "pure data record, assembled from fields",
      "referenceOrigSha256": "eeeb6fb37f08308037bc69fe75dcdd2c0314caac7dbd6c16b920f8a6f55c952e",
      "space": "slot",
      "cave": "__traceiter_kvm_userspace_exit",
      "slotExpectedSha256": "eeeb6fb37f08308037bc69fe75dcdd2c0314caac7dbd6c16b920f8a6f55c952e",
      "slotAcceptedSha256": [
        "c539d2c8694f94a4512b34f7cd24432b5f5f44d384ca404aa16878d34933d992",
        "357a9a545b3c47ab16f992012a4f690f21e080bc360b18d9edc681f93f901758"
      ]
    },
    {
      "role": "drm_dev_printk+0x5C",
      "site": {
        "symbol": "drm_dev_printk",
        "delta": 92
      },
      "length": 8,
      "relocs": [
        {
          "at": 0,
          "kind": "word",
          "op": "nop"
        },
        {
          "at": 4,
          "kind": "word",
          "op": "nop"
        }
      ],
      "note": "one-instruction stub, assembled from ops",
      "referenceOrigSha256": "507d1a8aeeda81c602d1bd9f27b1d0256542e0b34b9cffcab1939713f8440d85",
      "space": "symbol",
      "cave": "drm_dev_printk"
    },
    {
      "role": "drm_dev_printk+0x34",
      "site": {
        "symbol": "drm_dev_printk",
        "delta": 52
      },
      "length": 4,
      "relocs": [
        {
          "at": 0,
          "kind": "branch",
          "op": "b",
          "target": {
            "symbol": "drm_dev_printk",
            "delta": 100
          }
        }
      ],
      "note": "pure data record, assembled from fields",
      "referenceOrigSha256": "7d29a87084b2e7073448796a6dd209760002a0340ccee730c4558c451dee8599",
      "space": "symbol",
      "cave": "drm_dev_printk"
    }
  ]
}"""

/** sha256 of [K22_RECIPE_JSON]; update together with the embedded recipe. */
internal const val K22_RECIPE_SHA256: String = "0b2e2b5bc87ff553ddac0f266e220b271124dd6cd546d58778a1bef81884368f"
