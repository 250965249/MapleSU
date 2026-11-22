#!/usr/bin/env python3
"""Check the current SDK-to-management P4 credential routing contract."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[4]
PATCH = ROOT / "runtime/maplesu-sdk/sdk/src/patch/patch_current.cpp"
REQUEST = ROOT / "runtime/maplesu-sdk/sdk/src/kernel_request/module_base_kernel_request.cpp"
MANAGEMENT = ROOT / "runtime/ultra/identity/kernel/manager_management.c"


def function(source: str, signature: str) -> str:
    start = source.index(signature)
    brace = source.index("{", start)
    depth = 1
    end = brace + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


def check(condition: bool, description: str) -> int:
    if not condition:
        raise AssertionError(description)
    return 1


def main() -> None:
    patch = PATCH.read_text(encoding="utf-8")
    request = REQUEST.read_text(encoding="utf-8")
    management = MANAGEMENT.read_text(encoding="utf-8")

    root = function(patch, "KModErr PatchCurrent::set_current_root(")
    caps = function(patch, "KModErr PatchCurrent::set_current_caps(")
    channel = function(request, "KModErr maplesu_request_credential_channel(")
    root_request = function(request, "KModErr maplesu_request_owner_root(")
    caps_request = function(request, "KModErr maplesu_request_owner_caps(")
    credentials = function(management, "static int msu_management_credentials(")
    dispatch = function(management, "void msu_management_dispatch(")

    checks = 0
    checks += check(
        root.index("maplesu_request_credential_channel") < root.index("if (managed)") <
        root.index("maplesu_request_owner_root") < root.index("execute_legacy_credential_frame"),
        "Root selects the typed path before legacy execution",
    )
    checks += check(
        "(capabilities & required) != required" in root and
        "MAPLESU_CAP_CREDENTIAL | MAPLESU_CAP_TASK_STATE" in root,
        "Root requires credential and task-state capability",
    )
    checks += check(
        root.index("if (is_failed(channel_error)) return channel_error") < root.index("if (managed)"),
        "Root query errors terminate before compatibility writes",
    )
    checks += check(
        caps.index("maplesu_request_credential_channel") < caps.index("if (managed)") <
        caps.index("maplesu_request_owner_caps") < caps.index("execute_legacy_credential_frame"),
        "CAPS selects the typed path before legacy execution",
    )
    checks += check(
        "MAPLESU_CAP_CREDENTIAL" in caps and
        caps.index("if (is_failed(channel_error)) return channel_error") < caps.index("if (managed)"),
        "CAPS requires the credential capability and propagates query errors",
    )
    checks += check(
        "if (!(response.result & MAPLESU_CAP_CREDENTIAL)) return KModErr::OK;" in channel and
        "managed = true;" in channel,
        "Only an explicit old-producer descriptor selects compatibility mode",
    )
    checks += check(
        "owner_manage(MAPLESU_REQUEST_CRED_ROOT" in root_request and
        "owner_manage(MAPLESU_REQUEST_CRED_CAPS" in caps_request,
        "Typed SDK requests use authenticated owner management transport",
    )
    checks += check(
        "case MAPLESU_REQUEST_CRED_ROOT:" in dispatch and
        "case MAPLESU_REQUEST_CRED_CAPS:" in dispatch and
        "msu_management_credentials(session, operation," in dispatch,
        "Native dispatch routes Root and CAPS to the shared credentials handler",
    )
    checks += check(
        "msu_credential_replace_current(root ? NULL : &caps" in credentials,
        "The management handler invokes the unique credential replacement core",
    )
    print(f"p4-credential-wiring checks={checks} passed")


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, ValueError) as error:
        print(f"p4-credential-wiring failed: {error}", file=sys.stderr)
        raise SystemExit(1)
