import os
from pathlib import Path
import shutil
import sys

NDK_VERSION = "26.1.10909125"
CMAKE_VERSION = "3.22.1"
#: NDK r28c, the toolchain the jailbreak providers are pinned to (maplesuProviderNdk in manager/build.gradle.kts).
PROVIDER_NDK_VERSION = "28.2.13676358"
#: The platform whose android.jar the host-side Kotlin and Java checks compile against.
ANDROID_PLATFORM = "android-37.0"
#: What provider_ndk() returns when nothing is configured. It does not exist, and its name says what to set.
UNSET_PROVIDER_NDK = "MAPLESU_PROVIDER_NDK_NOT_SET"


def sdk_home():
    value = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    if not value:
        raise SystemExit("Set ANDROID_HOME or pass the toolchain path explicitly")
    return Path(value).resolve()


def ndk_home(value=None):
    value = value or os.environ.get("ANDROID_NDK_HOME") or os.environ.get("ANDROID_NDK_ROOT")
    path = Path(value).resolve() if value else sdk_home() / "ndk" / NDK_VERSION
    if not (path / "build/cmake/android.toolchain.cmake").is_file():
        raise SystemExit("Android NDK is missing: " + str(path))
    return path


def tool(directory, name):
    path = Path(directory) / name
    if not path.is_file():
        raise SystemExit("Required tool is missing: " + str(path))
    return path


def ndk_bin(ndk):
    hosts = {"win32": "windows-x86_64", "darwin": "darwin-x86_64", "linux": "linux-x86_64"}
    if sys.platform not in hosts:
        raise SystemExit("Unsupported NDK host: " + sys.platform)
    path = ndk / "toolchains/llvm/prebuilt" / hosts[sys.platform] / "bin"
    if not path.is_dir():
        raise SystemExit("NDK host tools are missing: " + str(path))
    return path


def cmake_path(value=None):
    if value:
        path = Path(value)
        if not path.is_file():
            found = shutil.which(value)
            if not found:
                raise SystemExit("CMake is missing: " + value)
            path = Path(found)
        return path.resolve()
    sdk = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    suffix = ".exe" if os.name == "nt" else ""
    if sdk:
        candidate = Path(sdk) / "cmake" / CMAKE_VERSION / "bin" / ("cmake" + suffix)
        if candidate.is_file():
            return candidate.resolve()
    found = shutil.which("cmake")
    if not found:
        raise SystemExit("Install CMake 3.22.1 or pass --cmake")
    return Path(found).resolve()


# The helpers below never raise: they return a path that may not exist, so a test can skip when a tool is absent
# and a command-line default can fail later with the path in the message.


def sdk_dir():
    """The Android SDK named by ANDROID_HOME or ANDROID_SDK_ROOT, or None."""
    value = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    return Path(value) if value else None


def provider_ndk(value=None):
    """The NDK the jailbreak providers build with (r28c).

    Order: the argument, MAPLESU_PROVIDER_NDK, then <SDK>/ndk/28.2.13676358."""
    value = value or os.environ.get("MAPLESU_PROVIDER_NDK")
    if value:
        return Path(value)
    sdk = sdk_dir()
    return sdk / "ndk" / PROVIDER_NDK_VERSION if sdk else Path(UNSET_PROVIDER_NDK)


def jdk_tool(name="java"):
    """A JDK executable: $JAVA_HOME/bin/<name> when it exists, else the one on PATH, else the bare name."""
    home = os.environ.get("JAVA_HOME")
    if home:
        candidate = Path(home) / "bin" / (name + (".exe" if os.name == "nt" else ""))
        if candidate.is_file():
            return candidate
    return Path(shutil.which(name) or name)


def android_jar(platform=ANDROID_PLATFORM):
    """<SDK>/platforms/<platform>/android.jar, which may be absent; a bare relative name without an SDK."""
    sdk = sdk_dir()
    return (sdk / "platforms" / platform / "android.jar") if sdk else Path("android.jar")


def adb_tool(value=None):
    """adb: the argument, $ADB, <SDK>/platform-tools/adb, else the one on PATH."""
    value = value or os.environ.get("ADB")
    if value:
        return str(value)
    sdk = sdk_dir()
    if sdk:
        candidate = sdk / "platform-tools" / ("adb.exe" if os.name == "nt" else "adb")
        if candidate.is_file():
            return str(candidate)
    return shutil.which("adb") or "adb"
