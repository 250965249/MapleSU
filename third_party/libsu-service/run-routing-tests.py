"""Compile and exercise the actual routing helper without Android or Gradle."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

root = Path(__file__).resolve().parent
output = root / "host-test-results"
classes = output / "classes"
classes.mkdir(parents=True, exist_ok=True)
suffix = ".exe" if os.name == "nt" else ""


def jdk_tool(name):
    """$JAVA_HOME/bin/<name> when JAVA_HOME names a JDK, else the tool on PATH."""
    home = os.environ.get("JAVA_HOME")
    if home and (Path(home) / "bin" / (name + suffix)).is_file():
        return Path(home) / "bin" / (name + suffix)
    return Path(shutil.which(name) or name)


javac = jdk_tool("javac")
java = jdk_tool("java")
sources = [
    root / "src/main/java/com/topjohnwu/superuser/internal/RootServiceRouting.java",
    root / "src/test/java/com/topjohnwu/superuser/internal/RootServiceRoutingTest.java",
]
record = {
    "startedAt": datetime.now(timezone.utc).isoformat(),
    "scope": "host routing logic only; not Android Binder, receiver delivery, or lifecycle validation",
    "sourceSHA256": {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources},
    "passed": False,
    "commands": [],
}
logs = []
try:
    for command in [
        [str(javac), "--release", "8", "-d", str(classes), *map(str, sources)],
        [str(java), "-cp", str(classes), "com.topjohnwu.superuser.internal.RootServiceRoutingTest"],
    ]:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=45)
        logs.append(result.stdout.decode("utf-8", errors="replace"))
        record["commands"].append({"argv": command, "exitCode": result.returncode})
        if result.returncode:
            raise RuntimeError("Host command failed")
    record["passed"] = True
except Exception as error:
    record["error"] = str(error)
finally:
    record["finishedAt"] = datetime.now(timezone.utc).isoformat()
    (output / "routing.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    (output / "routing.log").write_text("\n".join(logs), encoding="utf-8")
print(json.dumps(record, indent=2))
print("\n".join(logs))
sys.exit(0 if record["passed"] else 1)
