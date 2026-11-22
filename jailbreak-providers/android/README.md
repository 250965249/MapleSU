# Android raw root lease transport

Manager includes this directory's production and test source sets. It implements
the App-side transport for `../lease/src/root_consumer.cpp`; provider acquisition,
authorization, restoration and runtime ownership belong to their respective
adapters and services. See the [integration contract](../INTEGRATION.md).

## Ownership and wire contract

1. On an IO thread, call `RootShellLease.prepare(Provider)` from the ordinary App
   UID. It reads the current boot ID, creates a random abstract `maplesu-jb-UUID`
   listener and generates a 32-byte random nonce **before** an external provider
   is launched.
2. `PendingLease.consumerArgv(executable)` exposes the executable plus exactly
   `ENDPOINT NONCE_HEX MANAGER_UID BOOT_ID ghostlock|dirtyfrag`. Treat nonce-bearing
   argv as attempt secrets; do not put them in diagnostic logs. This class does
   not launch any provider or consumer.
3. `await(timeout, unit)` accepts one connection, verifies `SO_PEERCRED` UID 0
   and PID > 1, then checks `MJBL`, BE32 version 1/provider/PID/UID, nonce (constant
   time), length-bounded boot ID/domain and BE32 enforcing/seccomp. Announced
   worker PID/UID must match the kernel-reported peer.
4. Send byte `A` and exactly three ancillary descriptors from separate pipes:
   shell stdin read end, stdout write end, stderr write end. Remote ends close
   after transfer; local ends become the Process streams. Profile/ACK and
   provider logs never share these pipes or the control socket.
5. Only `R` + BE32 fresh child PID confirms shell exec. The returned
   `RootShellLease` is a `java.lang.Process` that the runtime adapter can supervise.
   Stage remains `RAW_ROOT_LEASE`.
6. `X` + BE32 exit code is the only successful completion frame. Control EOF,
   truncation or malformed frames make `waitFor`/`exitValue` raise an explicit
   `IllegalStateException("LEASE_CONTROL_FAILED", cause)`; they do not become
   exit 0. Close/destroy cancels through control EOF, which the consumer treats
   as process-group cancellation. Caller owns and must close the lease.

Close/destroy also completes Process waiters immediately with an explicit
cancellation failure, independently of the monitor thread unblocking. Socket
shutdown is requested before close; cross-thread Android socket/FD cancellation
and native process-group termination still require device verification.

The pending object is single-await and has a deadline covering accept,
handshake, descriptor transfer and exec acknowledgement. Timeout/cancel/failure
closes listener, accepted socket and owned pipe descriptors. Closing a pending
object after successful transfer does not close the returned lease. Normal
shell exit keeps stdout/stderr available for draining until the lease is closed.

## Remaining gates

Host tests do not exercise Android transport, FD transfer or device integration.
Authenticating a UID-0 peer is not proof of restored policy, required capability
set, namespace suitability, daemon readiness or third-party SU readiness.
The consumer observes enforcing/domain/seccomp only; original-policy recovery,
OEM/checkreqprot/domain/label observations and no persistent MapleSU policy
additions still require the separate current contract acceptance. Manager
handoff, lifecycle verification and trusted no-partition-write mode enforcement
require separate device acceptance for each release.

## Independent host checks (no Gradle)

Set `JAVA_HOME` to JDK 21 and `ANDROID_HOME` to the Android SDK:

```powershell
$javac = "$env:JAVA_HOME/bin/javac.exe"
$java = "$env:JAVA_HOME/bin/java.exe"
$androidJar = "$env:ANDROID_HOME/platforms/android-37/android.jar"
$src = 'jailbreak-providers/android/src'
$out = 'build/lease-java'
New-Item -ItemType Directory -Force -Path "$out/android", "$out/host" | Out-Null
& $javac --release 21 -Xlint:all -Werror -cp $androidJar -d "$out/android" "$src/main/java/dev/maplesu/manager/jailbreak/LeaseProtocol.java" "$src/main/java/dev/maplesu/manager/jailbreak/RootShellLease.java"
& $javac --release 21 -Xlint:all -Werror -d "$out/host" "$src/main/java/dev/maplesu/manager/jailbreak/LeaseProtocol.java" "$src/test/java/dev/maplesu/manager/jailbreak/LeaseProtocolHostTest.java"
& $java -cp "$out/host" dev.maplesu.manager.jailbreak.LeaseProtocolHostTest
```
