package dev.maplesu.manager.runtime.authorization

import java.nio.file.Paths

/**
 * One-shot authorization operation, executed as a short-lived root process.
 *
 * <p>Listing applications or reading the global switch must not require a resident root
 * executor. This tool is started through the same direct-admission path the client
 * delivery uses (one root process, exits immediately), applies exactly one operation on
 * the same [RootAuthorizationStore] and [PackageIdentityReader] the resident endpoint
 * would have used - no copy of that logic - prints one line and exits.
 *
 * <p>Since the one-authority change (design §3.2) this class is a thin entry point:
 * every operation goes through [SuperuserOps], i.e. through
 * [SuperuserTransaction]. That is what makes the UI's grant/revoke and the endpoints'
 * decisions share one journal, one revision and one ordering.
 *
 * <p>Since the seccomp fix (2026-10-31) the tool takes the audit path explicitly and
 * never creates an Android `Context`; see [SuperuserOps] for the crash it used to cause.
 *
 * <p>Usage: `AuthorizationTool <managerUid> <legacyFile> <auditFile> <op> [args...]` with
 * op one of `snapshot`, `status`, `enabled`, `count`, `has <uid>`, `grant <uid>`, `initialize-installation`,
 * `revoke <uid>`, `save-profile <base64-profile>`, `set-enabled:<true|false>`, `migrate <base64-plan>`,
 * `mark-applied <backend> <rev> <0|1> <detailBase64>`.
 * Output is one `OK ...` or `ERR ...` line and never contains credential material.
 */
object AuthorizationTool {
    @JvmStatic
    fun main(args: Array<String>) {
        try {
            require(args.size >= 4) { "AUTH_TOOL_ARGUMENTS" }
            val managerUid = args[0].toInt()
            val legacy = Paths.get(args[1])
            val audit = Paths.get(args[2])
            val operation = args[3]
            val extra = if (args.size > 4) args.drop(4) else emptyList()
            val payload = SuperuserOps.run(managerUid, legacy, audit, operation, extra)
            println("OK $payload")
        } catch (error: Throwable) {
            if (error is SuperuserOps.TransactionFailure) {
                println("ERR ${RootToolOutcome.failureReceipt(error.outcome)}")
            } else {
                val cause = generateSequence(error) { it.cause }
                    .map { it.javaClass.simpleName + ":" + it.message }
                    .joinToString(" <- ")
                println("ERR ${cause.replace('\n', ' ')}")
            }
        }
        System.out.flush()
        // app_process would otherwise keep waiting for the Android runtime to shut down.
        Runtime.getRuntime().halt(0)
    }
}

/**
 * The same entry point under the name the Ultra transport uses.
 *
 * <p>It exists as its own class so `CLASSPATH=<apk> app_process ... SuperuserTool ...`
 * reads as what it is - the Manager's superuser authority operation - while the
 * `AuthorizationTool` name keeps serving the code paths and tests that already use it.
 */
object SuperuserTool {
    @JvmStatic
    fun main(args: Array<String>) = AuthorizationTool.main(args)
}
