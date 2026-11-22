"""Source-only guards for independent Hook sessions; no compiler or device access."""
from pathlib import Path
import os
import unittest

ROOT = Path(os.environ.get("MAPLESU_SOURCE_ROOT", Path(__file__).resolve().parents[2]))
RUNTIME = ROOT / "manager/src/main/java/dev/maplesu/manager/runtime"


class HookQueueContract(unittest.TestCase):
    def test_hook_commands_keep_deadline_checks_without_waiting_for_sdk(self):
        router = (RUNTIME / "RootExecutionRouter.kt").read_text(encoding="utf-8-sig")
        admission = router.split("private fun executeSelected(", 1)[1].split("private fun executeOn(", 1)[0]
        isolated = admission.index("selected.singleOrNull()?.backend == RootBackend.HOOK")
        self.assertLess(admission.index("budget <= 0"), isolated)
        self.assertLess(admission.index("Thread.currentThread().isInterrupted"), isolated)
        self.assertLess(isolated, admission.index("executionLock.tryLock("))
        self.assertIn("return executeOn(script, selected)", admission)
        self.assertIn("finally { executionLock.unlock() }", admission)
        self.assertIn("executeOn(script, select())", admission)
        self.assertIn("executeSelected(script, ::executors)", router)
        self.assertIn("executeSelected(script) { listOfNotNull(hook) }", router)

    def test_native_hook_child_uses_the_page_budget(self):
        hook = (RUNTIME / "HookRootExecutor.kt").read_text(encoding="utf-8-sig")
        self.assertIn("PageReadDeadline.currentNanos()", hook)
        self.assertIn("remaining <= 0", hook)
        self.assertIn("minOf(timeoutMillis.toLong()", hook)
        self.assertIn("runScript(current, script, timeout)", hook)
        self.assertIn("NativeSu.FALLBACK_NAME), timeout)", hook)

    def test_parallel_execs_do_not_retain_other_commands_pipes(self):
        native = (ROOT / "manager/src/main/cpp/maplesu_su.c").read_text(encoding="utf-8-sig")
        for pipe in ("out_pipe", "err_pipe", "control"):
            self.assertIn("pipe2(" + pipe + ", O_CLOEXEC)", native)
            self.assertNotIn("pipe(" + pipe + ")", native)
        self.assertIn("waitpid(child,", native)
        self.assertNotIn("waitpid(-1,", native)

    def test_fork_publication_does_not_overlap_transient_pipe_writers(self):
        native = (ROOT / "manager/src/main/cpp/maplesu_su.c").read_text(encoding="utf-8-sig")
        run = native.split("Java_dev_maplesu_manager_runtime_NativeSu_run(", 1)[1]
        run = run.split("/* ===========================================================================", 1)[0]
        stream = native.split("Java_dev_maplesu_manager_runtime_NativeSu_startStreaming(", 1)[1]
        stream = stream.split("/* commitStreaming:", 1)[0]
        lock = "pthread_mutex_lock(&msu_fds_lock)"
        unlock = "pthread_mutex_unlock(&msu_fds_lock)"
        for function, pipe in ((run, "out_pipe"), (stream, "control")):
            self.assertLess(function.index(lock), function.index("pipe2(" + pipe))
            self.assertLess(function.index("pipe2(" + pipe), function.index("child = fork()"))
            for error in ("if (pipe2(" + pipe, "if (child < 0)"):
                failure = function.split(error, 1)[1].split("}", 1)[0]
                self.assertIn(unlock, failure)
            child = function.split("if (child == 0) {", 1)[1]
            child = child.split("/* Parent:", 1)[0] if pipe == "out_pipe" else child.split("_exit(MSU_EXIT_EXEC_FAILED);", 1)[0]
            self.assertNotIn("pthread_mutex_", child)
        second_pipe_error = run.split("if (pipe2(err_pipe", 1)[1].split("}", 1)[0]
        self.assertIn(unlock, second_pipe_error)
        parent = run.split("/* Parent:", 1)[1]
        self.assertLess(parent.index("close(err_pipe[1])"), parent.index(unlock))
        self.assertLess(parent.index(unlock), parent.index("poll(watched"))
        full = stream.split("if (msu_stream_store(child, control[1]) != 0)", 1)[1].split("}", 1)[0]
        self.assertLess(full.index("close(control[1])"), full.index(unlock))
        self.assertLess(full.index(unlock), full.index("waitpid(child"))
        success = stream.split(full + "}", 1)[1]
        self.assertIn(unlock, success)
        child_helper = native.split("static void msu_stream_child(", 1)[1].split("JNIEXPORT", 1)[0]
        self.assertNotIn("pthread_mutex_", child_helper)

    def test_stream_take_and_close_are_atomic_with_respect_to_fork(self):
        native = (ROOT / "manager/src/main/cpp/maplesu_su.c").read_text(encoding="utf-8-sig")
        for name in ("commitStreaming", "abortStreaming", "killStreaming"):
            function = native.split("Java_dev_maplesu_manager_runtime_NativeSu_" + name + "(", 1)[1]
            function = function.split("\nJNIEXPORT", 1)[0]
            lock = function.index("pthread_mutex_lock(&msu_fds_lock)")
            take = function.index("msu_stream_take((pid_t)pid)")
            close = function.index("close(control)")
            unlock = function.rindex("pthread_mutex_unlock(&msu_fds_lock)")
            self.assertLess(lock, take)
            self.assertLess(take, close)
            self.assertLess(close, unlock)
            if name == "killStreaming":
                self.assertLess(unlock, function.index("result = kill("))
                self.assertLess(unlock, function.index("waitpid("))
            else:
                missing = function.split("if (control < 0)", 1)[1].split("}", 1)[0]
                self.assertIn("pthread_mutex_unlock(&msu_fds_lock)", missing)

    def test_gate_is_checked_again_before_each_hook_command(self):
        hook = (RUNTIME / "HookRootExecutor.kt").read_text(encoding="utf-8-sig")
        run = hook.split("override fun run(script: String)", 1)[1].split("companion object", 1)[0]
        self.assertLess(run.index("gate()"), run.index("runScript(current, script, timeout)"))
        self.assertLess(run.index("!current.armed"), run.index("runScript(current, script, timeout)"))
        self.assertIn("Thread.currentThread().isInterrupted", run)


if __name__ == "__main__":
    unittest.main()
