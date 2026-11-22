#include "su_protocol.h"
#include "module_task_environment.h"
#include <jni.h>
#include <csignal>
#include <spawn.h>
#include <sys/wait.h>

extern char** environ;
namespace {
void error(JNIEnv* env, const char* reason) {
    env->ThrowNew(env->FindClass("java/io/IOException"), reason);
}
struct Descriptors {
    std::array<int, 8> values{-1, -1, -1, -1, -1, -1, -1, -1};
    ~Descriptors() { for (int fd : values) if (fd >= 0) close(fd); }
};
}

static jintArray launch(JNIEnv* env, jobjectArray arguments, jobjectArray module_facts) {
    maplesu::module_task::Environment environment;
    if (module_facts) {
        if (getuid() || geteuid()) { error(env, "MODULE_ROOT_REQUIRED"); return nullptr; }
        const jsize size = env->GetArrayLength(module_facts);
        if (size < 8 || size > 10) { error(env, "MODULE_ENVIRONMENT_INVALID"); return nullptr; }
        std::vector<std::string> facts;
        for (jsize i = 0; i < size; ++i) {
            auto value = static_cast<jbyteArray>(env->GetObjectArrayElement(module_facts, i));
            if (!value) { error(env, "MODULE_ENVIRONMENT_INVALID"); return nullptr; }
            const jsize bytes = env->GetArrayLength(value);
            if (bytes > 256) { env->DeleteLocalRef(value); error(env, "MODULE_ENVIRONMENT_INVALID"); return nullptr; }
            facts.emplace_back(bytes, '\0');
            env->GetByteArrayRegion(value, 0, bytes, reinterpret_cast<jbyte*>(facts.back().data()));
            env->DeleteLocalRef(value);
            if (env->ExceptionCheck()) return nullptr;
        }
        if (environment.build(environ, facts)) { error(env, "MODULE_ENVIRONMENT_INVALID"); return nullptr; }
    }
    const jsize count = env->GetArrayLength(arguments);
    if (count < 1 || count > 260) { error(env, "SESSION_ARGUMENTS_INVALID"); return nullptr; }
    std::vector<std::string> strings;
    for (jsize index = 0; index < count; ++index) {
        auto argument = static_cast<jbyteArray>(env->GetObjectArrayElement(arguments, index));
        if (!argument) { error(env, "SESSION_ARGUMENTS_INVALID"); return nullptr; }
        const jsize length = env->GetArrayLength(argument);
        if (length > 131072) { env->DeleteLocalRef(argument); error(env, "SESSION_ARGUMENTS_INVALID"); return nullptr; }
        strings.emplace_back(length, '\0');
        env->GetByteArrayRegion(argument, 0, length, reinterpret_cast<jbyte*>(strings.back().data()));
        env->DeleteLocalRef(argument);
        if (env->ExceptionCheck()) return nullptr;
        if (strings.back().find('\0') != std::string::npos) { error(env, "SESSION_ARGUMENTS_INVALID"); return nullptr; }
    }
    std::vector<char*> argv;
    for (auto& argument : strings) argv.push_back(argument.data());
    argv.push_back(nullptr);
    Descriptors fds;
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds.values.data()) != 0 ||
        pipe2(fds.values.data() + 2, O_CLOEXEC) != 0 ||
        pipe2(fds.values.data() + 4, O_CLOEXEC) != 0 ||
        pipe2(fds.values.data() + 6, O_CLOEXEC) != 0) {
        error(env, "SESSION_DESCRIPTORS_FAILED"); return nullptr;
    }
    // Duplicate child sources above 3 before file actions overwrite stdio/control.
    std::array<int, 4> sources{-1, -1, -1, -1};
    const std::array<int, 4> originals{fds.values[2], fds.values[5], fds.values[7], fds.values[1]};
    int result = 0;
    for (size_t index = 0; index < sources.size(); ++index) {
        sources[index] = fcntl(originals[index], F_DUPFD_CLOEXEC, 10);
        if (sources[index] < 0) { result = errno; break; }
    }
    posix_spawn_file_actions_t actions{};
    posix_spawnattr_t attributes{};
    bool actions_ready = false, attributes_ready = false;
    if (result == 0) { result = posix_spawn_file_actions_init(&actions); actions_ready = result == 0; }
    if (result == 0) { result = posix_spawnattr_init(&attributes); attributes_ready = result == 0; }
    // Bionic applies CLOEXEC to all inherited non-stdio descriptors before these
    // actions. Only explicitly dup2'd stdio and connected control FD3 survive exec.
    if (result == 0) result = posix_spawnattr_setflags(&attributes,
        POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK);
    sigset_t signals;
    sigemptyset(&signals);
    if (result == 0) result = posix_spawnattr_setsigmask(&attributes, &signals);
    sigaddset(&signals, SIGPIPE);
    if (result == 0) result = posix_spawnattr_setsigdefault(&attributes, &signals);
    for (size_t index = 0; result == 0 && index < sources.size(); ++index)
        result = posix_spawn_file_actions_adddup2(&actions, sources[index], static_cast<int>(index));
    pid_t child = -1;
    if (result == 0) result = posix_spawn(&child, argv[0], &actions, &attributes, argv.data(), module_facts ? environment.data() : environ);
    if (attributes_ready) posix_spawnattr_destroy(&attributes);
    if (actions_ready) posix_spawn_file_actions_destroy(&actions);
    for (int fd : sources) if (fd >= 0) close(fd);
    if (result != 0) { error(env, "SESSION_SPAWN_FAILED"); return nullptr; }
    const std::array<jint, 5> owned{child, fds.values[3], fds.values[4], fds.values[6], fds.values[0]};
    jintArray output = env->NewIntArray(owned.size());
    if (output) env->SetIntArrayRegion(output, 0, owned.size(), owned.data());
    if (!output || env->ExceptionCheck()) {
        kill(child, SIGKILL);
        while (waitpid(child, nullptr, 0) < 0 && errno == EINTR) {}
        return nullptr;
    }
    for (int index : {0, 3, 4, 6}) fds.values[index] = -1;
    return output;
}

extern "C" JNIEXPORT jintArray JNICALL
Java_dev_maplesu_manager_runtime_SessionProcessLauncher_launch(JNIEnv* env, jobject, jobjectArray arguments) {
    return launch(env, arguments, nullptr);
}

extern "C" JNIEXPORT jintArray JNICALL
Java_dev_maplesu_manager_runtime_SessionProcessLauncher_launchModule(JNIEnv* env, jobject,
    jobjectArray arguments, jobjectArray facts) {
    if (!facts) { error(env, "MODULE_ENVIRONMENT_REQUIRED"); return nullptr; }
    return launch(env, arguments, facts);
}

extern "C" JNIEXPORT jint JNICALL
Java_dev_maplesu_manager_runtime_SessionProcessLauncher_observeExit(JNIEnv* env, jobject, jint child) {
    siginfo_t status{};
    int result;
    do { result = waitid(P_PID, child, &status, WEXITED | WNOWAIT); } while (result < 0 && errno == EINTR);
    if (result < 0) { error(env, "SESSION_WAIT_FAILED"); return -1; }
    // Leave the child unreaped until the Java lock excludes destroy()/PID reuse.
    return status.si_code == CLD_EXITED ? status.si_status : 128 + status.si_status;
}

extern "C" JNIEXPORT void JNICALL
Java_dev_maplesu_manager_runtime_SessionProcessLauncher_reap(JNIEnv* env, jobject, jint child) {
    int result;
    do { result = waitpid(child, nullptr, 0); } while (result < 0 && errno == EINTR);
    if (result < 0) error(env, "SESSION_REAP_FAILED");
}

extern "C" JNIEXPORT void JNICALL
Java_dev_maplesu_manager_runtime_SessionProcessLauncher_terminate(JNIEnv*, jobject, jint child, jint signal) {
    kill(child, signal);
}

extern "C" JNIEXPORT void JNICALL
Java_dev_maplesu_manager_runtime_SessionProcessLauncher_sendDescriptors(JNIEnv* env, jobject,
    jint control, jintArray descriptors) {
    if (env->GetArrayLength(descriptors) != 3) { error(env, "SESSION_STREAMS_INVALID"); return; }
    std::array<jint, 3> streams{};
    env->GetIntArrayRegion(descriptors, 0, streams.size(), streams.data());
    if (!env->ExceptionCheck() && !maplesu::send_fds(control, 'F', streams.data(), streams.size()))
        error(env, "SESSION_STREAM_TRANSFER_FAILED");
}

extern "C" JNIEXPORT jint JNICALL
Java_dev_maplesu_manager_runtime_SessionProcessLauncher_receiveTerminal(JNIEnv* env, jobject, jint control) {
    int terminal = -1;
    if (!maplesu::receive_fds(control, 'P', &terminal, 1)) {
        error(env, "MAPLESU_SESSION_PTY_INVALID"); return -1;
    }
    return terminal;
}
